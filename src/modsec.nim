import os, tables, sets
import modsec / [base, rules, actions]
import sugar

type
  Ruleset* = object
    rules*: seq[Modsec]
    version*: string # empty string for no version
    files*: Table[string, HashSet[int]] # file -> ruleid
    ids: Table[int, int] # ruleid -> index into rules
  Malformations* = enum
    DuplicateIds, BrokenChain, OrphanLabel, SkipToNowhere, SkipNothing,
    ReferBadId, InvalidId, DuplicateIdsInChain, MultiplyDisruptive,
    ChainWithoutId

iterator pairs*(ab: (Ruleset, Ruleset)): (Modsec, Modsec) =
  let (a, b) = (ab[0].rules, ab[1].rules)
  assert a.len == b.len
  for i in 0 ..< a.len:
    yield (a[i], b[i])

proc initRuleset*: Ruleset =
  result.files = initTable[string, HashSet[int]]()
  result.ids = initTable[int, int]()

proc addRule*(ruleset: var Ruleset, rule: Modsec, filename: string = "") =
  if rule.kind notin {SecRule, SecAction}:
    ruleset.rules.add rule
    return
  let id = rule.getActions(Actions.Id)[^1].id
  if id in ruleset.ids:
    raise newException(ModsecInvalidConfig, "id already in ruleset: " & $id)
  ruleset.ids[id] = ruleset.rules.len
  ruleset.rules.add rule
  if filename.len > 0:
    if filename notin ruleset.files:
      ruleset.files[filename] = initSet[int]()
    ruleset.files[filename].incl id

proc addRules*(ruleset: var Ruleset, str: string) =
  for rule in parseRules(str):
    ruleset.addRule rule

proc addConfFile*(ruleset: var Ruleset, filename: string) =
  for rule in parseRules(readFile(filename)):
    ruleset.addRule rule, filename

proc recursiveAddConfFile*(ruleset: var Ruleset, filename: string) =
  for rule in parseRules(readFile(filename)):
    if rule.kind == HttpInclude:
      recursiveAddConfFile(ruleset, rule.path)
    else:
      ruleset.addRule rule, filename

proc addConfDir*(ruleset: var Ruleset, dir: string) =
  for file in walkFiles(dir / "*.conf"):
    ruleset.addConfFile file

func getRulesById*(ruleset: Ruleset, id: int): seq[Modsec] =
  for rule in ruleset.rules:
    case rule.kind
    of SecRule, SecAction, SecDefaultAction:
      let this = rule.getActions(Actions.Id)[^1].id
      if this == id: result.add rule
    else: discard

proc validate*(ruleset: seq[Modsec]): set[Malformations] =
  var
    seen = initSet[int]()
    expecting = initSet[int]()
    seenMarkers = initSet[string]()
    expectMarkers = initSet[string]()
    errors: set[Malformations]

    id, chains, chainIndex, skip: int
    disruptions: set[Actions]
    ruleno = -1
  when defined(debugrules):
    var complaints = initSet[(int, Malformations)]()

  proc error(err: Malformations) =
    when defined(debugrules):
      if (ruleno, err) in complaints: return
      complaints.incl (ruleno, err)
    when defined(debugrules):
      stderr.writeLine "ERROR: " & $err
      stderr.writeLine $ruleset[ruleno]
      stderr.writeLine ""
    errors.incl err

  proc newChain =
    id = -1
    chains = 0
    chainIndex = 0
    disruptions = {}
    skip = 0

  proc validateActions(acts: seq[Action]) =
    for act in acts:
      case act.kind
      of Actions.Id:
        if id > 0: error(DuplicateIdsInChain)
        if act.id < 1: error(InvalidId)
        id = act.id
        if id in seen: error(DuplicateIds)
        seen.incl id
      of Actions.Chain: inc chains
      of Actions.Allow, Actions.Block, Actions.Deny, Actions.Drop,
          Actions.Pass, Actions.Pause, Actions.Proxy, Actions.Redirect:
        disruptions.incl act.kind
        if card(disruptions) > 1: error(MultiplyDisruptive)
      of Actions.SkipAfter:
        expectMarkers.incl act.marker
      else: discard

  for rule in ruleset:
    inc ruleno
    newChain()
    case rule.kind
    of SecRule:
      for r in rule.rules:
        validateActions(r.actions)
        if chainIndex == rule.rules.high and chains != chainIndex:
          error(BrokenChain)
        inc chainIndex
      if id < 1: error(ChainWithoutId)
    of SecRuleRemoveById:
      for ids in rule.removedIds:
        for id in ids:
          expecting.incl id
    of SecMarker:
      seenMarkers.incl rule.marker
    of SecAction:
      validateActions(rule.actions)
      if id < 1:
        when defined(debugrules):
          stderr.writeLine "ERROR: SecAction without ID"
          stderr.writeLine rule
          stderr.writeLine ""
        errors.incl ChainWithoutId
    of SecDefaultAction:
      validateActions(rule.actions)
    of SecRuleUpdateTargetById:
      for id in rule.updatedId:
        expecting.incl id
    of HttpInclude, SecUnparsed: discard
  if skip > 0: error(SkipNothing)

  if card(seenMarkers - expectMarkers) > 0:
    when defined(debugrules):
      stderr.writeLine "ERROR: orphan markers"
      stderr.writeLine seenMarkers - expectMarkers
      stderr.writeLine ""
    errors.incl OrphanLabel
  if card(expectMarkers - seenMarkers) > 0:
    when defined(debugrules):
      stderr.writeLine "ERROR: skip to nowhere"
      stderr.writeLine expectMarkers - seenMarkers
      stderr.writeLine ""
    errors.incl SkipToNowhere
  if card(expecting - seen) > 0:
    when defined(debugrules):
      stderr.writeLine "ERROR: bad IDs referenced"
      stderr.writeLine expecting - seen
      stderr.writeLine ""
    errors.incl ReferBadId

  return errors
