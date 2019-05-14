import os, strformat, tables, strutils, terminal, algorithm
import modsec
import modsec / [rules, actions]

var diffs: uint

type
  Stats = object
    rules: array[SecDirective, uint]
    actions: array[Actions, uint]

var
  fromStats, toStats, diffStats: Stats
  useColors: bool

proc vivid(rule: Modsec) =
  const
    white = "\e[37;1m"
    yellow = "\e[33;1m"
    green = "\e[32;1m"
    cyan = "\e[36;1m"
    reset = ansiResetCode
  if useColors and rule.kind == SecRule:
    for i in 0 ..< rule.rules.len:
      let
        prefix = (if i > 0: "  " else: "")
        vars = $rule.rules[i].variables
        ops = $rule.rules[i].operator
        acts = $rule.rules[i].actions
      echo &"{prefix}{white}SecRule {yellow}{vars} {green}{ops} {cyan}{acts}{reset}"
    if rule.rules.len > 1:
      echo()
  else:
    echo $rule

proc dumpTotals =
  template dumpTable(header: typed; fromTbl, toTbl: typed; index: typed): untyped =
    echo header & " totals: "
    for i in index.low .. index.high:
      if fromTbl[i] == 0 and toTbl[i] == 0: continue
      let diff =
        if fromTbl[i] == toTbl[i]:
          ""
        else:
          " " & $(toTbl[i] - fromTbl[i]) & "}"
      echo "  " & $i & ": " & $fromTbl[i] & diff
    echo()
  dumpTable("rules", fromStats.rules, toStats.rules, SecDirective)
  dumpTable("actions", fromStats.actions, toStats.actions, Actions)

proc dumpDiffs =
  template dumpTable(header: typed; fromTbl, toTbl: typed; index: typed): untyped =
    var hasDiffs: bool
    echo header & " diffs: "
    for i in index.low .. index.high:
      if fromTbl[i] == toTbl[i]: continue
      hasDiffs = true
      echo "  " & $i & ": " & $fromTbl[i] & " (" & $(toTbl[i] - fromTbl[i]) & ")"
    if hasDiffs:
      echo()
    else:
      echo "(none)\n"
  dumpTable("rule", fromStats.rules, toStats.rules, SecDirective)
  dumpTable("action", fromStats.actions, toStats.actions, Actions)

proc confirmdiff(fromAct, toAct: Action; fromRules, toRules: Ruleset) =
  proc fail(a, b: Modsec) =
      echo "Rules differ:"
      echo "  " & $a
      echo "  " & $b
      echo()
      inc diffs
  for a, b in (fromRules, toRules):
    inc fromStats.rules[a.kind]
    inc toStats.rules[b.kind]
    if a == b and a.kind notin {SecRule, SecAction, SecDefaultAction}:
      continue
    elif a.kind == b.kind and a.kind in {SecRule, SecAction, SecDefaultAction}:
      if a.getActions.len == b.getActions.len:
        for x, y in (a.getActions, b.getActions):
          inc fromStats.actions[x.kind]
          inc toStats.actions[y.kind]
          if fromAct == x:
            if toAct == y: discard
            else: fail(a, b)
          elif x == y:
            discard
          else: fail(a, b)
      else: fail(a, b)
    else: fail(a, b)

proc grep(ruleset: Ruleset, act: Action) =
  for r in ruleset.rules:
    if r.kind in {SecRule, SecAction, SecDefaultAction}:
      block checkrule:
        for a in r.getActions:
          if a == act:
            echo r
            break checkrule

proc grep(ruleset: Ruleset, actkind: Actions) =
  for r in ruleset.rules:
    if r.kind in {SecRule, SecAction, SecDefaultAction}:
      block checkrule:
        for a in r.getActions:
          if a.kind == actkind:
            vivid r
            break checkrule

proc equalbut(a, b: Modsec; but: set[Actions]): bool =
  proc filter(acts: seq[Action]): seq[Action] =
    for act in acts:
      if act.kind notin but:
        result.add act
  let
    actsA = a.getActions.filter
    actsB = b.getActions.filter
  if actsA.len != actsB.len: return false
  for x, y in (actsA, actsB):
    if x != y: return false
  return true

proc rulesovertime(sets: seq[Ruleset]) =
  var
    versions = initTable[int, string]()
    last = initTable[int, Modsec]()
  for rs in sets:
    for rule in rs.rules:
      if rule.kind in {SecRule, SecAction}:
        let id = rule.getActions(Actions.Id)[^1].id
        if id in versions and not last[id].equalbut(rule, {Msg,Status}):
          versions[id] = rs.version
          last[id] = rule
        elif id notin versions:
          versions[id] = rs.version
          last[id] = rule
  var ids: seq[int]
  for id in versions.keys: ids.add id
  sort(ids, system.cmp[int])
  for id in ids:
    echo &"{id}: {versions[id]}"

proc usage {.noreturn.} =
  stderr.writeLine &"""
usage: {paramStr(0)} confirmdiff <Action> <from> <to> <file1> <file2>

Report where <file1> and <file2> contain different rules (with the exception of
<Action>, which should be set to <to> in file2's rules wherever file1's rules
has the action set to <from>). For example, the following command will have no
output if file1 and file2 have no differences apart from a change from
status:403 to status:404 in the new rules.

  {paramStr(0)} confirmdiff Status 403 404 rules.conf rules2.conf

usage: {paramStr(0)} act <Action> [!][<val>] <file>

Report where rules have <Action>. If <val> is provided, report where the Action
is present and equal to <val>.  If !<val> is provided, report where the Action
is present and unequal to <val>.

usage: {paramStr(0)} rulesovertime <version1> <file1> <version2> <file2> [<version3> <file3> ...]

Load rulesets from each file in turn and then dump a ruleid:version table,
showing the age of each rule. If an ID changes substantially from version1 to
version2, for example, then in output it'll have version2, unless it changes
substantially again. Hack: differences in Status and Msg actions are ignored.
"""
  quit 1

proc main =
  if paramCount() == 6 and paramStr(1) == "confirmdiff":
    var
      fromAct = actionOf(paramStr(2), paramStr(3))
      toAct = actionOf(paramStr(2), paramStr(4))
      fromRules = initRuleset()
      toRules = initRuleset()
    fromRules.recursiveAddConfFile(paramStr(5))
    toRules.recursiveAddConfFile(paramStr(6))
    confirmdiff(fromAct, toAct, fromRules, toRules)
    dumpTotals()
    dumpDiffs()
    if diffs == 0: echo "No differences"
    else: echo &"There were {diffs} differences."
    quit diffs != 0
  elif paramCount() == 4 and paramStr(1) == "act":
    var
      act = actionOf(paramStr(2), paramStr(3))
      ruleset = initRuleset()
    ruleset.recursiveAddConfFile(paramStr(paramCount()))
    ruleset.grep(act)
  elif paramCount() == 3 and paramStr(1) == "act":
    var
      actkind = parseEnum[Actions](paramStr(2))
      ruleset = initRuleset()
    ruleset.recursiveAddConfFile(paramStr(paramCount()))
    ruleset.grep(actkind)
  elif paramCount() > 5 and paramStr(1) == "rulesovertime":
    var sets: seq[Ruleset]
    for i in countup(2, paramCount(), 2):
      var ruleset = initRuleset()
      ruleset.version = paramStr(i)
      ruleset.recursiveAddConfFile(paramStr(i+1))
      sets.add ruleset
    rulesovertime(sets)
  else: usage()

if isMainModule:
  if stdout.isatty: useColors = true
  main()
