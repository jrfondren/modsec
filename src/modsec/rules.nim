import strutils, strformat
import npeg
import actions, base

type
  SecDirective* = enum
    SecRule,
    SecRuleRemoveById, SecMarker, SecAction, SecDefaultAction,
    SecRuleUpdateTargetById,
    HttpInclude,
    SecUnparsed
  SecIdRange* = HSlice[int, int]
  SecRuleObj* = object
    variables*: string
    operator*: string
    actions*: seq[Action]
  Modsec* = object
    case kind*: SecDirective
    of SecRule: rules*: seq[SecRuleObj]
    of SecRuleRemoveById: removedIds*: seq[SecIdRange]
    of SecMarker: marker*: string
    of SecAction, SecDefaultAction: actions*: seq[Action]
    of SecRuleUpdateTargetById:
      updatedId*: SecIdRange
      variables*: string
      replacements*: string  # empty string on no replacements
    of HttpInclude: path*: string
    of SecUnparsed: unparsed*: string

proc `==`*(a, b: Modsec): bool =
  if a.kind != b.kind: return false
  case a.kind
  of SecRule: a.rules == b.rules
  of SecRuleRemoveById: a.removedIds == b.removedIds
  of Secmarker: a.marker == b.marker
  of SecAction, SecDefaultAction: a.actions == b.actions
  of SecRuleUpdateTargetById:
    a.updatedId == b.updatedId and
        a.variables == b.variables and
        a.replacements == b.replacements
  of HttpInclude: a.path == b.path
  of SecUnparsed: a.unparsed == b.unparsed

func maybeQuote(str: string): string =
  if ' ' in str:
    '"' & str & '"'
  else:
    str

when not defined(debugPrettyModsec):
  func `$`*(rule: SecRuleObj): string =
    let actions =
      if rule.actions.len > 0: ' ' & $rule.actions
      else: ""
    &"SecRule {rule.variables.maybeQuote} \"{rule.operator}\"{actions}"

proc idRangeToString(id: SecIdRange): string =
  if id.a == id.b:
    result.add &"{id.a}"
  else:
    result.add &"{id.a}-{id.b}"

when not defined(debugPrettyModsec):
  proc `$`*(rule: Modsec): string =
    case rule.kind
    of SecRule:
      for r in rule.rules:
        if result.len > 0: result.add "\n"
        result.add $r
    of SecRuleRemoveById:
      result = "SecRuleRemoveById"
      for id in rule.removedIds:
        result.add " " & idRangeToString(id)
    of SecMarker:
      result = "SecMarker " & rule.marker
    of SecAction:
      result = &"SecAction {rule.actions}"
    of SecDefaultAction:
      result = &"SecDefaultAction {rule.actions}"
    of SecRuleUpdateTargetById:
      result = "SecRuleUpdateTargetById " & idRangeToString(rule.updatedId)
      result.add " " & rule.variables
      if rule.replacements.len > 0:
        result.add " " & rule.replacements
    of HttpInclude:
      result.add &"Include {rule.path}"
    of SecUnparsed:
      result = rule.unparsed

iterator pairs*(ab: tuple[a: seq[Action], b: seq[Action]]): tuple[a: Action, b: Action] =
  let (a, b) = ab
  for i in 0 .. a.high:
    yield (a[i], b[i])

proc getActions*(rule: ModSec): seq[Action] =
  case rule.kind
  of SecRule: result = rule.rules[0].actions
  of SecAction, SecDefaultAction: result = rule.actions
  else: assert(false)

proc getActions*(rule: ModSec, kind: Actions): seq[Action] =
  template scan(list: untyped) {.dirty.} =
    for i in 0 ..< list.len:
      if list[i].kind == kind:
        result.add list[i]
  case rule.kind
  of SecRule: scan rule.rules[0].actions
  of SecAction, SecDefaultAction: scan rule.actions
  else: assert(false)

proc getActions*(acts: seq[Action], kind: Actions): seq[Action] =
  for act in acts:
    if act.kind == kind:
      result.add act

proc parseRules*(str: string): seq[Modsec] =
  var
    results: seq[Modsec]
    resultIds: seq[SecIdRange]

  let parser = peg "ruleset":
    ruleset <- *(*emptyline * *Blank * rule) * *emptyline * !1
    comment <- *Blank * '#' * incomment
    incomment <- &line_is_continued * *PrintPlus * '\n' * incomment | *PrintPlus * '\n'
    line_is_continued <- '\\' * '\n' | (1 - '\n') * line_is_continued
    emptyline <- comment | *Blank * '\n' | *Blank * '\\' * *Blank * '\n' * (comment | *Blank * '\n')
    spacing <- +(*Blank * '\\' * *Blank * '\n' * *Blank) | +Blank
    rule <- RSecRule | RSecRuleRemoveById | RSecMarker | RSecAction |
            RSecDefaultAction | RSecRuleUpdateTargetById | RHttpInclude |
            RSecUnparsed

    RSecRule <- i"SecRule" * spacing * >maybeQuoted * spacing * >maybeQuoted * ?(*spacing * >maybeQuoted):
      let actions: seq[Action] =
        if capture.len == 4:
          parseActions(dequote(capture[3].s))
        else:
          @[]
      let rule = SecRuleObj(variables: dequote($1), operator: dequote($2), actions: actions)
      if results.len > 0 and
           results[^1].kind == SecRule and
           Action(kind: Chain) in results[^1].rules[^1].actions:
        results[^1].rules.add rule
      else:
        results.add(Modsec(kind: SecRule, rules: @[rule]))

    RSecRuleRemoveById <- i"SecRuleRemoveById" * +(spacing * (RuleIDRange | RuleID)):
      results.add(Modsec(kind: SecRuleRemoveById, removedIds: resultIds))
      resultIds = @[]
    RSecRuleUpdateTargetById <- i"SecRuleUpdateTargetById" * spacing * (RuleIDRange | RuleID) *
                                spacing * >maybeQuoted * ?(spacing * >maybeQuoted):
      let reps =
        if capture.len == 3:
          dequote(capture[2].s)
        else:
          ""
      results.add(Modsec(kind: SecRuleUpdateTargetById,
                         updatedId: resultIds[0],
                         variables: dequote($1),
                         replacements: reps))
      resultIds = @[]
    RuleIDRange <- >+Digit * '-' * >+Digit:
      let
        a = parseInt($1)
        b = parseInt($2)
      resultIds.add a..b
    RuleID <- >+Digit:
      let a = parseInt($1)
      resultIds.add a..a

    RSecMarker <- i"SecMarker" * spacing * >maybeQuoted:
      results.add(Modsec(kind: SecMarker, marker: dequote($1)))
    RSecAction <- i"SecAction" * spacing * >maybeQuoted:
      results.add(Modsec(kind: SecAction, actions: parseActions(dequote($1))))
    RSecDefaultAction <- i"SecDefaultAction" * spacing * >maybeQuoted:
      results.add(Modsec(kind: SecDefaultAction, actions: parseActions(dequote($1))))

    RHttpInclude <- i"Include" * spacing * >maybeQuoted:
      results.add(Modsec(kind: HttpInclude, path: $1))

    RSecUnparsed <- >(addoutputfilter | argsep | boolupdate | filemode | seccomponent | outputsed | location_open | location_close | directory_open | directory_close | ifmodule_open | ifmodule_close | randhtml):
      results.add(Modsec(kind: SecUnparsed, unparsed: $1))

    location_open <- i"<LocationMatch" * *Blank * *Print
    location_close <- i"</LocationMatch>"
    directory_open <- i"<Directory" * *Blank * >*Print
    directory_close <- i"</Directory>"
    ifmodule_open <- i"<IfModule" * *Blank * *Print
    ifmodule_close <- i"</IfModule>"
    randhtml <- i"RequestReadTimeout" * *Print
    addoutputfilter <- (i"AddOutputFilter" | i"RemoveOutputFilter") * spacing * maybeQuoted * spacing * maybeQuoted
    outputsed <- i"OutputSed" * spacing * maybeQuoted
    argsep <- i"SecArgumentSeparator" * spacing * maybeQuoted
    filemode <- i"SecUploadFileMode" * spacing * +Digit
    seccomponent <- i"SecComponentSignature" * spacing * maybeQuoted
    boolupdate <- booldirective * spacing * yesno
    ignored_rules <- directive * spacing * *maybeQuoted
    directive <- "SecAction" | "SecDefaultAction" | "SecMarker" | "SecRemoteRules" | "SecRule" | "SecRuleInheritance" | "SecRuleRemoveById" | "SevRuleRemoveByMsg" | "SecRuleRemoveByTag" | "SecRuleScript" | "SecRuleUpdateActionById" | "SecRuleUpdateTargetById" | "SecRuleUpdateActionByMsg" | "SecRuleUpdateActionByTag" | "SecWebAppId" | i"SecArgumentSeparator" | i"SecContentInjection" | i"SecStreamOutBodyInspection" | i"SecResponseBodyAccess" | i"SecTmpSaveUploadedFiles" | i"SecRuleUpdateTargetById" | i"SecUploadFileMode"
    booldirective <- i"SecContentInjection" | i"SecStreamOutBodyInspection" | i"SecResponsebodyAccess" | i"SecTmpSaveUploadedFiles"
    yesno <- i"On" | i"Off"

    maybeQuoted <- '"' * *NonQuotes * '"' | +UnquotedText
    NonQuotes <- '\\' * UTF8Rune | UTF8Rune - '"'
    UnquotedText <- UTF8Rune - {0..' ','"'}
    PrintPlus <- UTF8Rune - '\n'
    UTF8Rune <- {0..127} | {194..223} * UTF8Cont[1] | {224..239} * UTF8Cont[2] | {240..244} * UTF8Cont[3]
    UTF8Cont <- {128..191}
    BlankPlus <- {0..' '} | '#' * *PrintPlus

  doAssert parser.match(str).ok
  return results
