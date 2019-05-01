import npeg, strutils, macros
import base

type
  Transforms* = enum
    Base64Decode, SQLHexDecode, Base64DecodeExt, Base64Encode, CmdLine,
    CompressWhitespace, CSSDecode, EscapeSeqDecode, HexDecode, HexEncode,
    HTMLEntityDecode, JSDecode, Length, Lowercase, MD5, None, NormalizePath,
    NormalizePathWin, ParityEven7Bit, ParityOdd7Bit, ParityZero7Bit,
    RemoveNULLs, RemoveWhitespace, ReplaceComments, RemoveCommentsChar,
    RemoveComments, ReplaceNULLs, URLDecode, Uppercase, URLDecodeUni,
    URLEncode, UTF8ToUnicode, SHA1, TrimLeft, TrimRight, Trim
  Actions* = enum
    Accuracy, Allow, Append, Auditlog, Block, Capture, Chain, Ctl, Deny,
    Deprecatevar, Drop, Exec, Expirevar, Id, Initcol, Log, Logdata, Maturity,
    Msg, MultiMatch, Pass, Pause, Phase, Prepend, Proxy, Redirect, Rev,
    SanitiseArg, SanitiseMatched, SanitiseMatchedBytes, SanitiseRequestHeader,
    SanitiseResponseHeader, Severity, Setuid, Setrsc, Setsid, Setenv, Setvar,
    Skip, SkipAfter, Status, Transform, Tag, Ver, Xmlns,
  Action* = object
    case kind*: Actions
    of Accuracy: acc*: range[1..9]
    of Maturity: maturity*: range[1..9]
    of Id: id*: int
    of Phase: phase*: range[1..5]
    of Severity: severity*: string
    of Auditlog, Log: enabled*: bool
    of Allow, Block, Capture, Chain, Deny, Drop,
       MultiMatch, Pass: discard
    of Append, Ctl, Deprecatevar, Exec, Expirevar, Initcol, Msg, Prepend,
       Logdata, Proxy, Rev, Redirect, SanitiseArg, SanitiseMatched,
       SanitiseMatchedBytes, SanitiseRequestHeader, SanitiseResponseHeader,
       Setuid, Setrsc, Setsid, Setenv, Setvar, Tag, Ver, Xmlns:
      unparsed*: string
    of Skip: skip*: int
    of SkipAfter: marker*: string
    of Pause: ms*: int
    of Status: status*: int
    of Transform: t*: Transforms


func `$`*(act: Action): string =
  func maybeQuote(str: string): string =
    if {' ', ','} in str:
      '\'' & str & '\''
    else:
      str
  template `-->`(str: typed, field: untyped): untyped =
    str & ':' & maybeQuote($field)

  case act.kind
  of Accuracy: "accuracy" --> act.acc
  of Maturity: "maturity" --> act.maturity
  of Id: "id" --> act.id
  of Phase: "phase" --> act.phase
  of Severity: "severity" --> act.severity
  of AuditLog: (if act.enabled: "auditlog" else: "noauditlog")
  of Log: (if act.enabled: "log" else: "nolog")
  of Allow, Block, Capture, Chain, Deny, Drop, MultiMatch, Pass: toLowerAscii($act.kind)
  of Append, Ctl, Deprecatevar, Exec, Expirevar, Initcol, Msg, Prepend,
     Logdata, Proxy, Rev, Redirect, SanitiseArg, SanitiseMatched,
     SanitiseMatchedBytes, SanitiseRequestHeader, SanitiseResponseHeader,
     Setuid, Setrsc, Setsid, Setenv, Setvar, Tag, Ver, Xmlns:
       act.unparsed
  of Skip: "skip" --> act.skip
  of SkipAfter: "skipAfter" --> act.marker
  of Pause: "pause" --> act.ms
  of Status: "status" --> act.status
  of Transform: "t" --> toLowerAscii($act.t)

proc `==`*(a, b: Action): bool =
  if a.kind != b.kind: return false
  case a.kind
  of Accuracy: a.acc == b.acc
  of Maturity: a.maturity == b.maturity
  of Id: a.id == b.id
  of Phase: a.phase == b.phase
  of Severity: a.severity == b.severity
  of Auditlog, Log: a.enabled == b.enabled
  of Allow, Block, Capture, Chain, Deny, Drop, MultiMatch, Pass: true
  of Append, Ctl, Deprecatevar, Exec, Expirevar, Initcol, Msg, Prepend,
     Logdata, Proxy, Rev, Redirect, SanitiseArg, SanitiseMatched,
     SanitiseMatchedBytes, SanitiseRequestHeader, SanitiseResponseHeader,
     Setuid, Setrsc, Setsid, Setenv, Setvar, Tag, Ver, Xmlns:
       a.unparsed == b.unparsed
  of Skip: a.skip == b.skip
  of SkipAfter: a.marker == b.marker
  of Pause: a.ms == b.ms
  of Status: a.status == b.status
  of Transform: a.t == b.t

func `$`*(acts: seq[Action]): string =
  '"' & acts.join(",") & '"'

proc actionOf*(act, val: string): Action =
  let kind = parseEnum[Actions](capitalizeAscii(act))
  case kind
  of Accuracy: Action(kind: Accuracy, acc: val.parseInt)
  of Maturity: Action(kind: Maturity, maturity: val.parseInt)
  of Id: Action(kind: Id, id: val.parseInt)
  of Phase: Action(kind: Phase, phase: val.parseInt)
  of Severity: Action(kind: Severity, severity: val)
  of Auditlog, Log: Action(kind: Auditlog, enabled: val.parseBool)
  of Skip: Action(kind: Skip, skip: val.parseInt)
  of SkipAfter: Action(kind: SkipAfter, marker: val)
  of Pause: Action(kind: Pause, ms: val.parseInt)
  of Status: Action(kind: Status, status: val.parseInt)
  of Transform: Action(kind: Transform, t: parseEnum[Transforms](capitalizeAscii(val)))
  # pain incoming, see Nim-lang/Nim#11143
  of Allow: Action(kind: Allow)
  of Block: Action(kind: Block)
  of Capture: Action(kind: Capture)
  of Chain: Action(kind: Chain)
  of Deny: Action(kind: Deny)
  of Drop: Action(kind: Drop)
  of MultiMatch: Action(kind: MultiMatch)
  of Pass: Action(kind: Pass)
  # pain continued
  of Append: Action(kind: Append, unparsed: val)
  of Ctl: Action(kind: Ctl, unparsed: val)
  of Deprecatevar: Action(kind: Deprecatevar, unparsed: val)
  of Exec: Action(kind: Exec, unparsed: val)
  of Expirevar: Action(kind: Expirevar, unparsed: val)
  of Initcol: Action(kind: Initcol, unparsed: val)
  of Msg: Action(kind: Msg, unparsed: val)
  of Prepend: Action(kind: Prepend, unparsed: val)
  of Logdata: Action(kind: Logdata, unparsed: val)
  of Proxy: Action(kind: Proxy, unparsed: val)
  of Rev: Action(kind: Rev, unparsed: val)
  of Redirect: Action(kind: Redirect, unparsed: val)
  of SanitiseArg: Action(kind: SanitiseArg, unparsed: val)
  of SanitiseMatched: Action(kind: SanitiseMatched, unparsed: val)
  of SanitiseMatchedBytes: Action(kind: SanitiseMatchedBytes, unparsed: val)
  of SanitiseRequestHeader: Action(kind: SanitiseRequestHeader, unparsed: val)
  of SanitiseResponseHeader: Action(kind: SanitiseResponseHeader, unparsed: val)
  of Setuid: Action(kind: Setuid, unparsed: val)
  of Setrsc: Action(kind: Setrsc, unparsed: val)
  of Setsid: Action(kind: Setsid, unparsed: val)
  of Setenv: Action(kind: Setenv, unparsed: val)
  of Setvar: Action(kind: Setvar, unparsed: val)
  of Tag: Action(kind: Tag, unparsed: val)
  of Ver: Action(kind: Ver, unparsed: val)
  of Xmlns: Action(kind: Xmlns, unparsed: val)

proc parseActions*(str: string): seq[Action] =
  var results: seq[Action]

  let parser = peg "actions":
    actions <- spacing * action * *(',' * spacing * action) * ?garbage * !1
    garbage <- '\'' | ','
    spacing <- *Blank * '\\' * *Blank * '\n' * spacing |
               *Blank * '#' * *(UTF8Rune - '\n') * '\n' * spacing |
               *Blank
    action <- ActAcc | ActMat | ActID | ActPhase | ActSev |
              DisruptActs | UnparsedArgActs | BoolActs |
              ActSkip | ActSkipAfter | ActPause | ActStatus |
              ActTransform

    # loose quoting, assume no spacing except after a comma
    ActAcc <- "accuracy:" * ?'\'' * >Digit * ?'\'':
      results.add(Action(kind: Accuracy, acc: parseInt($1)))
    ActMat <- "maturity:" * ?'\'' * >Digit * ?'\'':
      results.add(Action(kind: Maturity, maturity: parseInt($1)))
    ActID <- "id:" * ?'\'' * >+Digit * ?'\'':
      results.add(Action(kind: Id, id: parseInt($1)))
    ActSev <- "severity:" * ?'\'' * >+Internal * ?'\'':
      results.add(Action(kind: Severity, severity: $1))

    ActPhase <- ActPhaseNumbered | ActPhaseNamed
    ActPhaseNumbered <- "phase:" * ?'\'' * >{'1'..'5'} * ?'\'':
      results.add(Action(kind: Phase, phase: parseInt($1)))
    ActPhaseNamed <- "phase:" * ?'\'' * >("request" | "respone" | "logging") * ?'\'':
      let phase: range[1..5] =
        if $1 == "request": 2
        elif $1 == "response": 4
        else: 5
      results.add(Action(kind: Phase, phase: phase))

    BoolActs <- NoAudit | YesAudit | NoLog | YesLog
    NoAudit <- "noauditlog":
      results.add(Action(kind: Auditlog, enabled: false))
    YesAudit <- "auditlog":
      results.add(Action(kind: Auditlog, enabled: true))
    NoLog <- "nolog":
      results.add(Action(kind: Log, enabled: false))
    YesLog <- "log":
      results.add(Action(kind: Log, enabled: true))

    DisruptActs <- >("allow" | "block" | "capture" | "chain" | "deny" |
                     "drop" | i"multimatch" | "pass"):
      case parseEnum[Actions](capitalizeAscii($1))
      of Allow: results.add(Action(kind: Allow))
      of Block: results.add(Action(kind: Block))
      of Capture: results.add(Action(kind: Capture))
      of Chain: results.add(Action(kind: Chain))
      of Deny: results.add(Action(kind: Deny))
      of Drop: results.add(Action(kind: Drop))
      of Multimatch: results.add(Action(kind: Multimatch))
      of Pass: results.add(Action(kind: Pass))
      else: assert(false)

    UnparsedArgActs <- >("append" | "ctl" | "deprecatevar" | "exec" |
                         "expirevar" | "initcol" | "msg" | "prepend" |
                         "logdata" | "proxy" | "rev" | "redirect" |
                         "sanitiseArg" | "sanitiseMatched" |
                         "sanitiseMatchedBytes" | "sanitiseRequestHeader" |
                         "sanitiseResponseHeader" | "setuid" | "setrsc" |
                         "setsid" | "setenv" | "setvar" | "tag" | "ver" |
                         "xmlns") *
                       ':' * ('\'' * >+QuotedInternal * '\'' | >+Internal):
      let val = capture[^1]
      case $1
      of "append": results.add(Action(kind: Append, unparsed: val))
      of "ctl": results.add(Action(kind: Ctl, unparsed: val))
      of "deprecatevar": results.add(Action(kind: DeprecateVar, unparsed: val))
      of "exec": results.add(Action(kind: Exec, unparsed: val))
      of "expirevar": results.add(Action(kind: Expirevar, unparsed: val))
      of "initcol": results.add(Action(kind: Initcol, unparsed: val))
      of "msg": results.add(Action(kind: Msg, unparsed: val))
      of "prepend": results.add(Action(kind: Prepend, unparsed: val))
      of "logdata": results.add(Action(kind: Logdata, unparsed: val))
      of "proxy": results.add(Action(kind: Proxy, unparsed: val))
      of "rev": results.add(Action(kind: Rev, unparsed: val))
      of "redirect": results.add(Action(kind: Redirect, unparsed: val))
      of "sanitiseMatched", "sanitizeMatched": results.add(Action(kind: SanitiseMatched, unparsed: val))
      of "sanitiseMatchedBytes", "sanitizeMatchedBytes": results.add(Action(kind: SanitiseMatchedBytes, unparsed: val))
      of "sanitiseRequestHeader": results.add(Action(kind: SanitiseRequestHeader, unparsed: val))
      of "sanitiseResponseHeader": results.add(Action(kind: SanitiseResponseHeader, unparsed: val))
      of "setuid": results.add(Action(kind: Setuid, unparsed: val))
      of "setrsc": results.add(Action(kind: Setrsc, unparsed: val))
      of "setsid": results.add(Action(kind: Setsid, unparsed: val))
      of "setenv": results.add(Action(kind: Setenv, unparsed: val))
      of "setvar": results.add(Action(kind: Setvar, unparsed: val))
      of "tag": results.add(Action(kind: Tag, unparsed: val))
      of "ver": results.add(Action(kind: Ver, unparsed: val))
      of "xmlns": results.add(Action(kind: XmlNS, unparsed: val))
      else: assert(false)

    ActSkip <- "skip:" * ?'\'' * >+Digit * ?'\'':
      results.add(Action(kind: Skip, skip: parseInt($1)))
    ActSkipAfter <- "skipAfter:" * ?'\'' * >+Internal * ?'\'':
      results.add(Action(kind: SkipAfter, marker: dequote($1)))
    ActPause <- "pause:" * ?'\'' * >+Digit * ?'\'':
      results.add(Action(kind: Pause, ms: parseInt($1)))
    ActStatus <- "status:" * ?'\'' * >+Digit * ?'\'':
      results.add(Action(kind: Status, status: parseInt($1)))
    ActTransform <- "t:" * ?'\'' * >Transforms * ?'\'':
      let trans =
        if 0 == cmpIgnoreCase($1, "normalisePath"): "normalizePath"
        elif 0 == cmpIgnoreCase($1, "normalisePathWin"): "normalizePathWin"
        else: $1
      results.add(Action(kind: Transform, t: parseEnum[Transforms](capitalizeAscii(trans))))
    Transforms <- i"base64DecodeExt" | i"sqlHexDecode" | i"base64Decode" |
                  i"base64Encode" | i"cmdLine" | i"compressWhitespace" |
                  i"cssDecode" | i"escapeSeqDecode" | i"hexDecode" |
                  i"hexEncode" | i"htmlEntityDecode" | i"jsDecode" |
                  i"length" | i"lowercase" | i"md5" | i"none" |
                  i"normalisePathWin" | i"normalizePathWin" |
                  i"normalisePath" | i"normalizePath" | i"parityEven7bit" |
                  i"parityOdd7bit" | i"parityZero7bit" | i"removeNulls" |
                  i"replaceNulls" | i"removeCommentsChar" | i"removeComments" |
                  i"replaceComments" | i"urlDecodeUni" | i"uppercase" |
                  i"removewhitespace" | i"urlDecode" | i"urlEncode" |
                  i"utf8toUnicode" | i"sha1" | i"trimLeft" | i"trimRight" |
                  i"trim"

    QuotedInternal <- '\\' * UTF8Rune | UTF8Rune - {'\'','"'}
    Internal <- '\\' * UTF8Rune | UTF8Rune - {',', '\'', '"'}
    UTF8Rune <- {0..127} | {194..223} * UTF8Cont[1] |
                {224..239} * UTF8Cont[2] | {240..244} * UTF8Cont[3]
    UTF8Cont <- {128..191}

  doAssert parser.match(str).ok
  return results
