import os, strformat, strutils
import src/modsec
import src/modsec/base
import src/modsec/rules

var ruleset = initRuleset()

proc checkFile(file: string) =
  when defined(debugrules) or defined(npegTrace):
    echo "processing: " & file
    defer: echo "done processing: " & file
  for rule in parseRules(readFile(file)):
    try:
      ruleset.addRule(rule, file)
    except ModsecInvalidConfig:
      discard

proc dumpCounts =
  var
    total: int
    counts: array[SecDirective, int]
  for rule in ruleset.rules:
    if paramCount() == 1 and not defined(debugrules):
      echo rule
    inc counts[rule.kind]
    inc total
  stderr.writeLine &"""
Total rules parsed:
  SecRule .................. {counts[SecRule]:>5}
  SecRuleRemoveById ........ {counts[SecRuleRemoveById]:>5}
  SecMarker ................ {counts[SecMarker]:>5}
  SecAction ................ {counts[SecAction]:>5}
  SecDefaultAction ......... {counts[SecDefaultAction]:>5}
  SecRuleUpdateTargetbyId .. {counts[SecRuleUpdateTargetbyId]:>5}
  SecUnparsed .............. {counts[SecUnparsed]:>5}
  total .................... {total:>5}
"""

if paramCount() > 0 and fileExists(paramStr(1)):
  checkFile paramStr(1)
elif paramCount() > 0 and dirExists(paramStr(1)):
  for file in walkFiles(paramStr(1) & "/*.conf"):
    checkFile file
else:
  stderr.writeLine &"""usage: {paramStr(0)} <file-or-dir> [<ruleid1> ... <ruleidn>]

Given a file argument, parse it as containing ModSec rules, printing and
tallying each. To troubleshoot a parse failure, compile with -d:npegTrace .

Given IDs as an argument, dump those rules after parsing (and don't normally
dump rules.)

Compile with -d:debugrules to dump malformed rules.

Given a directory argument, apply the previous to every *.conf file in that
directory."""
  quit(1)

dumpCounts()

for i in 2 .. paramCount():
  for r in ruleset.getRulesById(paramStr(i).parseInt):
    stderr.writeLine $r

stderr.writeLine "ruleset errors: " & $ruleset.rules.validate
