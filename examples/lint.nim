import strformat, os
import modsec / rules
import modsec

var faultcount: int

proc lint(ruleset: var Ruleset, filename: string) =
  for rule in parseRules(readFile(filename)):
    if rule.kind == HttpInclude:
      lint(ruleset, rule.path)
    else:
      let faults = validate(ruleset, rule)
      if faults.card > 0:
        echo $rule
        echo $faults
        echo()
        inc faultcount
      ruleset.addRule rule, filename

proc usage {.noreturn.} =
  stderr.writeLine &"""
usage: {paramStr(0)} <file>

Read file of modsec rules (recursively including any Included rules) and
report on defective rules. 'Defective' includes sloppiness that's 'tolerated
by modsec. 'Defective' does not cover everything that modsec might complain
about. Currently, only rule actions are considered.
"""
  quit 1

proc main =
  if paramCount() == 1:
    var ruleset = initRuleset()
    lint(ruleset, paramStr(1))
    echo &"Defects: {faultcount}"
  else: usage()
   
when isMainModule:
  main()
