import unittest
import modsec / [rules, actions]
from strutils import strip

suite "printing actions":
  test "accuracy":
    check "accuracy:9" == $Action(kind: Accuracy, acc: 9)

suite "printing rules":
  test "simple rule":
    check """
SecRule REQUEST_URI "java" "t:none,phase:1,id:1235,t:none,nolog,pass"
""".strip == $ModSec(kind: SecRule, rules: @[
         SecRuleObj(
           variables: "REQUEST_URI",
           operator: "java",
           actions: @[
             Action(kind: Transform, t: None),
             Action(kind: Phase, phase: 1),
             Action(kind: Id, id: 1235),
             Action(kind: Transform, t: None),
             Action(kind: Log, enabled: false),
             Action(kind: Pass)
           ]
         )
       ])
