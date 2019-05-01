import unittest
import modsec / [rules, actions]
proc parseEq(str: string, rules: seq[Modsec]): bool =
  try:
    result = parseRules(str) == rules
  except AssertionError:
    discard

proc parseOk(str: string): bool =
  try:
    discard parseRules(str)
    result = true
  except AssertionError:
    discard

proc actionEq(str: string, acts: seq[Action]): bool =
  try:
    result = parseActions(str) == acts
  except AssertionError:
    discard

proc actionOk(str: string): bool =
  try:
    discard parseActions(str)
    result = true
  except AssertionError:
    discard

# ----------------------------------------------------------------------
suite "parsing normal actions":

  test "can parse action with skipAfter":
    check "phase:4,rev:2,id:1234,t:none,pass,nolog,skipAfter:END_MALWARE_FOREVER".actionEq(
      @[Action(kind: Phase, phase: 4), Action(kind: Rev, unparsed: "2"), Action(kind: Id, id: 1234), Action(kind: Transform, t: None), Action(kind: Pass), Action(kind: Log, enabled: false), Action(kind: SkipAfter, marker: "END_MALWARE_FOREVER")]
    )

  test "can parse bare 'chain' action":
    check "chain".actionEq(@[Action(kind: Chain)])

  test "can parse continued-line action from OWASP3":
    check """
t:none,t:urlDecodeUni,t:lowercase,\
        setvar:'tx.msg=%{rule.msg}',\
        setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
        setvar:'tx.%{rule.id}-OWASP_CRS/POLICY/EXT_RESTRICTED-%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'""".actionEq(
      @[Action(kind: Transform, t: None), Action(kind: Transform, t: URLDecodeUni), Action(kind: Transform, t: Lowercase), Action(kind: Setvar, unparsed: "tx.msg=%{rule.msg}"), Action(kind: Setvar, unparsed: "tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}"), Action(kind: Setvar, unparsed: "tx.%{rule.id}-OWASP_CRS/POLICY/EXT_RESTRICTED-%{MATCHED_VAR_NAME}=%{MATCHED_VAR}")]
    )

# ----------------------------------------------------------------------
suite "parsing action oddities from real-world rulesets":

  test "can parse actions that end in a comma":
    check "phase:2,block,status:403,capture,t:none,t:hexDecode,t:replaceComments,msg:'real-world example',id:4123,logdata:'%{TX.0}',severity:'2',".actionOk

  test "can parse actions that end in a stray single quote":
    check "pass,nolog,noauditlog,phase:2,rev:24,id:390617,t:none,t:urlDecodeUni,setvar:tx.invalidarg=1,setvar:tx.invalidarg2=%{matched_var_name}'".actionOk

# ----------------------------------------------------------------------
suite "parsing normal ModSec rules":
  test "file with Apache Includes":
    check """
Include /etc/apache2/conf.d/modsecurity.d/exceptions.conf
Include /etc/apache2/conf.d/modsecurity.d/general_rules.conf
Include /etc/apache2/conf.d/modsecurity.d/antibrute.conf
""".parseEq(@[
      ModSec(kind: HttpInclude, path: "/etc/apache2/conf.d/modsecurity.d/exceptions.conf"),
      ModSec(kind: HttpInclude, path: "/etc/apache2/conf.d/modsecurity.d/general_rules.conf"),
      ModSec(kind: HttpInclude, path: "/etc/apache2/conf.d/modsecurity.d/antibrute.conf"),
    ])

  test "rule with escaped quote in string":
    check """
SecRule REQUEST_URI "[;) \":) ]" "phase:1,id:'1232',t:none,nolog,pass"
""".parseEq(@[
      Modsec(kind: SecRule, rules: @[
        SecRuleObj(
          variables: "REQUEST_URI",
          operator: "[;) \\\":) ]",
          actions: @[
            Action(kind: Phase, phase: 1),
            Action(kind: Id, id: 1232),
            Action(kind: Transform, t: None),
            Action(kind: Log, enabled: false),
            Action(kind: Pass)
          ]
      )
    ])])

  test "can parse SecComponentSignature":
    check """
SecComponentSignature "OWASP_CRS/3.1.0"
""".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "SecComponentSignature \"OWASP_CRS/3.1.0\"")
    ])

  test "SecMarker":
    check "SecMarker END_RULES".parseEq(@[
      Modsec(kind: SecMarker, marker: "END_RULES"),
    ])

  test "SecDefaultAction":
    check """
SecDefaultAction "log,deny,auditlog,phase:2,status:403"
""".parseEq(@[
      Modsec(kind: SecDefaultAction, actions: @[
        Action(kind: Log, enabled: true),
        Action(kind: Deny),
        Action(kind: Auditlog, enabled: true),
        Action(kind: Phase, phase: 2),
        Action(kind: Status, status: 403)
      ])
    ])

  test "SecAction":
    check """
SecAction "phase:2,id:13,t:none,pass,nolog,skipAfter:NEXT_RULE_23"
""".parseEq(@[
      Modsec(kind: SecAction, actions: @[
        Action(kind: Phase, phase: 2),
        Action(kind: Id, id: 13),
        Action(kind: Transform, t: None),
        Action(kind: Pass),
        Action(kind: Log, enabled: false),
        Action(kind: SkipAfter, marker: "NEXT_RULE_23")
      ])
    ])

  test "SecRuleRemoveById":
    check "SecRuleRemoveById 1232".parseEq(@[
      Modsec(kind: SecRuleRemoveById, removedIds: @[1232..1232])
    ])

  test "SecRuleRemoveById with multiple IDs":
    check "SecRuleRemoveById 1232 1233 1234".parseEq(@[
      Modsec(kind: SecRuleRemoveById, removedIds: @[1232..1232, 1233..1233, 1234..1234])
    ])


  test "SecRuleRemoveById with ID ranges":
    check "SecRuleRemoveById 999 1230-1234 600".parseEq(@[
      Modsec(kind: SecRuleRemoveById, removedIds: @[999..999, 1230..1234, 600..600])
    ])

  test "can parse SecArgumentSeparator":
    check "SecArgumentSeparator \";\"".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "SecArgumentSeparator \";\"")
    ])

  test "can parse SecContentInjection":
    check "SecContentInjection On".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "SecContentInjection On")
    ])

  test "can parse SecStreamOutBodyInspection":
    check "SecStreamOutBodyInspection On".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "SecStreamOutBodyInspection On")
    ])

  test "can parse SecResponseBodyAccess":
    check "SecResponseBodyAccess on".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "SecResponseBodyAccess on")
    ])

  test "can parse SecTmpSaveUploadedFiles":
    check "SecTmpSaveUploadedFiles Off".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "SecTmpSaveUploadedFiles Off")
    ])

  test "can parse AddOutputFilter":
    check "AddOutputFilter Sed html".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "AddOutputFilter Sed html")
    ])

  test "can parse RemoveOutputFilter":
    check "RemoveOutputFilter Sed html".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "RemoveOutputFilter Sed html")
    ])

  test "can parse OutputSed":
    check """
OutputSed "s/  //g;"
OutputSed "s/\"//g;"
OutputSed "s/\'//g;"
OutputSed "s/ =/=/g;"
OutputSed "s/= /=/g;"
OutputSed "s/< /</g;"
OutputSed "s/ >/>/g;"
""".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "OutputSed \"s/  //g;\""),
      Modsec(kind: SecUnparsed, unparsed: "OutputSed \"s/\\\"//g;\""),
      Modsec(kind: SecUnparsed, unparsed: "OutputSed \"s/\\'//g;\""),
      Modsec(kind: SecUnparsed, unparsed: "OutputSed \"s/ =/=/g;\""),
      Modsec(kind: SecUnparsed, unparsed: "OutputSed \"s/= /=/g;\""),
      Modsec(kind: SecUnparsed, unparsed: "OutputSed \"s/< /</g;\""),
      Modsec(kind: SecUnparsed, unparsed: "OutputSed \"s/ >/>/g;\"")
    ])

  test "can parse directories and locations":
    check """
<Directory /var/www/html>
<LocationMatch *.secret>
# rules here
</LocationMatch>
</Directory>
""".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "<Directory /var/www/html>"),
      Modsec(kind: SecUnparsed, unparsed: "<LocationMatch *.secret>"),
      Modsec(kind: SecUnparsed, unparsed: "</LocationMatch>"),
      Modsec(kind: SecUnparsed, unparsed: "</Directory>")
    ])

  test "can parse SecUploadFileMode":
    check "SecUploadFileMode 0644".parseEq(@[
      Modsec(kind: SecUnparsed, unparsed: "SecUploadFileMode 0644")
    ])

  test "can parse SecRuleUpdateTargetById":
    check "SecRuleUpdateTargetById 601 ARGS:comment|ARGS:socialLoginLinkAccountsRequire".parseEq(@[
      Modsec(kind: SecRuleUpdateTargetById,
             updatedId: 601..601,
             variables: "ARGS:comment|ARGS:socialLoginLinkAccountsRequire",
             replacements: "")
    ])

  test "fail on garbage between a comment and a continued line":
    check """
# just because there's a continued line below
# don't take the following nonsense as commented,
# OK?

blah blah blah blah

blah.

# continued: \
this is a comment though \
and so is this \
unlike in bash or python
""".parseOk.not


# ----------------------------------------------------------------------
suite "parsing ModSec-rule oddities from real-world rulesets":

  test "can parse escapes followed by (unidecodable) unicode chars":
    check "tests/evilquote.txt".readFile.parseOk

  test "can parse rule with \\ within a string":
    check """
SecAction "phase:1,id:'1234',t:none,nolog,pass, \
setvar:'tx.test=application/x-www-form-urlencoded|multipart/form-data'"
""".parseOk

  test "can parse a comment ending in \\ followed by an uncommented invalid rule":
    check """
#SecAction "phase:1,id:'1237',t:none,nolog,pass, \
setvar:'tx.test=application/x-www-form-urlencoded|multipart/form-data'"
""".parseOk

  test "can parse rule with no spacing between quoted arguments":
    check """
SecRule REQUEST_URI "java""t:none,phase:1,id:'1235',t:none,nolog,pass"
""".parseOk

  test "can parse rule with unicode double-quotes within double-quoted strings":
    check """
SecRule REQUEST_HEADERS:Referer   "intitle:”bobbytables” inurl:”btables\.html”" "phase:2,deny,log,t:none,t:urlDecodeUni,id:1236"
""".parseOk
