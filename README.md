# modsec
A parser and tools for mod\_security 2.x rulesets (in Nim) 

## big warning
This library is neither stable nor complete. Please wait for documentation and then a release and inclusion to the nimble package list.

## current status
We can parse the entirety of the OWASP3 and Atomic Modsecurity Rules. The most popular directives are represented directly. A selection of useful actions is represented directly. Much will show up in the rule lists but as 'unparsed' strings that need further examination. The big ruleset parser is in src/modsec/rules.nim; the big actions parser is in src/modsec/actions.nim. src/modsec.nim is a start on a library to work with entire rulesets.
