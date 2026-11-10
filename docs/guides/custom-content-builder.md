# Custom content builder: Sigma / YARA import and chains

Console: Scenarios > **Import Sigma / YARA**. API: `/api/content-import/*`.

## What it does
- **Sigma import** turns a rule into one safe step that should make the rule fire.
- **YARA import** writes a small inert file holding the rule's match strings and checks whether the host's security software removes it.
- **Chain** runs 2 to 8 approved steps in order. Each stage can run always, only if the previous stage was allowed (`prev_allowed`), or only if it was blocked (`prev_blocked`).

## Safety rules
- Nothing a rule describes is executed. Rule strings are carried inertly (echoed, or written into a file) and only if they pass a strict character allow-list. Anything else is reported as "not reproduced".
- Every import is a **draft**. A draft cannot run anywhere. An Admin (permission `content:transition`) approves or rejects it; approval saves it as a custom scenario and is audited. Importing needs only scenario-creation rights.
- Chains are built from references to already-approved custom scenarios; a request cannot supply its own command. A chain is gated like its most destructive stage.

## Supported
- Sigma: `process_creation` and `file_event` on Windows and Linux; conditions with and/or/not, parentheses, `N of`, `all of`; field modifiers contains/startswith/endswith/all. A rule with no ATT&CK tag needs a technique id supplied.
- YARA: text, hex and regex strings; the generated file is at most 4096 bytes.
- Not reproduced (reported per rule): ParentImage and other fields a single command cannot set, aggregation conditions (`| count`), other logsources.

## Outcomes
Exit code 0 = allowed. Non-zero = blocked by a security control. A chain's exit code is the last executed stage.

## Not yet verified
Not run on a real agent end to end, and the console dialog has not been checked in a browser. Needs a rebuild to ship.
