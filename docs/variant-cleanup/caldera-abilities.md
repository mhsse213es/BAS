# Caldera abilities: inventory, mapping and validation status

## Source

Abilities are read at runtime from the Caldera server, not from a file in the repo. Read-only query on staging (`audspect-caldera`, API key read inside the container and not printed):

- **2,213 abilities** across **342 techniques**.
- Executors: sh 869, psh 885, cmd 671, pwsh 111, proc 28, native 3, other 4.
- **1,085 executor entries include a Caldera-provided cleanup command.**
- Tactics: defense-evasion 543, discovery 451, credential-access 211, execution 143, multiple 341, command-and-control 125, collection 90, impact 74, lateral-movement 59, persistence 50, exfiltration 50, privilege-escalation 20, initial-access 8, reconnaissance 2, plus a few malformed tactic labels (`x`, `commmand-and-control`, etc.) that need normalising.

## Gap in our code

`CalderaStore` keeps only each ability's command, executor and name. The cleanup field Caldera provides is dropped, so no Caldera variant can have cleanup today.

## Status

| Item | Status |
|---|---|
| Inventory of abilities | Done (counts above) |
| Side effects per ability | **Not done.** 2,213 abilities cannot be read one by one from here. |
| Cleanup mapped per ability | **Not done.** The Caldera-provided cleanups exist but are unverified. |
| Lab validation | **Not run.** No Windows lab endpoint is available. |
| Eligibility | Every Caldera variant is `unverified`, so it is blocked outside a lab. |

## Recommended next step

1. Store the Caldera cleanup field in `CalderaStore` so it can be reviewed.
2. Choose an allow-list of the most useful abilities (for example, the 50 persistence and 20 privilege-escalation abilities), read each one's side effects, and confirm its cleanup.
3. Validate the allow-list on a lab endpoint with the same snapshot and kill tests as the stager.
4. Only then mark those abilities `verified`. Everything else stays ineligible for normal execution.
