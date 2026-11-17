# Carbanak BFSI Pack: ATT&CK Mapping Register

Each row was checked against attack.mitre.org technique pages. Source is the MITRE page cited.
Confidence reflects how closely the technique's description matches the simulated behavior.
`no_clean_attack_technique` rows carry no ID and are excluded from ATT&CK coverage percentages.

| Item | Scenario | ID | Status | Confidence | Source | Notes |
|---|---|---|---|---|---|---|
| Stage 3 | Host firewall rule via netsh | T1686.003 | validated | high | https://attack.mitre.org/techniques/T1686/003/ | T1686.001 is cloud firewalls, not host. Spec's suggested .001 is wrong. |
| 9 | Banking application and process discovery | T1057 | validated | high | https://attack.mitre.org/techniques/T1057/ | |
| 10 | Payment gateway configuration discovery | T1083 | validated | medium | https://attack.mitre.org/techniques/T1083/ | Locating config files by path; read existence and paths only. |
| 11 | Database server and service discovery | T1046 | validated-with-caveat | medium | https://attack.mitre.org/techniques/T1046/ | Technique describes scanning remote hosts. Stage lists local listeners and service names only, with no connection attempt. |
| 12 | Domain privileged account enumeration | T1069.002 | validated | high | https://attack.mitre.org/techniques/T1069/002/ | Query group membership names only. |
| 13 | Network share discovery for financial data | T1135 | validated | high | https://attack.mitre.org/techniques/T1135/ | `net view` share names only. |
| 14 | Windows Credential Manager access attempt | T1555.004 | validated-with-caveat | medium | https://attack.mitre.org/techniques/T1555/004/ | Technique describes retrieving credentials. The approved tier enumerates target names only, which is a probe of the same access path, not a retrieval. |
| 15 | Browser credential-store access probe | T1555.003 | validated-with-caveat | medium | https://attack.mitre.org/techniques/T1555/003/ | Same caveat as 14: existence and metadata only, never opening the store. |
| 17 | Kerberos service account enumeration | T1558.003 | validated-with-caveat | low | https://attack.mitre.org/techniques/T1558/003/ | Kerberoasting is requesting service tickets. The approved tier enumerates SPNs (`setspn -Q`) only, which is the precursor, not the ticket request. Weak fit; user decision needed before Task 9. |
| 18 | Synthetic operator credential discovery | T1552.001 | validated | high | https://attack.mitre.org/techniques/T1552/001/ | Search files for credentials. The scenario searches only for a synthetic marker file it creates. |
| 19 | SMB administrative share access | T1021.002 | validated | high | https://attack.mitre.org/techniques/T1021/002/ | Requires target host. |
| 20 | WinRM remote execution simulation | T1021.006 | validated | high | https://attack.mitre.org/techniques/T1021/006/ | Requires target host. |
| 21 | Remote service creation | T1569.002 | validated | high | https://attack.mitre.org/techniques/T1569/002/ | Requires target host. |
| 22 | Remote scheduled task creation | T1053.005 | validated | high | https://attack.mitre.org/techniques/T1053/005/ | Requires target host. |
| 23 | Unauthorized payment beneficiary creation | none | `no_clean_attack_technique` | n/a | n/a | T1098 is account manipulation. A payee record is not an account used to keep adversary access. T1565.001 would require performing stored-data manipulation, which this scenario does not do. |
| 24 | Transaction amount manipulation | T1565.002 | validated-with-caveat | medium | https://attack.mitre.org/techniques/T1565/002/ | Technique is about data altered in transit. The simulation alters the request on the way to the ledger. |
| 25 | Unauthorized transaction approval | T1078 | validated-with-caveat | medium | https://attack.mitre.org/techniques/T1078/ | Valid-credential use fits. Maker-checker bypass is authorization abuse, which the technique describes less directly. |
| 26 | Operator session misuse | T1078 | validated | high | https://attack.mitre.org/techniques/T1078/ | |
| 27 | Payment transaction outside normal hours | T1078 | validated-with-caveat | medium | https://attack.mitre.org/techniques/T1078/ | Off-hours is a detection rule. The behavior is valid-account use. |
| 28 | Transaction limit modification attempt | none | `no_clean_attack_technique` | n/a | n/a | A transaction limit is a business policy control, not an identity-account modification. T1098 does not fit. |
| 29 | Financial document collection | T1005 | validated | high | https://attack.mitre.org/techniques/T1005/ | Synthetic documents only. |
| 30 | Payment database staging simulation | T1074.001 | validated | high | https://attack.mitre.org/techniques/T1074/001/ | Synthetic data only. |
| 31 | Archive financial records | T1560.001 | validated-with-caveat | medium | https://attack.mitre.org/techniques/T1560/001/ | Technique names archive utilities (7-Zip, WinRAR). Use a utility, not an in-process API, to keep the mapping honest. Windows `tar.exe` is acceptable. |
| 32 | HTTPS financial data exfiltration simulation | T1041 | validated-with-caveat | medium | https://attack.mitre.org/techniques/T1041/ | T1041 is exfiltration over the **existing** C2 channel. The exfil must reuse the Stage 7 C2 channel. A separate HTTPS channel should be mapped to T1048 or T1567 instead. |

## Open items

- **Item 17 (Kerberos enumeration)** is a weak fit. The approved tier permits SPN enumeration only, so the technique describes the precursor, not the ticket request. Decision needed before Task 9 (the chain stage) uses it.
- **Items marked `validated-with-caveat`** keep their ID. The caveat text goes in the scenario's description.

## Chain-internal gap steps (added in Task 8)

| Step | Scenario | ID | Status | Confidence | Source | Notes |
|---|---|---|---|---|---|---|
| 8b | Beneficiary change inside the chain | none | `no_clean_attack_technique` | n/a | n/a | Same behavior as item 23; the chain copy is a stage of the sequence, the standalone file is the item. |
| 8f | Ledger audit integrity check | none | `no_clean_attack_technique` | n/a | n/a | Verification of the simulated ledger, not an adversary behavior. No ATT&CK technique describes checking an audit chain. |
| 8g | Fraud detection and alert check | none | `no_clean_attack_technique` | n/a | n/a | Verification that controls raised an alert. Not an adversary behavior. |
