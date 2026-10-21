# API BAS DET-001 per-scenario analysis

Each scenario that was `not_evaluated` before this analysis is listed once, with its decision. A detection rule is added
only when the attack and the access-event telemetry justify the rule. Bulk assignment is not used.

Scenarios analysed: 66. Detection added: 24. Still not_evaluated: 42.

| Scenario | Decision | Rule | Justification |
|---|---|---|---|
| API-BAS-ABUSE-002 | not_evaluated | - | single report request; no volume or owner signal; no rule for expensive-query cost |
| API-BAS-ABUSE-003 | not_evaluated | - | single page request; no volume or owner signal; no rule for response size |
| API-BAS-ABUSE-004 | not_evaluated | - | single GraphQL request; query depth is not a volume, owner or injection class the fixture carries |
| API-BAS-ABUSE-005 | not_evaluated | - | upload targets the attacker own order; no rule for body size |
| API-BAS-ABUSE-006 | detection added | APIBAS-REL-005 | Ten validation calls in one run reach the burst threshold. The attack is a volume of counted requests, which is what the rule sees. |
| API-BAS-ABUSE-007 | detection added | APIBAS-REL-005 | Ten OTP sends in one run reach the burst threshold. Paid-unit abuse is a volume the rule sees. |
| API-BAS-ABUSE-008 | detection added | APIBAS-REL-005 | Ten anonymous signups in one run reach the burst threshold. REL-005 counts requests regardless of identity, so the anonymous attack is visible. |
| API-BAS-ABUSE-009 | detection added | APIBAS-REL-005 | Ten quote requests in one run reach the burst threshold. Rotating the session identifier does not change the run volume the rule counts. |
| API-BAS-AUTHN-001 | detection added | APIBAS-REL-011 | The anonymous read of an owned order is served by the vulnerable build. REL-011 fires on a successful request with no identity that reaches an owned object. |
| API-BAS-AUTHN-002 | not_evaluated | - | single revoked-token attempt is below the REL-001 threshold of three; one refusal alerts nothing |
| API-BAS-AUTHN-003 | not_evaluated | - | forged alg_none identity is the owner identity in the vulnerable build: the blind spot documented for DET-007; no claim is made |
| API-BAS-AUTHN-004 | not_evaluated | - | redirect URI validation produces no owner or volume signal; no rule |
| API-BAS-AUTHN-005 | not_evaluated | - | token exchange reuse returns 400; the 401 failure rule does not match; no rule |
| API-BAS-AUTHN-007 | not_evaluated | - | forged certificate subject is the owner identity: the same blind spot as DET-007; the attacker has no identity of its own |
| API-BAS-AUTHN-009 | not_evaluated | - | workload token request without the secret has no owner; two requests are below the thresholds |
| API-BAS-AUTHN-010 | not_evaluated | - | sensitive action on the attacker own order; no privileged-function class covers the close action |
| API-BAS-AUTHN-011 | not_evaluated | - | WebSocket handshake only; origin validation is not a rule class and frame behaviour is not built |
| API-BAS-AUTHZ-002 | detection added | APIBAS-REL-004 | A customer request to an admin route names the order owned by another customer. The access event names that owner. |
| API-BAS-AUTHZ-003 | not_evaluated | - | mass assignment on the attacker own order; REL-004 needs a foreign object |
| API-BAS-AUTHZ-004 | detection added | APIBAS-REL-007 | The self-assigned role change is a privileged permission change under the policy. REL-007 fires on the setup attempt in both builds, before the fixed build refuses it. |
| API-BAS-BIZ-001 | detection added | APIBAS-REL-007 | A customer refund is a privileged financial operation under the policy. REL-007 fires on the attempt in both builds, because the privileged call is made whatever the outcome. |
| API-BAS-BIZ-002 | not_evaluated | - | negative quantity on the attacker own order; no rule for value validation |
| API-BAS-BIZ-003 | not_evaluated | - | two credit requests are below the volume threshold; no owner signal |
| API-BAS-BIZ-004 | not_evaluated | - | two payment requests are below the volume threshold; no owner signal |
| API-BAS-BIZ-005 | not_evaluated | - | five parallel withdrawals on the attacker own order are below the volume threshold; the race outcome is graded by the scenario itself |
| API-BAS-BIZ-006 | not_evaluated | - | status change on the attacker own order; no privileged-function class |
| API-BAS-BIZ-007 | detection added | APIBAS-REL-007 | Approving a payout is a privileged financial approval under the policy. REL-007 fires on the attempt in both builds. |
| API-BAS-BIZ-008 | not_evaluated | - | six transfers are below the volume threshold of ten |
| API-BAS-BIZ-009 | not_evaluated | - | beneficiary change on the attacker own order; not a foreign-owner or privileged class |
| API-BAS-BIZ-010 | not_evaluated | - | two coupon redemptions are below the volume threshold |
| API-BAS-BIZ-011 | not_evaluated | - | two reservations are below the volume threshold |
| API-BAS-DATA-005 | detection added | APIBAS-REL-004 | The filter names the protected account value of an order owned by another customer. The lab attributes a query that names a protected value to that value owner, so the access event names that owner. |
| API-BAS-DATA-006 | not_evaluated | - | cache headers are response properties the access event does not carry |
| API-BAS-DATA-007 | not_evaluated | - | export of the attacker own order; protected fields are a response property, not a rule class |
| API-BAS-DATA-008 | not_evaluated | - | card display on the attacker own order; masking is a response property |
| API-BAS-DATA-009 | not_evaluated | - | staging route on the attacker own object; environment exposure is not a rule class |
| API-BAS-DATA-010 | detection added | APIBAS-REL-004 | The signed file path names an order owned by another customer. The lab now attributes an order ID embedded in a path segment to its owner, so the access event names that owner. |
| API-BAS-DISC-002 | detection added | APIBAS-REL-011 | The anonymous request to the retired version reaches an owned order and is served by the vulnerable build. REL-011 fires on it. |
| API-BAS-DISC-004 | detection added | APIBAS-REL-011 | The anonymous request to the drifted route reaches an owned order and is served by the vulnerable build. REL-011 fires on it. |
| API-BAS-DISC-005 | not_evaluated | - | the anonymous CORS request names no owned object; REL-011 needs an owned object, so no rule applies |
| API-BAS-DISC-006 | detection added | APIBAS-REL-011 | The anonymous request to staging reaches an owned order and is served by the vulnerable build. REL-011 fires on it. |
| API-BAS-DISC-007 | not_evaluated | - | the anonymous documentation request names no owned object; REL-011 needs an owned object, so no rule applies |
| API-BAS-DISC-008 | not_evaluated | - | not-found on a nonexistent object: no owner exists for REL-004 to match |
| API-BAS-DISC-010 | detection added | APIBAS-REL-004 | The legacy regional route is reached for an order owned by another customer. The access event names that owner. |
| API-BAS-GWAY-002 | detection added | APIBAS-REL-011 | The anonymous request to the legacy route reaches an owned order and is served by the vulnerable build. REL-011 fires on it. |
| API-BAS-GWAY-003 | detection added | APIBAS-REL-004 | The method-override request targets an order owned by another customer. The access event names that owner. |
| API-BAS-GWAY-004 | detection added | APIBAS-REL-004 | The percent-encoded request targets an order owned by another customer. The decoded path still names that owner. |
| API-BAS-GWAY-005 | not_evaluated | - | duplicate content-type on the attacker own order; body parsing differential is not a rule class |
| API-BAS-GWAY-006 | detection added | APIBAS-REL-004 | The forwarded-host request targets an order owned by another customer. The access event names that owner. |
| API-BAS-GWAY-008 | not_evaluated | - | schema omission on the attacker own order; no rule |
| API-BAS-GWAY-009 | detection added | APIBAS-REL-005 | Ten requests in one run reach the burst threshold. Varying the forwarded address does not change the run volume the rule counts. |
| API-BAS-GWAY-010 | detection added | APIBAS-REL-011 | The anonymous request to the legacy region reaches an owned order and is served by the vulnerable build. REL-011 fires on it. |
| API-BAS-GWAY-012 | not_evaluated | - | upstream certificate trust is not in the access event; no owner or volume signal |
| API-BAS-INJ-006 | not_evaluated | - | duplicate JSON keys: no injection class covers it (the classes are SQL, traversal, LDAP and template) |
| API-BAS-INJ-009 | not_evaluated | - | CRLF and cookie-attribute injection in a note: no injection class covers header attributes |
| API-BAS-INJ-011 | not_evaluated | - | prototype key in an attribute merge: no injection class covers prototype keys |
| API-BAS-INJ-012 | not_evaluated | - | form-encoded status skips validation: no injection class; a validation bypass has no signature |
| API-BAS-INTEG-001 | not_evaluated | - | quote refresh on the attacker own order; contract validation is not a rule class |
| API-BAS-INTEG-002 | not_evaluated | - | the anonymous webhook replay names no owned object; REL-011 needs an owned object, so no rule applies |
| API-BAS-INTEG-003 | not_evaluated | - | SSRF through the webhook test has no owner and no SSRF injection class |
| API-BAS-INTEG-004 | not_evaluated | - | open redirect has no object or owner; no rule |
| API-BAS-INTEG-006 | detection added | APIBAS-REL-004 | The proxy request names an order owned by another customer. The access event names that owner. |
| API-BAS-INTEG-007 | detection added | APIBAS-REL-009 | The same payment authorization during the fraud-check outage as BIZ-012. Graded separately; it does not change the DET-003 mapping on BIZ-012. |
| API-BAS-INTEG-009 | detection added | APIBAS-REL-011 | The anonymous partner request names an owned order. REL-011 fires when the vulnerable build serves it. |
| API-BAS-INTEG-010 | not_evaluated | - | async publish-form adapter only; no consumer access event exists to grade |
| API-BAS-INTEG-011 | not_evaluated | - | callback registration has no object; no allowlist rule |
