# Kubernetes network-policy boundary analysis (scenario 9) — design

Status: design only, not built. Read-only analysis. Active connection testing is a separate scenario and is not part of this document.

## 1. Intent

Answer one question for a Kubernetes cluster: **do the collected NetworkPolicy objects allow or block the workload-to-workload traffic that the owner says should be allowed or blocked?**

The owner states the expectation. The analysis checks the configured policy against it and reports each expected boundary as one of:

- `CONFIGURED_BLOCKS` — the policies, as written, deny the flow.
- `CONFIGURED_ALLOWS` — the policies, as written, permit the flow. For a flow that should be blocked, this is a gap.
- `UNKNOWN` — the answer depends on something discovery did not collect (an `ipBlock` peer, an unresolved selector, incomplete discovery).

## 2. Goals

- Evaluate expected source → destination → port boundaries against NetworkPolicy objects.
- Use Kubernetes' own selection rules: a policy selects pods by label; ingress and egress are isolated per pod once any policy selects that pod for that direction.
- Stay read-only: list calls only, no writes, no connections between pods.
- Report incomplete inputs as `UNKNOWN`, never as blocked or allowed.

## 3. Non-goals

- **Enforcement is not verified.** A NetworkPolicy object existing does not prove the CNI plugin enforces it. The analysis says "configured", never "enforced". Enforcement needs an active test (scenario 1's kind of work) and its own design.
- No attempt to open connections from pods. That is an active test and needs explicit approval.
- No judgement of what traffic *should* be allowed. The owner supplies the expectations.
- Not admission control (scenario 10) and not cloud security groups.

## 4. Inputs

**Collected from the cluster (list calls, no new permission beyond read access to these kinds):**
- `networkpolicies` in each namespace (`networking.k8s.io/v1`).
- `pods` with labels and IPs (already collected by discovery; labels are not yet recorded, see §9).
- `namespaces` with labels (already collected for namespace resolution; labels to be recorded).

**Supplied by the owner (the expectation):** a list of boundaries, each naming:
- `from`: a workload selector (namespace plus pod labels), or `external`.
- `to`: a workload selector (namespace plus pod labels).
- `port` and `protocol`.
- `expect`: `allow` or `block`.

The expectation input is not in the cluster, so it cannot be discovered. It is a file or API payload the owner writes.

## 5. Evaluation rules

For a flow `from → to:port/protocol`:

1. **Ingress isolation on `to`.** Find the NetworkPolicies in `to`'s namespace whose `podSelector` matches `to`'s labels and that select `Ingress`. When `policyTypes` is unset, `Ingress` is always selected, and `Egress` is selected only if the policy has egress rules.
   - None found: ingress is **open** on `to` for this flow.
   - Found: ingress is **isolated**. The flow is allowed only if at least one matching policy has an ingress rule whose `from` peers include `from` and whose `ports` include `port/protocol`.
2. **Egress isolation on `from`.** Same logic with `Egress` rules and the `to` peers, applied to `from`. Skipped when `from` is `external`.
3. The flow is `CONFIGURED_ALLOWS` only if it passes both sides. It is `CONFIGURED_BLOCKS` if either side isolates and no rule permits it.
4. A peer rule with `ipBlock`, or a selector that cannot be resolved against collected labels, makes that side `UNKNOWN`.
5. An empty `ports` list in a matching rule means all ports. A `port` range uses `endPort`.

Matching follows Kubernetes semantics: an empty `podSelector` matches every pod in the namespace; a `namespaceSelector` matches namespaces by their labels; both present in one peer entry means both must match.

## 6. Output

One result per expected boundary:

| Field | Meaning |
|---|---|
| `expect` | what the owner said should happen |
| `configured` | `CONFIGURED_BLOCKS`, `CONFIGURED_ALLOWS` or `UNKNOWN` |
| `matches` | `true` when `configured` agrees with `expect` |
| `ingressPolicies`, `egressPolicies` | the policy names that decided each side |
| `reasons` | short statements such as "no ingress policy selects db-0; ingress open" |
| `complete` | `false` when discovery was incomplete |

A mismatch is a finding. Its wording is "configured policy allows a flow the owner expects blocked", never "exploitable".

## 7. Safety and scope

- Read-only, like scenarios 2–8. It writes nothing and makes no pod-to-pod connection.
- The expectations file is untrusted input: it is parsed, validated against the allow-listed cluster and namespace, and never sent to the cluster.
- Results are configured permission. Reporting that a flow is allowed does not prove it works.

## 8. Test plan

Unit tests with built inventories, mirroring scenarios 2–8:
- no policy selects the destination → open, matches `expect: allow`, mismatches `expect: block`;
- an ingress policy selecting the destination that permits the source and port → allowed;
- the same policy with a different port → blocked;
- a default-deny policy (empty `ingress`) selecting the destination → blocked;
- an egress rule on the source that does not permit the destination → blocked, even when ingress allows it;
- `ipBlock` peer → `UNKNOWN`;
- incomplete discovery → `complete: false` on every result.

## 9. Discovery changes needed

- Discover `networkpolicies` (one list per namespace or cluster-wide, respecting the existing page limits).
- Record pod labels and namespace labels on the existing pod and namespace resources.

Both are read-only and add no new request shape beyond the list call for `networkpolicies`.

## 10. Decisions needed from the owner

1. **Where do the expectations come from?** A YAML file checked into the repo, or entered in the console. Recommendation: a file reviewed like other scenario content.
2. **Is a configured-only answer enough for the first increment?** Recommendation: yes. Enforcement needs an active test with its own approval.
3. **Which lab fixtures prove it?** Recommendation: two namespaces with a default-deny policy and one allow policy on kind-bas-lab, checked against this analysis before any claim.

## 11. Open items

- Enforcement by the CNI is outside this design (see §3).
