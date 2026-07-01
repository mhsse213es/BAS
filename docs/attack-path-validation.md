# Attack Path Validation

## Overview

Attack Path Validation identifies potential lateral movement paths from a compromised endpoint by validating reachability and administrative relationships between systems. It does not exploit targets or perform vulnerability scanning. Instead, it builds an attack graph from collected connectivity and privilege information, then computes the paths, blast radius, and choke points an attacker could traverse from any given starting host.

This is relationship mapping and reachability analysis — the XM Cyber / BloodHound Enterprise approach — not a penetration test. Every edge in the graph is an observed fact, not a simulated exploit.

---

## Prerequisites

Before running a collection, verify the following:

| Requirement | Notes |
|---|---|
| Windows agent online | Agent must be enrolled and connected |
| Local enumeration permissions | The agent runs as a user with rights to enumerate local admins and active sessions |
| Firewall allows outbound probes | SMB (445), WinRM (5985), RDP (3389) must be permitted from the agent to the target list |
| Targets explicitly specified | The agent probes only the hosts you supply — it performs no subnet discovery |
| Domain-joined host (optional) | Required for SharpHound to run; non-domain hosts collect reachability and local identity only |
| SharpHound configured (optional) | Admin must enable SharpHound in the schedule configuration |

If collection returns fewer nodes than expected, check permissions first. A lack of local admin rights on the collecting endpoint suppresses session and admin enumeration without error — the collection succeeds with a smaller graph.

---

## What Collection Does

When a collection runs, the agent performs the following actions in order:

### 1. Local Identity Collection

- **Local Administrators** — enumerates every principal (user or group) in the local Administrators group and emits an `admin-to` edge from each principal to the collecting host.
- **Interactive Sessions** — enumerates currently active logon sessions (interactive and remote interactive) and emits a `has-session` edge from the host to each logged-on user, indicating credentials for those accounts may be harvestable from memory on this machine.

### 2. Reachability Probes

For each host in the server-supplied target list, the agent attempts a TCP connect (1.5 s timeout) on three ports:

| Port | Protocol | Edge emitted |
|---|---|---|
| 445 | SMB | `smb` |
| 5985 | WinRM | `winrm` |
| 3389 | RDP | `rdp` |

The agent **only probes the hosts you provide**. It never performs range scans or ARP discovery. A host that is unreachable on all three ports is omitted from the graph entirely.

### 3. SharpHound (domain-joined hosts only)

If SharpHound is enabled and the host is domain-joined, the agent:

1. Receives the SharpHound binary from the server (from the payload store — not bundled with the agent).
2. Executes it with the configured arguments.
3. Uploads the raw output ZIP to the server.

The server parses the ZIP and merges the AD relationship edges into the same graph as the reachability edges. The agent never interprets SharpHound output.

### 4. Upload

The agent submits all collected nodes and edges to `POST /api/attackpath/collect`. The server stores this as the agent's latest collection and immediately notifies connected browser sessions of the new node and edge counts. The agent does not build a graph or compute paths — all analytics are server-side.

---

## Graph Edges — Reference

Each edge represents an observed relationship or reachability fact. The direction is `From → To`.

| Edge | Meaning |
|---|---|
| `smb` | The source host can reach the destination over TCP 445 (SMB). Lateral movement via file share access, PsExec, or remote service creation is possible if credentials are available. |
| `winrm` | TCP 5985 reachable. PowerShell Remoting or WinRM-based lateral movement is possible. |
| `rdp` | TCP 3389 reachable. Remote Desktop access is possible if credentials are available. |
| `admin-to` | The source user or group is a member of the local Administrators group on the destination host. Credential reuse on this account yields admin access to that machine. |
| `has-session` | An interactive logon session for the destination user currently exists on the source host. Credentials for that user may be harvestable from LSASS on that machine. |
| `member-of` | The source user or group is a member of the destination group (AD). Enriched by SharpHound. |
| `credential` | A reusable credential (e.g. shared local admin password) links a user to a host. Derived from SharpHound data. |

Reachability edges (`smb`, `winrm`, `rdp`) connect hosts to hosts. Identity edges (`admin-to`, `has-session`, `member-of`) connect users/groups to hosts or other groups. An attack chain typically traverses both: reach a host over SMB, harvest a session credential, use that credential to reach the next host.

---

## Derived Insights

After collection, the server computes the following from the graph:

### Paths to Domain Admin

Potential privilege escalation or lateral movement chains that lead from a given entry host through observed relationships to a node tagged as a Domain Controller or marked `highValue` (Domain Admins group or equivalent). These are computed using shortest-path traversal over the collected edges — the system does not know about Domain Admin unless a domain-joined collection or SharpHound provided that relationship. Without AD data, this section is empty.

### Blast Radius

The estimated number of distinct hosts reachable from a selected entry endpoint by chaining reachability edges (`smb`, `winrm`, `rdp`). A blast radius of 12 means: if this endpoint were compromised, an attacker with credentials could potentially reach 12 other systems using the connectivity observed during collection.

### Choke Points

Hosts that appear in a high proportion of computed attack paths. Compromising or hardening a choke point significantly increases or reduces attacker reach across the fleet. These are the highest-leverage targets for network segmentation improvements.

### Crown Jewel Exposure

Attack paths that terminate at a host tagged as a Crown Jewel (ERP system, backup server, payment gateway, etc.). Tags are configured per-host in the infrastructure settings.

### Segmentation Violations

Reachability edges that cross segment boundaries where connectivity should be blocked by policy. Requires segment tags to be assigned to hosts.

---

## Collected Data vs. Derived Insights

**Collected Data** (raw facts from agents):

- Reachable services (SMB / WinRM / RDP per target pair)
- Local Administrator principals per host
- Active interactive logon sessions per host
- Active Directory relationships — groups, memberships, admin assignments, sessions (SharpHound only)

**Derived Insights** (computed server-side from collected data):

- Lateral movement paths
- Blast Radius per entry host
- Choke Points
- Crown Jewel exposure chains
- Paths to Domain Admin / high-value targets
- Segmentation violations

The distinction matters for interpreting results: if an insight is missing, the underlying collected data may be incomplete due to permissions or missing SharpHound, not a product defect.

---

## SharpHound Enrichment

Without SharpHound, the graph contains only what the Windows agent observed locally: which hosts are reachable over SMB/WinRM/RDP, who is a local admin on the collecting host, and who has an active session on it.

Enable SharpHound to enrich the graph with Active Directory relationships including:

- Group memberships (`member-of`)
- AdminTo edges across all domain-joined machines
- HasSession edges across the domain
- Local admin rights (from GPO or direct assignment)
- GPO links and OU structure

Without SharpHound, you see host-to-host connectivity but not who can use it. With SharpHound, you see the full chain: endpoint → reachability → AD privilege → Domain Admin.

SharpHound only runs on domain-joined hosts. On workgroup machines or standalone servers, reachability and local identity collection still run; SharpHound is silently skipped.

---

## Scheduling

Configure automatic collection under **Settings → Attack Path → Schedule**.

Scheduled collections dispatch to all online agents at the configured interval and automatically refresh the attack graph without manual intervention. The server checks every minute whether the configured interval has elapsed since the last run — no action is taken if agents are offline or the schedule is disabled.

Recommended intervals:

| Environment | Interval |
|---|---|
| Active AD / high churn | 4–8 hours |
| Stable production network | 24 hours |
| Post-change validation | Manual (on-demand) |

---

## Limitations

- **Explicit targets only.** The agent probes only the hosts in the supplied target list. Systems not in the list are invisible to the graph, regardless of what is on the network.
- **No subnet discovery.** The agent does not perform ARP scans, ICMP sweeps, or any form of host enumeration. You must supply the targets.
- **No exploitation.** Reachability is confirmed via TCP connect only. The agent does not authenticate to any service, execute code on targets, or test for vulnerabilities.
- **No credential testing.** An `admin-to` edge means administrative rights were observed locally — it does not test whether those credentials are valid against remote hosts.
- **Results depend on collector permissions.** A collecting agent without local admin rights on its own host will not see local admin or session edges. A non-domain-joined agent will not run SharpHound.
- **Graph is a snapshot.** Collection reflects the state of the network at the time the agent ran. Sessions and reachability change; re-collect to refresh.
- **Cannot infer unobserved relationships.** If a privilege path was never collected (because the relevant host was offline, out of scope, or SharpHound was not run), it will not appear in the graph.

---

## Confidence and Interpretation

Attack paths represent potential attacker movement based on observed relationships. They are not proof that exploitation is possible.

- A `smb` edge means TCP 445 accepted a connection — it does not mean the attacker has valid credentials for that host.
- An `admin-to` edge means local admin rights were observed — it does not confirm those rights extend to remote administration.
- A path to Domain Admin indicates that the chain of relationships exists in the graph — it does not confirm that every step is exploitable without additional credential access.

Use these paths to prioritise hardening and segmentation work, not as an exploitation roadmap. Every path you close reduces theoretical attacker reach even before any vulnerability is confirmed.

---

## Security Considerations

The collection process is non-invasive:

| Property | Detail |
|---|---|
| No exploits executed | TCP connect probes only; no authentication, no payloads |
| No target modification | The agent reads local state and probes ports; it writes nothing to target systems |
| Read-only enumeration | Local admin and session enumeration uses standard Windows APIs (no WMI writes, no registry changes) |
| Minimal network traffic | One TCP SYN per port per target (three probes per host, 1.5 s timeout each) |
| Controlled scope | Agent probes only the explicit target list provided by the server |
| No propagation | The agent does not move to or execute on any remote host |

SOC teams can safely whitelist this traffic as authorized reconnaissance from enrolled BAS agents. It generates the same signature as a TCP port scan with a very short host list.

---

## Supported Relationship Types

### Current

| Type | Source |
|---|---|
| SMB reachability (TCP 445) | Agent — reachability probe |
| WinRM reachability (TCP 5985) | Agent — reachability probe |
| RDP reachability (TCP 3389) | Agent — reachability probe |
| Local Administrator membership | Agent — local identity |
| Interactive Session | Agent — local identity |
| AD Group Membership | SharpHound |
| AD AdminTo | SharpHound |
| AD HasSession | SharpHound |
| Shared credential | SharpHound |
| GPO links | SharpHound |

### Planned

| Type | Notes |
|---|---|
| SSH (TCP 22) | Linux/macOS agent support |
| WMI | Port 135 + DCOM |
| PsExec | SMB-based execution path |
| Remote Registry | Port 445, registry service |
| DCOM | Port 135 |
| SQL Admin | Port 1433 |
| Azure AD / Entra ID | Cloud identity graph (requires connector) |
| AWS IAM | Cross-account privilege paths |
| Kubernetes RBAC | Service account privilege chains |

Adding a new edge type requires: agent-side probe, edge kind constant in `graph.go`, and server-side path traversal — no schema changes.

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/attackpath/collect` | POST | Agent submits a collection payload (agent-authed) |
| `/api/attackpath/sharphound` | POST | Agent uploads raw SharpHound ZIP (agent-authed) |
| `/api/attackpath/graph` | GET | Returns the merged fleet graph (nodes + edges) |
| `/api/attackpath/summary` | GET | Returns blast radius, choke points, path counts |
| `/api/attackpath/paths` | GET | Returns computed paths to high-value targets |
| `/api/attackpath/schedule` | GET / PUT | Reads or updates the collection schedule |
| `/api/attackpath/collect/trigger` | POST | Triggers an immediate on-demand collection |
