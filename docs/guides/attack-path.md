# Audspect BAS — Attack Path Validation Guide

**Platform Version:** v1.7.3

---

## Overview

Attack Path Validation maps how an attacker with initial access on one endpoint could reach other systems in the network. Unlike BAS scenario simulation (which tests control effectiveness on a single endpoint), attack path analysis answers a broader question: **which hosts can reach which other hosts, and through what relationships?**

The platform builds a graph where:
- **Nodes** are hosts and user identities
- **Edges** are observed reachability or privilege relationships (network access, admin group membership, active sessions)

From this graph, it computes attack path risk: blast radius, choke points, crown jewel exposure, and lateral movement potential.

---

## What Collection Does (and Doesn't Do)

**What collection does:**
- Probes TCP reachability to target hosts you specify (selected ports only: SMB 445, WinRM 5985/5986, RDP 3389, SSH 22)
- Reads the local Administrators group on Windows (no escalation — reads via WinAPI as the agent user)
- Reads active logon sessions on Windows (no credential extraction)
- Optionally runs SharpHound against an Active Directory domain (domain-joined hosts only, requires explicit enable)
- Uploads the collected graph to the orchestrator

**What collection does not do:**
- Does not exploit any vulnerability
- Does not extract credentials
- Does not authenticate to remote hosts (reachability = TCP connect only)
- Does not modify any system configuration
- Does not probe hosts not on the list you provide

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Agent must be Active | Offline agents cannot receive AP dispatch |
| Agent has OS-level network access | Agent must be able to reach the target IPs |
| Target list provided | You supply the list of hosts to probe |
| Admin group read permission | Windows only; agent user needs local read access |
| SharpHound (optional) | Place `SharpHound.exe` on the server; set `BAS_SHARPHOUND_PATH` env var |
| Domain connectivity (SharpHound) | Required only if SharpHound collection is enabled |

---

## Job Lifecycle

Every collection request creates a tracked job:

```
POST /api/attackpath/jobs
        │
        ▼
   ┌─────────┐
   │ Queued  │  ← Job created; waiting for agent to receive dispatch
   └────┬────┘
        │ (agent receives and acknowledges)
        ▼
   ┌────────────┐
   │ Dispatched │  ← Dispatch confirmed by agent ACK
   └──────┬─────┘
          │ (agent begins collection)
          ▼
   ┌─────────┐
   │ Running │  ← Collection stages progress (see below)
   └────┬────┘
        │
   ┌────┴────────────────────────┐
   │                             │
   ▼                             ▼
┌───────────┐           ┌─────────────────────┐
│ Completed │           │ failed / timed_out  │
│           │           │ delivery_failed      │
│           │           │ cancelled            │
└───────────┘           └─────────────────────┘
```

### Job status definitions

| Status | Meaning |
|---|---|
| **queued** | Job created; agent has not yet acknowledged |
| **dispatched** | Agent acknowledged receipt; collection not yet started |
| **running** | Agent is actively collecting |
| **completed** | Collection finished; graph uploaded and processed |
| **failed** | Collection aborted due to an error (see `error` field) |
| **timed_out** | Collection exceeded the 30-minute timeout |
| **delivery_failed** | Agent did not ACK dispatch within 30 seconds |
| **cancelled** | Cancelled by an admin before completion |

### Automatic retry

If a job is in `queued` state when the agent reconnects (after being offline), the orchestrator re-dispatches it automatically. This handles the case where the server dispatched while the agent was temporarily offline.

---

## Collection Stages

During a `running` job, the agent reports progress through stages:

| Stage | Description |
|---|---|
| `initializing` | Agent received the job and is preparing collection context |
| `probing` | TCP reachability probes to target IP list |
| `enumerating_admins` | Reading local Administrators group on each reachable host |
| `enumerating_sessions` | Reading active logon sessions on each reachable host |
| `running_sharphound` | SharpHound collecting AD data (optional stage) |
| `building_graph` | Constructing node/edge graph from collected data |
| `uploading` | Uploading graph JSON to orchestrator |

The Attack Path tab in the agent detail drawer and the Attack Path dashboard display the current stage, percentage progress, and targets-completed/targets-total counters in real time.

---

## Running a Collection

### From the dashboard

1. Navigate to **Attack Path** in the left sidebar
2. Click **Run Collection**
3. Select an agent as the collection source
4. Enter target hosts: comma-separated IPs, CIDR blocks, or hostnames
5. Optionally enable SharpHound (domain-joined hosts only)
6. Click **Start Collection**

The job appears in the collection history immediately with status **queued**.

### Via API

```
POST /api/attackpath/jobs

Body:
{
  "agentId": "agt-abc123",
  "targets": ["192.168.1.0/24", "10.0.0.50", "dc01.company.local"],
  "enableSharpHound": false,
  "label": "Weekly scan - Finance subnet"
}

Response: { "jobId": "ap-job-xyz", "status": "queued" }
```

### Target pre-population

The dashboard pre-fills the target list with the agent's detected /24 subnet. This is derived from the agent's reported IP on its last heartbeat. You can modify or expand this list before dispatching.

---

## Scheduling

Attack Path collection can be scheduled on a recurring basis per agent:

```
POST /api/attackpath/schedule
Body:
{
  "agentId": "agt-abc123",
  "cronExpression": "0 2 * * 1",   // Every Monday at 02:00
  "targets": ["192.168.1.0/24"],
  "label": "Weekly finance subnet scan"
}
```

Scheduled jobs appear in the schedule list and create tracked jobs at the configured time.

---

## SharpHound Integration

SharpHound is the BloodHound data collector for Active Directory. It enumerates:
- Domain users and groups
- Group Policy Objects
- Trust relationships
- Session information from DCs
- ACL relationships on AD objects

**Setup:**

1. Place `SharpHound.exe` on the orchestrator server
2. Set `BAS_SHARPHOUND_PATH=/path/to/SharpHound.exe` in the orchestrator environment
3. The orchestrator pushes SharpHound to the agent as part of the job payload during AP dispatch
4. The agent executes SharpHound in collection-only mode, compresses results, and uploads

**Important:** SharpHound collection only runs if `enableSharpHound: true` is set in the job and if `BAS_SHARPHOUND_PATH` is configured. Without this, the platform still performs TCP probe + local admin/session enumeration, which provides a useful but less complete graph.

---

## Graph Analysis

After a completed collection, the orchestrator processes the uploaded data and builds an in-memory graph:

**Nodes:**
- Host nodes (IP, hostname, OS, domain status)
- User identity nodes (domain users, local accounts observed in sessions)

**Edges (relationship types):**
- `tcp_reachable` — Source agent can reach target on tested ports
- `local_admin` — User identity is a local administrator on target host
- `active_session` — User identity has an active logon session on target host
- `ad_group_member` — (SharpHound) Domain group membership relationship
- `ad_gpo` — (SharpHound) Group Policy applied to host

**Derived metrics (computed from the graph):**

| Metric | Description |
|---|---|
| **Blast Radius** | Number of hosts reachable from the collection source in ≤N hops |
| **Choke Points** | Hosts that appear in the most attack paths; hardening reduces the blast radius significantly |
| **Crown Jewel Exposure** | Number of active attack paths terminating at or passing through crown-jewel-tagged assets |
| **Path Count** | Total number of distinct paths through the graph from any source to any target |
| **Shortest Path** | Minimum hop count to reach any crown jewel asset |

---

## Asset Tagging

Hosts in the attack path graph can be tagged with a criticality tier:

| Tag | Meaning |
|---|---|
| **crown-jewel** | Highest value asset; exposure to this asset is always Critical severity |
| **high** | Important asset; exposure weighted heavily in scoring |
| **medium** | Standard business asset |
| **low** | Low-value or non-sensitive host |

**Setting asset tags:**
```
POST /api/attackpath/assets/{hostId}/tag
Body: { "tier": "crown-jewel", "label": "Domain Controller", "notes": "DC01 - primary AD controller" }
```

Asset tags persist across collection runs. Once tagged, a host retains its tier in all future graphs.

---

## Visualization

The Attack Path section in the dashboard provides an interactive graph view:

- **Node colors:** Host type (server/workstation/domain controller) and criticality tier
- **Edge colors:** Relationship type (TCP reach / admin / session / AD)
- **Shortest path highlight:** Click any crown-jewel node to highlight the shortest path from the collection source
- **Blast radius view:** Shows all hosts reachable from a selected source within selected hop count

---

## Risk Calculation

The **Attack Path Score** is a scalar (0–100, higher = safer) computed from the inverse of exposure:

```
Attack Path Score = 100 - (normalized_exposure × 100)
```

Where `normalized_exposure` accounts for:
- Proportion of tested hosts reachable by the collection source
- Crown jewel reachability (heavily penalized)
- Choke point concentration (high choke point count → more fragile topology)
- SharpHound-derived privilege path depth (if available)

---

## Finding Creation from Attack Paths

When a collection completes and the graph contains high-severity paths, the platform creates **Attack Path Findings**:
- One finding per identified high-severity path type (not per path instance — deduped by category)
- Finding is linked to the collection job for evidence
- Remediation guidance suggests the highest-impact choke point to harden

Attack Path Findings appear in the **Findings** section alongside BAS simulation findings and follow the same lifecycle (Open → In Progress → Validated → Resolved).

---

## Monitoring Jobs

All in-progress and completed jobs for a specific agent are visible in:
- The **Attack Path** tab of the agent detail drawer
- The **Attack Path** section → **Job History** in the main navigation

Job progress (stages, percentage, targets-completed/total) updates in real time via WebSocket while the job is running.

---

*© Audspect — Confidential — Customer Distribution*
