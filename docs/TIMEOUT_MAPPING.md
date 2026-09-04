# Technique Timeout Mapping Reference

## Overview

Some ATT&CK techniques legitimately require extended execution times on real systems. This document maps techniques that commonly exceed the 120-second default timeout and provides recommended timeout values based on observed behavior and system scale.

## Slow Techniques Requiring Custom Timeouts

### CRITICAL (Often exceed 120s on realistic systems)

#### T1083 - File and Directory Discovery
- **Description**: Recursive file/directory enumeration
- **Real-world runtime**: 180-600+ seconds on multi-TB filesystems
- **Why slow**: Traverses entire directory trees, stat() calls for each entry
- **Recommended timeout**: **300 seconds** (small systems), **600 seconds** (large systems)
- **Scenarios affected**: 
  - windows-discovery.yaml (intentionally excluded, use windows-discovery-validation.yaml instead)
  - linux-discovery.yaml
  - Full ART sweeps

**Example slow commands:**
```powershell
Get-ChildItem -Path "C:\" -Recurse -File  # Multi-TB disk = 300-600s
```

#### T1087.002 - Domain Account Discovery
- **Description**: LDAP domain user/group enumeration
- **Real-world runtime**: 120-300+ seconds on domains with 10K+ users
- **Why slow**: LDAP queries are paginated (1000 user limit per query), multiple attribute lookups
- **Recommended timeout**: **300 seconds** (small domains), **600 seconds** (enterprise)
- **Scenarios affected**: 
  - windows-discovery.yaml (included, but at risk)
  - Full ART sweeps

**Example slow commands:**
```powershell
Get-ADUser -Filter * -ResultSetSize $null  # 10K users = 120-300s
```

#### T1018 - Remote System Discovery
- **Description**: Network topology enumeration (ping sweep, ARP scan)
- **Real-world runtime**: 120-400+ seconds on large subnets
- **Why slow**: Pings to every address (256 hosts per /24), ICMP timeout per host
- **Recommended timeout**: **300 seconds** (standard subnet), **600 seconds** (large ranges)
- **Scenarios affected**: 
  - windows-discovery.yaml (included, but at risk)
  - Full ART sweeps

**Example slow commands:**
```powershell
1..254 | ForEach { Test-Connection -ComputerName "192.168.1.$_" }  # 256 hosts = 120-300s
```

### HIGH (Often approach or exceed 120s)

#### T1526 - Cloud Infrastructure Discovery
- **Description**: Multi-cloud provider enumeration (AWS, Azure, GCP)
- **Real-world runtime**: 60-180+ seconds depending on APIs
- **Why slow**: API calls to each cloud provider, large result sets
- **Recommended timeout**: **300 seconds**
- **Scenarios affected**: cloud-vm-attack.yaml (partially covered)

#### T1087 - Account Discovery (general)
- **Description**: Local and domain user enumeration
- **Real-world runtime**: 30-120 seconds on large systems
- **Why slow**: Querying all users/groups, large result sets
- **Recommended timeout**: **180 seconds**
- **Scenarios affected**: Multiple discovery scenarios

### MEDIUM (May approach 120s on slower systems)

#### T1007 - System Service Discovery
- **Description**: Enumerate system services and drivers
- **Real-world runtime**: 20-60 seconds depending on service count
- **Why slow**: Querying service metadata, potentially 1000+ services
- **Recommended timeout**: **120 seconds** (systems with 1000+ services → **180 seconds**)
- **Scenarios affected**: windows-discovery.yaml, Full ART sweeps

#### T1518 - Software Discovery
- **Description**: Enumerate installed software
- **Real-world runtime**: 30-120+ seconds via WMI on slow systems
- **Why slow**: WMI queries are expensive, large result sets
- **Recommended timeout**: **150 seconds** (slow systems → **180 seconds**)
- **Scenarios affected**: windows-discovery.yaml, Full ART sweeps

#### T1538 - Cloud Service Dashboard
- **Description**: Enumerate cloud storage/services accessible from endpoint
- **Real-world runtime**: 60-180 seconds with API rate limiting
- **Why slow**: Multiple API calls with rate limits
- **Recommended timeout**: **300 seconds**
- **Scenarios affected**: cloud-vm-attack.yaml

## Profiling Guide: Measuring Actual Runtimes

To validate timeout values on your own systems:

### 1. Baseline Small Systems (< 500 GB, < 100 users, < 50 services)

```powershell
# T1083 - File Discovery baseline
Measure-Command {
  Get-ChildItem -Path "C:\Users" -Recurse -File -ErrorAction SilentlyContinue | Measure-Object
}

# T1087.002 - Domain Account baseline
Measure-Command {
  Get-ADUser -Filter * -ResultSetSize $null
}

# T1018 - Network sweep baseline (small subnet)
Measure-Command {
  1..50 | ForEach { Test-Connection -ComputerName "192.168.1.$_" -Count 1 -Quiet }
}
```

### 2. Large Production Systems (> 5 TB, > 10K users, > 1000 services)

```powershell
# T1083 - File Discovery production scale
# CAUTION: May take 5-10 minutes. Test outside business hours.
Measure-Command {
  Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue | Measure-Object
}

# T1087.002 - Enterprise domain query
Measure-Command {
  Get-ADUser -Filter * -ResultSetSize $null | Measure-Object
}

# T1018 - Large network sweep
# CAUTION: Generates significant network traffic. Coordinate with network team.
Measure-Command {
  1..254 | ForEach { Test-Connection -ComputerName "192.168.0.$_" -Count 1 -Quiet }
}
```

## Current Scenario Status

### ✅ Using Custom Timeouts (Safe)
- `windows-discovery-validation.yaml` - T1083, T1087.002, T1018 at 300s
- `clop-kill-chain.yaml` - Individual technique timeouts (20-30s)
- `ransomware-drill.yaml` - Individual technique timeouts
- Most attack-kill-chain scenarios

### ⚠️ At Risk (No Custom Timeouts for Slow Techniques)
- `art-full-windows.yaml` - All ART techniques at 120s default
- `art-full-linux.yaml` - All ART techniques at 120s default
- `art-full-darwin.yaml` - All ART techniques at 120s default
- `art-selective-*.yaml` - All ART techniques at 120s default
- `windows-discovery.yaml` - T1083 excluded, others at 120s default
- `linux-discovery.yaml` - All discovery techniques at 120s default
- `caldera-full-windows.yaml` - All techniques at 120s default

## Recommendations

### For Custom Scenarios
When creating discovery or enumeration-focused scenarios, always set explicit timeouts:

```yaml
- name: "Large-Scale File Discovery"
  technique_id: T1083
  executor: powershell
  timeout:
    executeSec: 300  # 5 minutes
    graceSec: 10
  command: |
    # Your T1083 command here
```

### For Full-Sweep Scenarios
If running full-sweep scenarios (art-full-*, caldera-full-*), either:
1. Create custom step overrides for known-slow techniques
2. Set a global higher timeout (consider infrastructure impact)
3. Use selective scenarios with pre-configured timeouts

### For Production Testing
Always profile on systems representative of your production scale:
- Never assume "small test systems" behavior applies to production
- Budget 30-50% overhead above observed times for system variance
- Test during off-peak hours to minimize impact
- Coordinate with network team for large-scale sweeps

## Testing Timeout Values

To validate that a timeout is sufficient:

```yaml
# Test timeout value on your system
timeout:
  executeSec: 300  # Proposed timeout
  graceSec: 10     # Grace for cleanup

# Run scenario and check:
# ✅ PASS: Execution completed normally
# ✅ FAIL: Execution completed but detection failed
# ❌ SKIPPED: Atomic not available on this system
# ❌ TIMEOUT: Killed before completion (timeout too short)
```

If you see TIMEOUT verdicts on known-working techniques, increase the timeout and re-test.

## Related Documentation

- [TIMEOUT_AUDIT.md](TIMEOUT_AUDIT.md) - Detailed audit findings
- [windows-discovery-validation.yaml](../scenarios/windows-discovery-validation.yaml) - Reference implementation with proper timeouts
- Agent timeout implementation: [agent/executor.go](../agent/executor.go) - `executeSeconds()` function
