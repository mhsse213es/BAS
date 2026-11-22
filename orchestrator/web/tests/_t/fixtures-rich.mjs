// Fixture sets for judging the redesigned console with realistic data.
//
// The smoke fixtures (tests/smoke/fixtures.mjs) use one hostile-named row per endpoint: ideal for
// XSS checks, useless for judging layout. These sets reuse the smoke shapes (they are the real
// response shapes) but fill them with realistic names and enough rows for tables, charts and
// long-text wrapping to show what an operator actually sees.
//
//   rich   - populated, realistic
//   empty  - every list empty (first-run console)
//   error  - every API call fails with HTTP 500 (outage)
import { fixtureFor as smoke } from '../smoke/fixtures.mjs';
import { DEMO as demoA } from './demo-a.mjs';
import { DEMO as demoB } from './demo-b.mjs';
import { DEMO as demoC } from './demo-c.mjs';
import { DEMO as demoG1 } from './demo-g1.mjs';
import { DEMO as demoG2 } from './demo-g2.mjs';
import { DEMO as demoG3 } from './demo-g3.mjs';
import { DEMO as demoG4 } from './demo-g4.mjs';
import { DEMO as demoG5 } from './demo-g5.mjs';
import { DEMO as demoG6 } from './demo-g6.mjs';
import { DEMO as demoG7 } from './demo-g7.mjs';
import { DEMO as demoG8 } from './demo-g8.mjs';
import { DEMO as demoG9 } from './demo-g9.mjs';
import { DEMO as demoG10 } from './demo-g10.mjs';
import { DEMO as demoG11 } from './demo-g11.mjs';
import { DEMO as demoG12 } from './demo-g12.mjs';
import { DEMO as demoG13 } from './demo-g13.mjs';
import { DEMO as demoG14 } from './demo-g14.mjs';
import { DEMO as demoG17 } from './demo-g17.mjs';
import { DEMO as demoG15 } from './demo-g15.mjs';
import { DEMO as demoG16 } from './demo-g16.mjs';
import { DEMO as demoG18 } from './demo-g18.mjs';
import { DEMO as demoG19 } from './demo-g19.mjs';
import { DEMO as demoG20 } from './demo-g20.mjs';
import { DEMO as demoG21 } from './demo-g21.mjs';
import { DEMO as demoG24 } from './demo-g24.mjs';
import { DEMO as demoG22 } from './demo-g22.mjs';
import { DEMO as demoG23 } from './demo-g23.mjs';
import { DEMO as demoG25 } from './demo-g25.mjs';
import { DEMO as demoG28 } from './demo-g28.mjs';
import { DEMO as demoG29 } from './demo-g29.mjs';
import { DEMO as demoG30 } from './demo-g30.mjs';
import { DEMO as demoG31 } from './demo-g31.mjs';
import { DEMO as demoG26 } from './demo-g26.mjs';
import { DEMO as demoG27 } from './demo-g27.mjs';

const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();

const HOSTS = [
  ['WS-FIN-0142', 'windows', '10.20.4.42', 'Finance Workstations'], ['WS-FIN-0143', 'windows', '10.20.4.43', 'Finance Workstations'],
  ['DC-PRI-01', 'windows', '10.20.1.10', 'Domain Controllers'], ['DC-SEC-02', 'windows', '10.20.1.11', 'Domain Controllers'],
  ['FS-LEG-01', 'windows', '10.20.2.21', 'File Servers'], ['lnx-web-07', 'linux', '10.30.8.7', 'Linux Web Tier'],
  ['lnx-web-08', 'linux', '10.30.8.8', 'Linux Web Tier'], ['lnx-db-02', 'linux', '10.30.9.2', 'Payments DB'],
  ['MAC-DES-221', 'darwin', '10.40.2.221', 'Executive Laptops'], ['MAC-DES-222', 'darwin', '10.40.2.222', 'Executive Laptops'],
  ['WS-HR-0031', 'windows', '10.20.6.31', 'Finance Workstations'], ['CA-ISS-01', 'windows', '10.20.1.30', 'Domain Controllers'],
];
const STATES = ['online', 'online', 'online', 'online', 'online', 'degraded', 'online', 'online', 'offline', 'online', 'degraded', 'online'];

export function richAgents() {
  return HOSTS.map(([host, os, ip, group], i) => {
    const st = STATES[i];
    return {
      id: `a-${i + 1}`, agentId: `a-${i + 1}`, hostname: host, os, platform: os, ip, state: 'active',
      status: st, online: st !== 'offline', version: i % 5 === 0 ? '1.9.1' : '1.9.2',
      lastSeen: iso(st === 'offline' ? 2900 : i * 3), lastHeartbeat: iso(st === 'offline' ? 2900 : i * 3),
      groupId: 1 + (i % 4), groupName: group, tags: [], capabilities: [],
      osVersion: { windows: i % 3 ? 'Windows 11 23H2' : 'Windows Server 2022', linux: 'Ubuntu 22.04', darwin: 'macOS 14.6' }[os],
      ipAddress: ip, wsConnected: i !== 5 && st !== 'offline', transport: 'mtls', lastUpdate: iso(st === 'offline' ? 2900 : i * 3),
      sims: i % 4 === 0 ? 2 : 0,
    };
  });
}

const SCEN = ['Credential Dumping via LSASS', 'Ransomware — Shadow Copy Deletion', 'Persistence via Run Key', 'DCSync Replication Abuse', 'Office Child Process Execution', 'DNS Tunnelling Exfiltration', 'Kerberoasting', 'Defender Tamper Attempt'];
export function richRuns() {
  const status = ['completed', 'completed', 'running', 'completed', 'failed', 'completed', 'completed', 'completed'];
  return SCEN.flatMap((s, i) => [0, 1].map((k) => {
    const n = i * 2 + k;
    return {
      id: `run-${n + 1}`, name: s, scenarioId: `sc-${i + 1}`, scenarioName: s, status: status[i], mode: 'standard',
      agentId: `a-${(n % 12) + 1}`, hostname: HOSTS[n % 12][0], startedAt: iso(30 + n * 95), finishedAt: iso(20 + n * 95),
      createdAt: iso(31 + n * 95), score: 40 + ((n * 17) % 60), passed: 3 + (n % 5), failed: n % 4, total: 7,
      progress: { stepsTotal: 7, stepsDone: status[i] === 'running' ? 4 : 7 },
    };
  }));
}

const SEV = ['critical', 'high', 'high', 'medium', 'medium', 'medium', 'low'];
const TECH = [['T1003', 'OS Credential Dumping'], ['T1547', 'Boot or Logon Autostart'], ['T1021', 'Remote Services'], ['T1059', 'Command and Scripting Interpreter'], ['T1490', 'Inhibit System Recovery'], ['T1558', 'Steal or Forge Kerberos Tickets']];
export function richFindings() {
  return Array.from({ length: 22 }, (_, i) => {
    const [tid, tname] = TECH[i % TECH.length];
    return {
      id: `finding-${i + 1}`, techniqueId: tid, techniqueName: tname, title: `${tname} not detected on ${HOSTS[i % 12][0]}`,
      severity: SEV[i % SEV.length], status: ['open', 'open', 'in_progress', 'verified'][i % 4], runId: `run-${(i % 16) + 1}`,
      agentId: `a-${(i % 12) + 1}`, hostname: HOSTS[i % 12][0], createdAt: iso(60 + i * 340), updatedAt: iso(30 + i * 200),
      firstSeen: iso(60 + i * 340), lastSeen: iso(30 + i * 200), enrichment: {},
    };
  });
}

export function richCampaigns() {
  const base = smoke('GET', new URL('http://x/api/campaigns'))[0];
  return [
    { ...base, id: 'c-1', name: 'Q4 ransomware readiness', status: 'running' },
    { ...base, id: 'c-2', name: 'Domain controller hardening check', status: 'completed' },
    { ...base, id: 'c-3', name: 'Branch office endpoint sweep', status: 'paused' },
  ];
}

const OVERRIDES = {
  'GET /api/agents': (u) => {
    const a = richAgents();
    const n = (s) => a.filter((x) => x.status === s).length;
    return u.searchParams.has('limit')
      ? { items: a, next_cursor: '', has_more: false, totals: { online: n('online'), degraded: n('degraded'), offline: n('offline'), retired: 1 } }
      : a;
  },
  'GET /api/agents/legacy-migration-status': { daysClean: 30, daysRequired: 30, eligible: true, blockingAgents: [], unattributedRequests: null },
  'GET /api/scenarios/runs': () => richRuns(),
  'GET /api/findings': () => richFindings(),
  'GET /api/campaigns': () => richCampaigns(),
  'GET /api/auth/me': { username: 'asha.nair', role: 'admin' },
};

Object.assign(OVERRIDES, demoA, demoB, demoC, demoG1, demoG2, demoG3, demoG4, demoG5, demoG6, demoG7, demoG8, demoG9, demoG10, demoG11, demoG12, demoG13, demoG14, demoG17, demoG15, demoG16);
Object.assign(OVERRIDES, demoG20);
Object.assign(OVERRIDES, demoG21);
Object.assign(OVERRIDES, demoG24);
Object.assign(OVERRIDES, demoG22);
Object.assign(OVERRIDES, demoG23);
Object.assign(OVERRIDES, demoG25);
Object.assign(OVERRIDES, demoG26);
Object.assign(OVERRIDES, demoG27);
Object.assign(OVERRIDES, demoG19);
Object.assign(OVERRIDES, demoG18);
Object.assign(OVERRIDES, demoG28);
Object.assign(OVERRIDES, demoG29);
Object.assign(OVERRIDES, demoG30);
Object.assign(OVERRIDES, demoG31);

const ALWAYS = new Set(['GET /ready', 'GET /api/license/status', 'GET /api/auth/me', 'GET /api/license']);

export function fixtureSet(name) {
  if (name === 'smoke') return (m, u) => smoke(m, u);
  if (name === 'rich') {
    return (m, u) => {
      const key = `${m} ${u.pathname}`;
      const o = OVERRIDES[key];
      if (o !== undefined) return typeof o === 'function' ? o(u) : o;
      return smoke(m, u);
    };
  }
  if (name === 'empty') {
    return (m, u) => {
      const key = `${m} ${u.pathname}`;
      if (ALWAYS.has(key)) return smoke(m, u);
      if (m !== 'GET') return smoke(m, u);
      return [];
    };
  }
  if (name === 'error') return null; // handled by the capture script: HTTP 500
  throw new Error(`unknown fixture set: ${name}`);
}
