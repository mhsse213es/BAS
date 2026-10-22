import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { buildAgentInstallCommands } = await load(['buildAgentInstallCommands']);

const PEM = '-----BEGIN CERTIFICATE-----\nFAKEFAKEFAKE\n-----END CERTIFICATE-----';
const B64 = Buffer.from(PEM).toString('base64');

test('defaults to mTLS 9443 and enroll 9444 when the server advertises nothing', () => {
  const c = buildAgentInstallCommands('https://10.0.0.5:9543', '10.0.0.5', {});
  assert.equal(c.serverURL, 'https://10.0.0.5:9443');
  for (const cmd of [c.windows, c.mac]) {
    assert.match(cmd, /--server https:\/\/10\.0\.0\.5:9443\b/);
    assert.match(cmd, /--enroll-port 9444\b/);
  }
  assert.match(c.linux, /BAS_SERVER_HOST=10\.0\.0\.5 BAS_ENROLL_PORT=9444 BAS_MTLS_PORT=9443 BAS_DASHBOARD_PORT=9543/);
});

test('uses advertised host ports so a port-remapped deployment installs with no manual edits', () => {
  const c = buildAgentInstallCommands('https://192.168.10.78:9543', '192.168.10.78', { mtlsPort: '9443', enrollPort: '9445' });
  assert.equal(c.serverURL, 'https://192.168.10.78:9443');
  for (const cmd of [c.windows, c.mac]) {
    assert.match(cmd, /--server https:\/\/192\.168\.10\.78:9443\b/);
    assert.match(cmd, /--enroll-port 9445\b/);
  }
  assert.match(c.linux, /BAS_SERVER_HOST=192\.168\.10\.78 BAS_ENROLL_PORT=9445 BAS_MTLS_PORT=9443 BAS_DASHBOARD_PORT=9543/);
});

test('linux downloads the installer from the dashboard and runs it with the server details filled in', () => {
  const c = buildAgentInstallCommands('https://192.168.10.78:9543', '192.168.10.78', { mtlsPort: '9443', enrollPort: '9445' });
  assert.match(c.linux, /&& curl -fsSk -o install-agent-linux\.sh https:\/\/192\.168\.10\.78:9543\/api\/agent\/install-script && sudo env BAS_SERVER_HOST=192\.168\.10\.78 .* bash install-agent-linux\.sh --ca-file \.\/deployment-ca\.pem$/);
  assert.doesNotMatch(c.linux, /bas-agent-linux-\*/);
});

test('falls back to fetching the CA root over an unverified connection when caRootPem is unavailable', () => {
  const c = buildAgentInstallCommands('https://192.168.10.78:9543', '192.168.10.78', { mtlsPort: '9443', enrollPort: '9445' });
  assert.match(c.linux, /^curl -fsSk -o deployment-ca\.pem https:\/\/192\.168\.10\.78:9543\/api\/config\/ca-root &&/);
  assert.match(c.mac, /^curl -fsSk -o deployment-ca\.pem https:\/\/192\.168\.10\.78:9543\/api\/config\/ca-root &&/);
  assert.match(c.windows, /^curl\.exe -fsSk -o deployment-ca\.pem https:\/\/192\.168\.10\.78:9543\/api\/config\/ca-root; /);
  for (const cmd of [c.windows, c.mac, c.linux]) assert.match(cmd, /--ca-(root|file) /);
});

test('writes an already-available caRootPem into the command instead of fetching it again', () => {
  const c = buildAgentInstallCommands('https://192.168.10.78:9543', '192.168.10.78', {
    mtlsPort: '9443', enrollPort: '9445', caRootPem: PEM,
  });
  // Must never fetch the CA root from serverURL at all once it's already
  // in hand -- a serverURL that got redirected to a rogue host can no
  // longer hand back its own CA to be trusted.
  for (const cmd of [c.windows, c.linux, c.mac]) {
    assert.doesNotMatch(cmd, /curl.*ca-root/);
    assert.doesNotMatch(cmd, /\/api\/config\/ca-root/);
    assert.ok(cmd.includes(B64), 'command should embed the CA as base64');
  }
  assert.match(c.linux, /^echo [A-Za-z0-9+/=]+ \| base64 -d > deployment-ca\.pem && /);
  assert.match(c.mac, /^echo [A-Za-z0-9+/=]+ \| openssl base64 -d -A > deployment-ca\.pem && /);
  assert.match(c.windows, /^\[IO\.File\]::WriteAllBytes\('deployment-ca\.pem', \[Convert\]::FromBase64String\('[A-Za-z0-9+/=]+'\)\); /);
});

test('the CA is written before the agent installer runs, on every OS', () => {
  const c = buildAgentInstallCommands('https://h:9543', 'h', { caRootPem: PEM });
  assert.ok(c.linux.indexOf(B64) < c.linux.indexOf('bash install-agent-linux.sh'));
  assert.ok(c.mac.indexOf(B64) < c.mac.indexOf('--install'));
  assert.ok(c.windows.indexOf(B64) < c.windows.indexOf('--install'));
});

test('every OS command is a single line, with or without an embedded CA', () => {
  for (const data of [{}, { caRootPem: PEM }]) {
    const c = buildAgentInstallCommands('https://h:9543', 'h', data);
    for (const cmd of [c.windows, c.linux, c.mac]) {
      assert.doesNotMatch(cmd, /\n/);
      assert.doesNotMatch(cmd, /<</);
      assert.doesNotMatch(cmd, /@'/);
    }
  }
});

test('mac command strips the browser quarantine flag before chmod/install, since Gatekeeper blocks an unsigned binary otherwise', () => {
  const c = buildAgentInstallCommands('https://h:9543', 'h');
  assert.match(c.mac, /xattr -d com\.apple\.quarantine bas-agent-darwin-\* &&/);
  // The quarantine strip must run before chmod/the install itself, or the
  // binary is still blocked when it's invoked.
  assert.ok(c.mac.indexOf('xattr -d com.apple.quarantine') < c.mac.indexOf('chmod +x'));
});

test('install commands never contain the secret, since the installer asks for it interactively', () => {
  const c = buildAgentInstallCommands('https://h:9543', 'h');
  for (const cmd of [c.windows, c.linux, c.mac]) {
    assert.doesNotMatch(cmd, /--secret\b/);
  }
});

test('treats missing arguments defensively without throwing', () => {
  const c = buildAgentInstallCommands('https://h:9543', 'h');
  assert.equal(c.serverURL, 'https://h:9443');
  assert.match(c.linux, /BAS_ENROLL_PORT=9444 /);
});
