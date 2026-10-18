import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { buildAgentInstallCommands } = await load(['buildAgentInstallCommands']);

test('defaults to mTLS 9443 and enroll 9444 when the server advertises nothing', () => {
  const c = buildAgentInstallCommands('https://10.0.0.5:9543', '10.0.0.5', {});
  assert.equal(c.serverURL, 'https://10.0.0.5:9443');
  for (const cmd of [c.windows, c.linux, c.mac]) {
    assert.match(cmd, /--server https:\/\/10\.0\.0\.5:9443\b/);
    assert.match(cmd, /--enroll-port 9444\b/);
  }
});

test('uses advertised host ports so a port-remapped deployment installs with no manual edits', () => {
  const c = buildAgentInstallCommands('https://192.168.10.78:9543', '192.168.10.78', { mtlsPort: '9443', enrollPort: '9445' });
  assert.equal(c.serverURL, 'https://192.168.10.78:9443');
  for (const cmd of [c.windows, c.linux, c.mac]) {
    assert.match(cmd, /--server https:\/\/192\.168\.10\.78:9443\b/);
    assert.match(cmd, /--enroll-port 9445\b/);
  }
});

test('falls back to fetching the CA root over an unverified connection when caRootPem is unavailable', () => {
  const c = buildAgentInstallCommands('https://192.168.10.78:9543', '192.168.10.78', { mtlsPort: '9443', enrollPort: '9445' });
  assert.match(c.linux, /curl -fsSk -o deployment-ca\.pem https:\/\/192\.168\.10\.78:9543\/api\/config\/ca-root/);
  assert.match(c.mac, /curl -fsSk -o deployment-ca\.pem https:\/\/192\.168\.10\.78:9543\/api\/config\/ca-root/);
  assert.match(c.windows, /curl\.exe -fsSk -o deployment-ca\.pem https:\/\/192\.168\.10\.78:9543\/api\/config\/ca-root/);
  for (const cmd of [c.windows, c.linux, c.mac]) assert.match(cmd, /--ca-root /);
});

test('writes an already-available caRootPem directly into the command instead of fetching it again', () => {
  const pem = '-----BEGIN CERTIFICATE-----\nFAKEFAKEFAKE\n-----END CERTIFICATE-----';
  const c = buildAgentInstallCommands('https://192.168.10.78:9543', '192.168.10.78', {
    mtlsPort: '9443', enrollPort: '9445', caRootPem: pem,
  });
  // Must never fetch the CA root from serverURL at all once it's already
  // in hand -- a serverURL that got redirected to a rogue host can no
  // longer hand back its own CA to be trusted.
  for (const cmd of [c.windows, c.linux, c.mac]) {
    assert.doesNotMatch(cmd, /curl.*ca-root/);
    assert.doesNotMatch(cmd, /\/api\/config\/ca-root/);
    assert.ok(cmd.includes(pem), 'command should embed the CA PEM bytes directly');
    assert.match(cmd, /--ca-root /);
  }
  assert.match(c.linux, /cat > deployment-ca\.pem <<'BASCAEOF'/);
  assert.match(c.mac, /cat > deployment-ca\.pem <<'BASCAEOF'/);
  assert.match(c.windows, /@'[\s\S]*'@ \| Out-File -Encoding ascii deployment-ca\.pem/);
});

test('embedded CA PEM is written before the agent binary runs, on both bash and PowerShell', () => {
  const pem = '-----BEGIN CERTIFICATE-----\nFAKEFAKEFAKE\n-----END CERTIFICATE-----';
  const c = buildAgentInstallCommands('https://h:9543', 'h', { caRootPem: pem });
  assert.ok(c.linux.indexOf(pem) < c.linux.indexOf('--install'));
  assert.ok(c.mac.indexOf(pem) < c.mac.indexOf('--install'));
  assert.ok(c.windows.indexOf(pem) < c.windows.indexOf('--install'));
});

test('mac command strips the browser quarantine flag before chmod/install, since Gatekeeper blocks an unsigned binary otherwise', () => {
  const c = buildAgentInstallCommands('https://h:9543', 'h');
  assert.match(c.mac, /xattr -d com\.apple\.quarantine bas-agent-darwin-\* &&/);
  // The quarantine strip must run before chmod/the install itself, or the
  // binary is still blocked when it's invoked.
  assert.ok(c.mac.indexOf('xattr -d com.apple.quarantine') < c.mac.indexOf('chmod +x'));
});

test('install commands omit --secret entirely, since the agent now prompts for it interactively', () => {
  const c = buildAgentInstallCommands('https://h:9543', 'h');
  for (const cmd of [c.windows, c.linux, c.mac]) {
    assert.doesNotMatch(cmd, /--secret\b/);
  }
});

test('treats missing arguments defensively without throwing', () => {
  const c = buildAgentInstallCommands('https://h:9543', 'h');
  assert.equal(c.serverURL, 'https://h:9443');
  assert.match(c.linux, /--enroll-port 9444\b/);
});
