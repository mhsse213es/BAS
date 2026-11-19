import test from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/deb-command.js';

// The console's .deb command must carry the same pinned CA and server values as its script command, and must not
// tell the operator to hand-edit a config file or to start the service themselves.
const LINUX = 'echo Q0E= | base64 -d > deployment-ca.pem && curl -fsSk -o install-agent-linux.sh https://10.0.0.5:9543/api/agent/install-script'
  + ' && sudo env BAS_SERVER_HOST=10.0.0.5 BAS_ENROLL_PORT=9445 BAS_MTLS_PORT=9443 BAS_DASHBOARD_PORT=9543 bash install-agent-linux.sh --ca-file ./deployment-ca.pem';

test('debCommand reuses the CA step and server values of the script command', () => {
  const c = M.debCommand(LINUX, 'amd64');
  assert.equal(c, 'echo Q0E= | base64 -d > deployment-ca.pem && sudo apt install -y ./bas-agent-linux-amd64.deb'
    + ' && sudo env BAS_SERVER_HOST=10.0.0.5 BAS_ENROLL_PORT=9445 BAS_MTLS_PORT=9443 BAS_DASHBOARD_PORT=9543 audspect-agent-setup --ca-file ./deployment-ca.pem');
});

test('debCommand follows the chosen architecture', () => {
  assert.match(M.debCommand(LINUX, 'arm64'), /\.\/bas-agent-linux-arm64\.deb/);
});

test('debCommand falls back to a plain command when the script command is not in the expected shape', () => {
  assert.equal(M.debCommand('', 'amd64'), 'sudo apt install -y ./bas-agent-linux-amd64.deb && sudo audspect-agent-setup');
  assert.equal(M.debCommand('something else', 'arm64'), 'sudo apt install -y ./bas-agent-linux-arm64.deb && sudo audspect-agent-setup');
});

test('debCommand ignores an architecture it does not ship', () => {
  assert.match(M.debCommand(LINUX, 'x"; rm -rf /'), /bas-agent-linux-amd64\.deb/);
});
