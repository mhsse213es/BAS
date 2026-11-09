// The Deploy Agent page's command for the .deb package, derived from its Linux script command so both carry the
// same CA and server values. The package is installed with apt, then audspect-agent-setup (the same installer the
// script command runs) enrols the host.

var SHAPE = /^(.*?) && curl -fsSk -o install-agent-linux\.sh \S+ && sudo env (.+?) bash install-agent-linux\.sh --ca-file \.\/deployment-ca\.pem$/;

export function debCommand(linuxCmd, arch) {
  var a = arch === 'arm64' ? 'arm64' : 'amd64';
  var pkg = './bas-agent-linux-' + a + '.deb';
  var m = SHAPE.exec(linuxCmd || '');
  if (!m) return 'sudo apt install -y ' + pkg + ' && sudo audspect-agent-setup';
  return m[1] + ' && sudo apt install -y ' + pkg + ' && sudo env ' + m[2] + ' audspect-agent-setup --ca-file ./deployment-ca.pem';
}
