# Linux agent: the `.deb` package

`bas-agent-linux-amd64.deb` and `bas-agent-linux-arm64.deb` (package name `audspect-agent`) are the recommended way to
install the agent on Ubuntu and Debian. The agent still runs as root under systemd as `bas-agent.service`: the attack
simulations need it.

## Install

The Deploy Agent page shows the exact one-line command, with your CA and server values filled in:

```
<write the CA file> && sudo apt install -y ./bas-agent-linux-amd64.deb && sudo env BAS_SERVER_HOST=... audspect-agent-setup --ca-file ./deployment-ca.pem
```

`audspect-agent-setup` asks for the agent secret (and the enrolment token if the server issues them). Nothing secret is
on a command line.

**Fleet tools (Ansible, Puppet, apt mirrors).** Create `/etc/audspect-agent/enroll.env` (root, mode 0600; template in
`/usr/share/doc/audspect-agent/enroll.env.example`) before installing the package. The package then enrols the host as
it installs. The secret and token are deleted from the file once used.

## One install path

The package carries the console's own `install-agent-linux.sh` and `audspect-agent-setup` runs it, so the package, the
console's script command and a future `.run` all share the same enrolment, identity handling and service creation.

## What each operation does

| Operation | Result |
|---|---|
| install | Enrols from `enroll.env` if it has a secret; else re-installs from an earlier enrolment if one is on the host; else says how to enrol. |
| upgrade | Keeps the old binary, swaps in the new one, restarts, and requires the service to stay running (about 6 s). If it does not, the old binary is restored and `dpkg` reports the failure. Configuration, certificates and identity are never touched. |
| remove | Stops and removes the service and binary. Keeps `/etc/bas-agent`, `/etc/audspect/certs` (identity) and `/etc/audspect-agent`, so a re-install is the same agent. |
| purge | Also erases all of those and the agent's state. It does **not** tell the server: remove the endpoint in the console (Agents, Force Remove). |
| replacing the old `bas-agent` package | The old package's config is deleted by dpkg on replacement, so the new package saves it first and re-installs from it. |

## Tested

`packaging/linux-deb/test/` builds the package around a fake agent and fake `systemctl` in an Ubuntu 24.04 container and
runs the real maintainer scripts through install, enrol, upgrade, a failed upgrade (rollback), remove, re-install, purge
and replacing the old package (39 checks):

```
docker build -f packaging/linux-deb/test/Dockerfile -t audspect-deb-test . && docker run --rm audspect-deb-test
```

## Not done / not verified

- Not run on a real Ubuntu host with real systemd and the real agent. Needs one pass on a VM: enrol, upgrade to a newer
  build, remove, purge.
- Ubuntu 22.04 / 24.04 / 26.04 compatibility is only tested on 24.04 in a container.
- The package is not signed on its own. It is covered by the signed `BINARIES.sha256`, which the console serves; apt
  repository signing is a separate publishing step.
- The `.rpm` is still the old minimal package (manual config edit, no rollback). A `.run` self-extracting installer for
  non-Debian systems is not built yet; it would wrap the same `install-agent-linux.sh`.
- The package version is the build's `AGENT_VERSION` when that is a valid Debian version, otherwise 1.6.0 (the old
  fixed value). Check the version your build passes.
