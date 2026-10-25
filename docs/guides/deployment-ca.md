# Deployment CA

Every Audspect installation has its **own** certificate authority. It issues the client certificates agents use
to talk to that server (mTLS), and it is also the server's TLS identity for agent connections. Two installations
never share a CA, so a compromise of one server cannot be used against another.

## How it behaves

| Situation | What happens |
|---|---|
| Fresh install | A dedicated CA is generated (`PKI_DIR`, default under the data directory): `ca-key.pem` (mode 0600) and `ca-cert.pem`. |
| Restart or upgrade | The existing CA is loaded and reused. The upgrade backup includes it. |
| Certificates in `/etc/ssl/certs` or the operating system trust store | Ignored. They are a list of roots to trust, not a CA that can sign, and are never used for signing. |
| Only one of the two files is present | **Refuses to start.** Nothing is overwritten and no replacement is generated. Restore both files from backup. |
| Key and certificate do not belong together, the certificate is not a CA, cannot sign, is expired, or is not yet valid | **Refuses to start** with the reason (a wrong clock shows as "not yet valid"). |
| Key file readable by other users (for example after a restore) | Restricted to 0600 and logged. |
| CA expires in under 180 days | A warning is logged at every start. Expiry locks out every agent, so plan the replacement early. |
| Files missing but agents are already enrolled | **Refuses to start.** A new CA would invalidate every enrolled agent. |
| Deliberate replacement | Set `BAS_CONFIRM_NEW_CA=true` after removing both files. Every enrolled agent must then re-enroll. |

## Backup and restore

Back up `ca-key.pem` and `ca-cert.pem` together, somewhere only administrators can read. Losing the key means
re-enrolling the whole fleet. Restoring means copying both files back into `PKI_DIR` before starting the server;
a restored pair is loaded as the same CA (covered by a test).

### Ownership after a restore

The server runs as the unprivileged user `65532` and `install.sh` makes the PKI directory owned by it. If you
restore the files as root they will be owned by root, and a key with mode 0600 is then unreadable to the
server. After restoring, run `chown 65532:65532 <PKI_DIR>/ca-key.pem <PKI_DIR>/ca-cert.pem`. The server only
tightens a key it can already read, so tightening never takes access away from the service; the failure to
watch for is a restore that leaves the files owned by someone else.

### `BAS_CONFIRM_NEW_CA`

Set it only for a deliberate replacement, and **remove it again straight afterwards**. Left set, a CA that is
later lost on a running deployment would be replaced instead of stopping the server. It is only consulted when the
CA key is missing and agents are already enrolled, and even then a surviving `ca-cert.pem` is never overwritten:
remove both files first.

## Using a company (enterprise) CA

Not supported yet, deliberately. Placing an arbitrary certificate in `PKI_DIR` is not a supported way to do it,
and importing a CA *certificate* alone would not work: the server must be able to sign, so it needs either the
private key or an approved signing service.

When a deployment needs it, the plan is a **subordinate CA** issued to Audspect by the customer's root, never the
root key itself, selected by an explicit setting and validated as strictly as above, with no fallback to a
generated CA. Keeping the subordinate key in an HSM or signing service is the stronger option.
