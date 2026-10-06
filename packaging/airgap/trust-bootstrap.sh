# shellcheck shell=bash
H=$(mktemp -d); gpg --homedir "$H" --import oob.asc && gpg --homedir "$H" --status-fd 1 --verify bundle.tar.gz.asc bundle.tar.gz
# The VALIDSIG fingerprint printed above must equal the one Audspect publishes. Then:
rm -rf "$H"
