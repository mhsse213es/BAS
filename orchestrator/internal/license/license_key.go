package license

// PublicKeyPEM is the Audspect RSA-4096 public key embedded at build time.
// Run `bash packaging/licensing/keygen.sh` once to generate the real key pair.
// keygen.sh overwrites this file with the real key — do NOT edit manually.
var PublicKeyPEM = "KEYGEN_REQUIRED"
