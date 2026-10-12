package iocregistry

// knownTypes is the single source of truth for every valid Type constant
// above -- callers outside this package (e.g. internal/ingest, validating
// an externally-supplied type string before it reaches upsertIOCFull) use
// IsKnownType instead of hand-maintaining their own copy of this list.
var knownTypes = map[Type]bool{
	TypeFileHash: true, TypeFilename: true, TypeDomain: true, TypeURL: true,
	TypeIP: true, TypeRegistryKey: true, TypeMutex: true, TypeService: true,
	TypeProcess: true, TypeCommandLine: true, TypeJA3: true, TypeUserAgent: true,
	TypeEmail: true, TypeDNSRecord: true, TypeCertificate: true,
}

// IsKnownType reports whether s is one of this package's defined Type
// constants.
func IsKnownType(s string) bool {
	return knownTypes[Type(s)]
}
