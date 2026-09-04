package main

// Vocabulary shared by every platform's security-control inventory.
//
// Untagged on purpose. A per-OS copy of these constants is how the platforms
// would drift into reporting the same kind of product under different labels,
// and the server would have no way to tell that had happened.

// productKind is the report prefix, and the reason the widest inventory stays
// honest: a preventive control and a log shipper must not read alike.
type productKind string

const (
	kindEDR       productKind = "EDR"
	kindTelemetry productKind = "Telemetry"
)
