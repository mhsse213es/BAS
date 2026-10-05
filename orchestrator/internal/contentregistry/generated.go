package contentregistry

// SourceRef names one intelligence entity a generated version derives from.
// EntityType: actor|campaign|malware|tool|technique_evidence. Role: primary|supporting.
type SourceRef struct {
	EntityType string
	EntityID   string
	Provider   string
	ExternalID string
	Role       string
}
