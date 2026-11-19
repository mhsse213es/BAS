package tcv

// UnclassifiedReason marks a rejection recorded before exclusion codes existed.
// It is counted as its own exclusion bucket, never dropped (spec section 4).
const UnclassifiedReason = "unclassified"

// LifecyclePayload is the payload for a lifecycle-derived ledger event. A
// REJECTED event carries its exclusion reason. A REJECTED row with no code is
// a legacy rejection and is marked unclassified, not left blank.
func LifecyclePayload(toLifecycle, reasonCode string) map[string]any {
	p := map[string]any{"to_lifecycle": toLifecycle}
	if toLifecycle == "REJECTED" {
		if reasonCode == "" {
			reasonCode = UnclassifiedReason
		}
		p["reason_code"] = reasonCode
	}
	return p
}
