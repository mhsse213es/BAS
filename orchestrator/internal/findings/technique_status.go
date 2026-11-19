package findings

// CheckTechniques maps a technique ID to the remediation checks that directly prevent
// its behaviour. A check belongs here only when it prevents that behaviour, not when
// it merely reduces exposure or protects data. The approved mapping for the current
// catalog is empty: windows-smbv1-disabled, windows-firewall-enabled and
// windows-bitlocker-enabled each have no technique mapping.
var CheckTechniques = map[string][]string{}

// TechniqueRemediationStatus derives a technique's remediation status from its mapped
// checks only. It returns ok=false when no mapped check has a request, so an unmapped
// or unrelated check never produces a technique status. The status of each mapped
// check is its latest request. A failed check fails the technique. Otherwise the
// technique is in progress while any check is pending or running. It is completed only
// when every mapped check completed. Completion is an execution state, not proof of
// closure; closure is verified separately.
func TechniqueRemediationStatus(mapping map[string][]string, techniqueID string, reqs []RemediationRequest) (string, bool) {
	checks := mapping[techniqueID]
	if len(checks) == 0 {
		return "", false
	}
	latest := map[string]RemediationRequest{}
	for _, r := range reqs {
		isMapped := false
		for _, c := range checks {
			if c == r.CheckID {
				isMapped = true
				break
			}
		}
		if !isMapped {
			continue
		}
		if cur, ok := latest[r.CheckID]; !ok || r.RequestedAt.After(cur.RequestedAt) {
			latest[r.CheckID] = r
		}
	}
	if len(latest) == 0 {
		return "", false
	}
	anyOpen, allDone := false, len(latest) == len(checks)
	for _, c := range checks {
		r, ok := latest[c]
		if !ok {
			allDone = false
			continue
		}
		switch MapRequestStatus(r.Status) {
		case RequestFailed:
			return RequestFailed, true
		case RequestPending, RequestInProgress:
			anyOpen = true
			allDone = false
		case RequestCompleted:
		default:
			allDone = false
		}
	}
	switch {
	case anyOpen:
		return RequestInProgress, true
	case allDone:
		return RequestCompleted, true
	}
	return RequestUnknown, true
}
