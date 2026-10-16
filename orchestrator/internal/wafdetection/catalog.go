package wafdetection

import (
	"fmt"
	"time"
)

// AudspectWAFDetectionCatalog returns Audspect's real, current seed
// detection/telemetry-validation scenario set: one scenario per named
// item from waf.txt Phase 8, split across the three evaluation shapes.
func AudspectWAFDetectionCatalog() (completeness []CompletenessScenario, alert []AlertScenario, timing []TimingScenario, err error) {
	s1, err := NewCompletenessScenario("WAFDETECT-001", ChannelWAFEventLog,
		"a test execution's CorrelationKey must resolve to a findable WAF-engine event-log record",
		"manually authored from waf.txt Phase 8's named WAF-events item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed detection catalog: %w", err)
	}

	s2, err := NewCompletenessScenario("WAFDETECT-002", ChannelSIEMRecord,
		"the same correlation key must resolve to a findable SIEM-ingested record, an independent corroborating source",
		"manually authored from waf.txt Phase 8's named SIEM-records item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed detection catalog: %w", err)
	}

	s5, err := NewCompletenessScenario("WAFDETECT-005", ChannelEvidenceArchive,
		"evidence already confirmed present at collection time must still be retrievable from long-term archival storage, not lost to log rotation or a retention-policy gap",
		"manually authored from waf.txt Phase 8's named evidence-loss item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed detection catalog: %w", err)
	}

	s3, err := NewAlertScenario("WAFDETECT-003",
		"a blocked or detected-but-allowed request must produce a queryable alert; an allowed-and-undetected request must not spuriously produce one",
		"manually authored from waf.txt Phase 8's named alerts item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed detection catalog: %w", err)
	}

	s4, err := NewTimingScenario("WAFDETECT-004", 5*time.Minute,
		"an alert must surface within 5 minutes of the triggering event, a representative SOC response-time target",
		"manually authored from waf.txt Phase 8's named response-timing item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed detection catalog: %w", err)
	}

	return []CompletenessScenario{s1, s2, s5}, []AlertScenario{s3}, []TimingScenario{s4}, nil
}
