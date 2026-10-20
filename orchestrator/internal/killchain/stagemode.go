package killchain

// Stage modes. An empty mode is posture.
const (
	ModePosture   = "posture"
	ModeTelemetry = "telemetry"
	ModeLab       = "lab"
)

// EffectiveMode returns the stage's mode, with an unset mode read as posture.
func (s StageDef) EffectiveMode() string {
	if s.Mode == "" {
		return ModePosture
	}
	return s.Mode
}

// LiveAndLabStages lists, in definition order, the stages that run live, and the subset
// that runs in lab mode. Approval of live stages is checked against these lists.
func (c CampaignDef) LiveAndLabStages() (live []string, lab []string) {
	for _, st := range c.Stages {
		switch st.EffectiveMode() {
		case ModeTelemetry:
			live = append(live, st.Key)
		case ModeLab:
			live = append(live, st.Key)
			lab = append(lab, st.Key)
		}
	}
	return live, lab
}
