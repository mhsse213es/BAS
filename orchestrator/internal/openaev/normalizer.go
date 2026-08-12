package openaev

// Normalize maps a ParsedBundle into Audspect's own Scenario (summary) and
// Detail (full content) types. Pure function — no I/O, no database.
func Normalize(parsed *ParsedBundle) (Scenario, Detail) {
	techniqueSet := map[string]bool{}
	platformSet := map[string]bool{}
	detailInjects := make([]DetailInject, 0, len(parsed.Injects))

	for _, inj := range parsed.Injects {
		injTechniques := make([]string, 0, len(inj.AttackPatterns))
		for _, ap := range inj.AttackPatterns {
			if ap.ExternalID == "" {
				continue
			}
			techniqueSet[ap.ExternalID] = true
			injTechniques = append(injTechniques, ap.ExternalID)
			for _, p := range ap.Platforms {
				platformSet[p] = true
			}
		}
		detailInjects = append(detailInjects, DetailInject{
			Title:        inj.Title,
			TechniqueIDs: injTechniques,
		})
	}

	techniqueIDs := make([]string, 0, len(techniqueSet))
	for id := range techniqueSet {
		techniqueIDs = append(techniqueIDs, id)
	}
	platforms := make([]string, 0, len(platformSet))
	for p := range platformSet {
		platforms = append(platforms, p)
	}

	tags := make([]string, 0, len(parsed.Tags))
	for _, t := range parsed.Tags {
		tags = append(tags, t.Name)
	}

	detailObjectives := make([]DetailObjective, 0, len(parsed.Objectives))
	for _, o := range parsed.Objectives {
		detailObjectives = append(detailObjectives, DetailObjective{Title: o.Title, Description: o.Description})
	}

	detailVariables := make([]DetailVariable, 0, len(parsed.Variables))
	for _, v := range parsed.Variables {
		detailVariables = append(detailVariables, DetailVariable{Key: v.Key, Description: v.Description})
	}

	scenario := Scenario{
		OpenAEVScenarioID: parsed.Scenario.ID,
		Name:              parsed.Scenario.Name,
		Category:          parsed.Scenario.Category,
		Severity:          parsed.Scenario.Severity,
		Platforms:         platforms,
		TechniqueIDs:      techniqueIDs,
		Tags:              tags,
		ObjectivesCount:   len(parsed.Objectives),
		InjectsCount:      len(parsed.Injects),
		SourceUpdatedAt:   parsed.Scenario.UpdatedAt,
		SourceType:        parsed.SourceType,
	}
	if scenario.SourceType == "" {
		scenario.SourceType = "scenario"
	}
	detail := Detail{
		Description: parsed.Scenario.Description,
		Objectives:  detailObjectives,
		Injects:     detailInjects,
		Variables:   detailVariables,
	}
	return scenario, detail
}
