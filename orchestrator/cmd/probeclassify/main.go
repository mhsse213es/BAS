package main

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/audspect/bas/internal/scenario"
)

func main() {
	dir, _ := filepath.Abs(".")
	dir = filepath.Join(dir, "..", "scenarios")
	e := scenario.NewEngine(dir)
	if err := e.Load(); err != nil {
		fmt.Println("load error:", err)
		return
	}

	type key struct{ tid, ak string }
	total := 0
	unclassified := map[key]int{}
	unclassifiedFiles := map[key]map[string]bool{}
	classified := 0

	for _, sc := range e.List() {
		for _, step := range sc.Steps {
			if step.Framework != "" && step.Framework != "custom" {
				continue
			}
			total++
			c := scenario.ResolveExecutionClass(step.TechniqueID, step.ActionKey)
			if c.DestructiveAction == "unclassified" {
				k := key{step.TechniqueID, step.ActionKey}
				unclassified[k]++
				if unclassifiedFiles[k] == nil {
					unclassifiedFiles[k] = map[string]bool{}
				}
				unclassifiedFiles[k][sc.ID] = true
			} else {
				classified++
			}
		}
	}
	fmt.Println("total custom/hand-authored steps:", total)
	fmt.Println("classified:", classified)
	fmt.Println("unclassified (technique_id, action_key) pairs:", len(unclassified))
	keys := make([]key, 0, len(unclassified))
	for k := range unclassified {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].tid != keys[j].tid {
			return keys[i].tid < keys[j].tid
		}
		return keys[i].ak < keys[j].ak
	})
	for _, k := range keys {
		fmt.Printf("  %-14s action_key=%-25q count=%d\n", k.tid, k.ak, unclassified[k])
	}

	fmt.Println("\n\n=== PER-TECHNIQUE FULL DETAIL (deduped by first 60 chars of command) ===")
	byTech := map[string][]struct {
		scID, name, cmd, cleanup string
	}{}
	for _, sc := range e.List() {
		for _, step := range sc.Steps {
			if step.Framework != "" && step.Framework != "custom" {
				continue
			}
			c := scenario.ResolveExecutionClass(step.TechniqueID, step.ActionKey)
			if c.DestructiveAction != "unclassified" {
				continue
			}
			byTech[step.TechniqueID] = append(byTech[step.TechniqueID], struct {
				scID, name, cmd, cleanup string
			}{sc.ID, step.Name, step.Command, step.Cleanup})
		}
	}
	techKeys := make([]string, 0, len(byTech))
	for k := range byTech {
		techKeys = append(techKeys, k)
	}
	sort.Strings(techKeys)
	for _, tid := range techKeys {
		fmt.Printf("\n\n########## %s (%d steps) ##########\n", tid, len(byTech[tid]))
		seen := map[string]bool{}
		for _, s := range byTech[tid] {
			dedupeKey := s.cmd
			if len(dedupeKey) > 80 {
				dedupeKey = dedupeKey[:80]
			}
			if seen[dedupeKey] {
				fmt.Printf("--- %s | %s (DUPLICATE PATTERN, skipped) ---\n", s.scID, s.name)
				continue
			}
			seen[dedupeKey] = true
			fmt.Printf("--- %s | %s ---\ncmd:\n%s\ncleanup:\n%s\n\n", s.scID, s.name, s.cmd, s.cleanup)
		}
	}
}
