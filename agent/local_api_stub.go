//go:build !windows

package main

// Stubs so the Agent struct compiles on non-Windows platforms.
// The local HTTP status API is Windows-only.

type LocalAgentState struct{}
type LocalEvidenceStats struct{ EventsCollected, DefenderAlerts, SysmonDetections int }
type LocalOperation struct{}
type LocalActivity struct{}

func newLocalAgentState() *LocalAgentState                                            { return &LocalAgentState{} }
func (s *LocalAgentState) SetConnected(_ bool)                                        {}
func (s *LocalAgentState) StartOperation(_, _, _ string, _ int)                       {}
func (s *LocalAgentState) UpdateProgress(_, _ int, _ string)                          {}
func (s *LocalAgentState) CompleteOperation(_ string, _ LocalEvidenceStats)           {}
func (s *LocalAgentState) RecordActivity(_ string)                                    {}
