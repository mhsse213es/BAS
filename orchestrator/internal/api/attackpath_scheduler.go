package api

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartAttackPathScheduler runs a background goroutine that ticks every 60 s
// and fires a fleet-wide command_attackpath_collect when the singleton
// attackpath_schedule row is enabled and the configured interval has elapsed.
// Follows the same "fire-and-forget" pattern as the staleness monitor.
func StartAttackPathScheduler(ctx context.Context, pool *pgxpool.Pool, hub *ws.Hub) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runScheduledAPCollection(ctx, pool, hub)
			}
		}
	}()
	log.Println("[+] Attack-path scheduler started")
}

func runScheduledAPCollection(ctx context.Context, pool *pgxpool.Pool, hub *ws.Hub) {
	var (
		enabled         bool
		intervalMinutes int
		targetsRaw      []byte
		segment         string
		runSharpHound   bool
		lastRunAt       *time.Time
	)
	err := pool.QueryRow(ctx,
		`SELECT enabled, interval_minutes, targets, segment, run_sharphound, last_run_at
		 FROM attackpath_schedule WHERE id = 1`).
		Scan(&enabled, &intervalMinutes, &targetsRaw, &segment, &runSharpHound, &lastRunAt)
	if err != nil {
		return // row not yet created — schedule never configured
	}
	if !enabled {
		return
	}
	if intervalMinutes <= 0 {
		intervalMinutes = 1440
	}
	if lastRunAt != nil && time.Since(*lastRunAt) < time.Duration(intervalMinutes)*time.Minute {
		return
	}

	var targets []string
	_ = json.Unmarshal(targetsRaw, &targets)

	agentIDs := hub.ConnectedAgents()
	if len(agentIDs) == 0 {
		return
	}

	cmd, _ := buildCollectCmd(targets, segment, runSharpHound, "")
	dispatched := 0
	for _, id := range agentIDs {
		if hub.SendToAgent(id, models.WSMessage{
			Type:    models.MsgCommandAttackPathCollect,
			AgentID: id,
			Data:    cmd,
		}) {
			dispatched++
		}
	}
	log.Printf("[attackpath-scheduler] dispatched to %d/%d agent(s) (interval=%dm)",
		dispatched, len(agentIDs), intervalMinutes)

	pool.Exec(ctx, `UPDATE attackpath_schedule SET last_run_at = NOW() WHERE id = 1`)
}
