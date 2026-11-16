package jobs

import (
	"context"
	"log"
	"sync"
	"time"
)

type blackoutLister interface {
	ListBlackouts(ctx context.Context) ([]Blackout, error)
}

// HoldForFreeze reports whether an automatic starter must wait. It is the one check every timer-driven starter shares
// with the scheduled-assessment spawner, so a change-freeze window holds all of them and not only one.
//
// A starter that is held starts nothing this tick and asks again on its next one, so its work starts once the window
// ends. Scheduled assessments differ on purpose: they are skipped (see Blackout). If the windows cannot be read the
// answer is "hold": a freeze must not be breached by a read error. A nil store holds nothing, since there is nothing
// to enforce yet. what names the starter in the log.
func HoldForFreeze(ctx context.Context, s *Store, what string, now time.Time) bool {
	if s == nil {
		return false
	}
	return holdForFreeze(ctx, s, what, now)
}

// A held starter asks again every tick, which for some is every minute, so the log line is rate limited per starter and
// reason rather than repeated for the length of a window.
const freezeLogEvery = 15 * time.Minute

var (
	freezeLogMu   sync.Mutex
	freezeLogLast = map[string]time.Time{}
)

func logFreezeHold(key, format string, args ...any) {
	freezeLogMu.Lock()
	last, seen := freezeLogLast[key]
	due := !seen || time.Since(last) >= freezeLogEvery
	if due {
		freezeLogLast[key] = time.Now()
	}
	freezeLogMu.Unlock()
	if due {
		log.Printf(format, args...)
	}
}

func holdForFreeze(ctx context.Context, l blackoutLister, what string, now time.Time) bool {
	if l == nil {
		return false
	}
	windows, err := l.ListBlackouts(ctx)
	if err != nil {
		logFreezeHold(what+"|unreadable", "[freeze] %s held: change-freeze windows unreadable: %v", what, err)
		return true
	}
	if w, held := CoveringBlackout(windows, now); held {
		logFreezeHold(what+"|"+w.ID+w.Name, "[freeze] %s held: inside change-freeze window %q", what, w.Name)
		return true
	}
	return false
}
