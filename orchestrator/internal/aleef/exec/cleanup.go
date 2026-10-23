package exec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/runner"
)

// ErrCleanupFailed is wrapped by every cleanup failure. Its text is the
// runner's reason code, runner.ReasonCleanupFailed.
var ErrCleanupFailed = errors.New(runner.ReasonCleanupFailed)

// CompensatingReset implements runner.Resetter. It undoes only objects it
// knows it created, by calling each object's Compensate operation as the
// owning account, and never touches anything else.
//
// Reset (called by the runner before and after each sandbox scenario)
// compensates the objects registered with Track during runs. The fixture
// objects in Created are the shared starting state of every test, so Reset
// leaves them alone; Cleanup compensates them (and any tracked objects) at
// the end of a campaign.
type CompensatingReset struct {
	base    string
	fx      fixture.Fixture
	secrets runner.SecretResolver
	doer    model.Doer
	m       model.Model

	mu      sync.Mutex
	created []model.CreatedObject // fixture objects, compensated by Cleanup
	tracked []model.CreatedObject // run-created objects, compensated by Reset
	orphans []model.CreatedObject
}

func newCompensatingReset(cfg Config, doer model.Doer) *CompensatingReset {
	return &CompensatingReset{
		base: strings.TrimRight(cfg.BaseURL, "/"), fx: cfg.Fixture, secrets: cfg.Secrets, doer: doer, m: cfg.Model,
		created: append([]model.CreatedObject(nil), cfg.Created...),
	}
}

// Track registers an object created during a run for compensation by Reset.
func (c *CompensatingReset) Track(o model.CreatedObject) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tracked = append(c.tracked, o)
}

// Orphans lists objects whose compensation failed or that had no Compensate
// operation. An object leaves the list once a later attempt succeeds.
func (c *CompensatingReset) Orphans() []model.CreatedObject {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]model.CreatedObject(nil), c.orphans...)
}

// Reset implements runner.Resetter for tracked (run-created) objects.
func (c *CompensatingReset) Reset(ctx context.Context) error {
	return c.run(ctx, false)
}

// Cleanup compensates the Created fixture objects and any tracked objects.
func (c *CompensatingReset) Cleanup(ctx context.Context) error {
	return c.run(ctx, true)
}

func (c *CompensatingReset) run(ctx context.Context, includeCreated bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	failed := 0
	process := func(list []model.CreatedObject) []model.CreatedObject {
		var keep []model.CreatedObject
		for _, o := range list {
			if err := c.compensate(ctx, o); err != nil {
				failed++
				keep = append(keep, o)
				c.addOrphan(o)
				continue
			}
			c.dropOrphan(o)
		}
		return keep
	}
	c.tracked = process(c.tracked)
	if includeCreated {
		c.created = process(c.created)
	}
	if failed > 0 {
		return fmt.Errorf("%w: %d object(s) not compensated", ErrCleanupFailed, failed)
	}
	return nil
}

func sameObj(a, b model.CreatedObject) bool { return a.ID == b.ID && a.Operation == b.Operation }

func (c *CompensatingReset) addOrphan(o model.CreatedObject) {
	for _, e := range c.orphans {
		if sameObj(e, o) {
			return
		}
	}
	c.orphans = append(c.orphans, o)
}

func (c *CompensatingReset) dropOrphan(o model.CreatedObject) {
	var out []model.CreatedObject
	for _, e := range c.orphans {
		if !sameObj(e, o) {
			out = append(out, e)
		}
	}
	c.orphans = out
}

// compensate undoes one object. 404 and 410 count as success, so compensating
// twice is harmless.
func (c *CompensatingReset) compensate(ctx context.Context, o model.CreatedObject) error {
	if o.Compensate == "" {
		return errors.New("no compensating operation")
	}
	op, ok := opByID(c.m, o.Compensate)
	if !ok {
		return errors.New("compensating operation not in model")
	}
	path, ok := fillPath(op, o.ID)
	if !ok {
		return errors.New("compensating operation needs exactly one path parameter")
	}
	tok, err := tokenForOwner(c.fx, c.secrets, o.Owner)
	if err != nil {
		return err
	}
	status, _, err := call(ctx, c.doer, op.Method, c.base+path, tok)
	if err != nil {
		return err
	}
	if (status >= 200 && status <= 299) || status == http.StatusNotFound || status == http.StatusGone {
		return nil
	}
	return fmt.Errorf("compensation returned status %d", status)
}
