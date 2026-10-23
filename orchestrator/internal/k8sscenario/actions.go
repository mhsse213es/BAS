package k8sscenario

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Action is one entry in the fixed registry. Each function is part of the action's reviewed behaviour:
// validate, plan, snapshot, apply, verify, rollback and verifyRolledBack.
type Action struct {
	ID               string
	validate         func(params map[string]string) error
	plan             func(ns string, params map[string]string) []string
	snapshot         func(ctx context.Context, c Client, req RunRequest) (any, error)
	apply            func(ctx context.Context, c Client, req RunRequest, snap any) error
	verify           func(ctx context.Context, c Client, req RunRequest, snap any) error
	rollback         func(ctx context.Context, c Client, req RunRequest, snap any) error
	verifyRolledBack func(ctx context.Context, c Client, req RunRequest, snap any) error
	// forceVerifyFail is a test hook: it makes verification fail, so the rollback path can be exercised.
	forceVerifyFail bool
	// unrevocable marks an action whose effect rollback cannot undo (a minted credential). A successful run ends
	// in StateDiscardedNotRevoked, never StateCleaned. summary describes that result for the operator.
	unrevocable bool
	summary     func(snap any) string
}

var (
	reK8sName  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?$`)
	rePodName  = regexp.MustCompile(`^bas-sbx-[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)
	reSafeText = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// registry is the only set of actions the engine can run.
var registry = map[string]*Action{
	"pod-create-unprivileged":  podAction(),
	"configmap-patch-labelled": configMapAction(),
	"sa-token-probe":           tokenProbeAction(),
}

// Registry returns the fixed action registry.
func Registry() map[string]*Action { return registry }

func onlyParams(params map[string]string, allowed ...string) error {
	if len(params) != len(allowed) {
		return errors.New("unexpected parameters")
	}
	for _, a := range allowed {
		if _, ok := params[a]; !ok {
			return fmt.Errorf("missing parameter %q", a)
		}
	}
	return nil
}

// podAction creates one unprivileged pause-image pod with no service account token, labelled for this run.
// Rollback deletes only a pod that carries this run's label.
func podAction() *Action {
	const image = "registry.k8s.io/pause:3.9"
	ref := func(ns string, params map[string]string) ObjectRef {
		return ObjectRef{Kind: "Pod", Namespace: ns, Name: params["name"]}
	}
	return &Action{
		ID: "pod-create-unprivileged",
		validate: func(params map[string]string) error {
			if err := onlyParams(params, "name"); err != nil {
				return err
			}
			if !rePodName.MatchString(params["name"]) {
				return errors.New("pod name must start with bas-sbx-")
			}
			return nil
		},
		plan: func(ns string, params map[string]string) []string {
			return []string{
				fmt.Sprintf("create pod %s/%s (image %s, no service account token, non-root, no privilege escalation)", ns, params["name"], image),
				"verify the pod exists with this run's label, then delete it and verify it is gone",
			}
		},
		snapshot: func(ctx context.Context, c Client, req RunRequest) (any, error) {
			_, exists, err := c.Get(ctx, ref(req.Namespace, req.Params))
			if err != nil {
				return nil, err
			}
			if exists {
				return nil, errors.New("pod already exists; refusing to touch an object this run did not create")
			}
			return nil, nil
		},
		apply: func(ctx context.Context, c Client, req RunRequest, _ any) error {
			return c.Create(ctx, Object{
				Ref:    ref(req.Namespace, req.Params),
				Labels: map[string]string{RunLabel: req.RunID},
				Spec: map[string]any{
					"automountServiceAccountToken": false,
					"securityContext":              map[string]any{"runAsNonRoot": true, "runAsUser": 65534},
					"containers": []any{map[string]any{
						"name":  "probe",
						"image": image,
						"securityContext": map[string]any{
							"allowPrivilegeEscalation": false,
							"readOnlyRootFilesystem":   true,
							"capabilities":             map[string]any{"drop": []any{"ALL"}},
						},
					}},
				},
			})
		},
		verify: func(ctx context.Context, c Client, req RunRequest, _ any) error {
			o, exists, err := c.Get(ctx, ref(req.Namespace, req.Params))
			if err != nil {
				return err
			}
			if !exists {
				return errors.New("pod not found after create")
			}
			if o.Labels[RunLabel] != req.RunID {
				return errors.New("pod does not carry this run's label")
			}
			if v, _ := o.Spec["automountServiceAccountToken"].(bool); v {
				return errors.New("service account token is mounted")
			}
			return nil
		},
		rollback: func(ctx context.Context, c Client, req RunRequest, _ any) error {
			o, exists, err := c.Get(ctx, ref(req.Namespace, req.Params))
			if err != nil {
				return err
			}
			if !exists {
				return nil
			}
			if o.Labels[RunLabel] != req.RunID {
				return errors.New("refusing to delete a pod this run did not create")
			}
			return c.Delete(ctx, ref(req.Namespace, req.Params))
		},
		verifyRolledBack: func(ctx context.Context, c Client, req RunRequest, _ any) error {
			_, exists, err := c.Get(ctx, ref(req.Namespace, req.Params))
			if err != nil {
				return err
			}
			if exists {
				return errors.New("pod still exists after rollback")
			}
			return nil
		},
	}
}

type cmSnap struct {
	prior string
	had   bool
}

// configMapAction patches one key of a ConfigMap that carries the sandbox fixture label. Rollback restores the
// prior value, or removes the key if it was absent, and the restore is verified.
func configMapAction() *Action {
	const key = "state"
	ref := func(ns string, params map[string]string) ObjectRef {
		return ObjectRef{Kind: "ConfigMap", Namespace: ns, Name: params["name"]}
	}
	return &Action{
		ID: "configmap-patch-labelled",
		validate: func(params map[string]string) error {
			if err := onlyParams(params, "name", "value"); err != nil {
				return err
			}
			if !reK8sName.MatchString(params["name"]) {
				return errors.New("invalid ConfigMap name")
			}
			if !reSafeText.MatchString(params["value"]) {
				return errors.New("value must be 1-64 safe characters")
			}
			return nil
		},
		plan: func(ns string, params map[string]string) []string {
			return []string{
				fmt.Sprintf("set data.%s on ConfigMap %s/%s to %q (must carry %s=true)", key, ns, params["name"], params["value"], FixtureLabel),
				"verify the value, then restore the prior value and verify the restore",
			}
		},
		snapshot: func(ctx context.Context, c Client, req RunRequest) (any, error) {
			o, exists, err := c.Get(ctx, ref(req.Namespace, req.Params))
			if err != nil {
				return nil, err
			}
			if !exists {
				return nil, errors.New("ConfigMap not found")
			}
			if o.Labels[FixtureLabel] != "true" {
				return nil, errors.New("ConfigMap is not a sandbox fixture")
			}
			prior, had := o.Data[key]
			return cmSnap{prior: prior, had: had}, nil
		},
		apply: func(ctx context.Context, c Client, req RunRequest, _ any) error {
			return c.SetData(ctx, ref(req.Namespace, req.Params), map[string]string{key: req.Params["value"]})
		},
		verify: func(ctx context.Context, c Client, req RunRequest, _ any) error {
			o, _, err := c.Get(ctx, ref(req.Namespace, req.Params))
			if err != nil {
				return err
			}
			if o.Data[key] != req.Params["value"] {
				return errors.New("value does not match the requested value")
			}
			return nil
		},
		rollback: func(ctx context.Context, c Client, req RunRequest, snap any) error {
			s := snap.(cmSnap)
			restore := map[string]string{key: s.prior}
			if !s.had {
				restore = map[string]string{key: ""} // empty means remove the key
			}
			return c.SetData(ctx, ref(req.Namespace, req.Params), restore)
		},
		verifyRolledBack: func(ctx context.Context, c Client, req RunRequest, snap any) error {
			s := snap.(cmSnap)
			o, _, err := c.Get(ctx, ref(req.Namespace, req.Params))
			if err != nil {
				return err
			}
			cur, has := o.Data[key]
			if s.had && (!has || cur != s.prior) {
				return errors.New("prior value not restored")
			}
			if !s.had && has {
				return errors.New("key that was absent is still present")
			}
			return nil
		},
	}
}

// probeServiceAccount is the throwaway ServiceAccount a probe token is minted for. It has no RBAC bindings, so a
// token for it authenticates but grants nothing. The scenario role may request tokens for this name only.
const probeServiceAccount = "bas-sbx-token-probe"

// probeTokenSeconds is the lifetime requested for the probe token.
const probeTokenSeconds = 600

// tokenSnap holds the minted credential for the verification step. The bytes are cleared on rollback.
type tokenSnap struct {
	token   []byte
	expires time.Time
}

// wipe overwrites the token bytes and drops the reference.
func (s *tokenSnap) wipe() {
	for i := range s.token {
		s.token[i] = 0
	}
	s.token = nil
}

// tokenProbeAction mints a short-lived token for the probe ServiceAccount, verifies it authenticates as that
// account, and discards it. Nothing can be revoked, so the run ends in DISCARDED_NOT_REVOKED.
func tokenProbeAction() *Action {
	return &Action{
		ID:          "sa-token-probe",
		unrevocable: true,
		validate: func(params map[string]string) error {
			if len(params) != 0 {
				return errors.New("this action takes no parameters")
			}
			return nil
		},
		plan: func(ns string, _ map[string]string) []string {
			return []string{
				"mint a " + fmt.Sprint(probeTokenSeconds) + "-second token for ServiceAccount " + ns + "/" + probeServiceAccount,
				"verify the token authenticates as system:serviceaccount:" + ns + ":" + probeServiceAccount,
				"discard the token; it stays valid until it expires and cannot be revoked",
			}
		},
		snapshot: func(context.Context, Client, RunRequest) (any, error) {
			return &tokenSnap{}, nil
		},
		apply: func(ctx context.Context, c Client, req RunRequest, snap any) error {
			s := snap.(*tokenSnap)
			iss, err := c.IssueToken(ctx, req.Namespace, probeServiceAccount, probeTokenSeconds)
			if err != nil {
				return err
			}
			s.token = iss.Token
			s.expires = iss.Expires
			return nil
		},
		verify: func(ctx context.Context, c Client, req RunRequest, snap any) error {
			s := snap.(*tokenSnap)
			if len(s.token) == 0 {
				return errors.New("no token to verify")
			}
			id, err := c.IdentityWithToken(ctx, s.token)
			if err != nil {
				return err
			}
			want := "system:serviceaccount:" + req.Namespace + ":" + probeServiceAccount
			if id != want {
				return errors.New("token authenticated as an unexpected identity")
			}
			return nil
		},
		rollback: func(_ context.Context, _ Client, _ RunRequest, snap any) error {
			snap.(*tokenSnap).wipe()
			return nil
		},
		verifyRolledBack: func(_ context.Context, _ Client, _ RunRequest, snap any) error {
			s := snap.(*tokenSnap)
			if s.token != nil {
				return errors.New("token is still held")
			}
			return nil
		},
		summary: func(snap any) string {
			s := snap.(*tokenSnap)
			return "token discarded; it remains valid until " + s.expires.UTC().Format(time.RFC3339) +
				" and cannot be revoked"
		},
	}
}
