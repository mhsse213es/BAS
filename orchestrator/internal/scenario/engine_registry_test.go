package scenario

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeRegistry struct {
	order      []string // "source:id" in intake order
	refuseIDs  map[string]bool
	errIDs     map[string]bool
	approved   map[string]string // id -> actor
	retired    map[string]string
	approveErr error
	retireErr  error
	refusals   []string // "path|reason" in NoteRefusal order
}

func newFake() *fakeRegistry {
	return &fakeRegistry{refuseIDs: map[string]bool{}, errIDs: map[string]bool{}, approved: map[string]string{}, retired: map[string]string{}}
}

func idOf(b []byte) string {
	var s Scenario
	_ = yamlUnmarshal(b, &s)
	return s.ID
}

func (f *fakeRegistry) Intake(_ context.Context, in IntakeFile) (IntakeDecision, error) {
	id := idOf(in.Artifact)
	f.order = append(f.order, in.Source+":"+id)
	if f.errIDs[id] {
		return IntakeDecision{}, errors.New("db down")
	}
	if f.refuseIDs[id] {
		return IntakeDecision{Accepted: false, Reason: "refused"}, nil
	}
	return IntakeDecision{Accepted: true}, nil
}
func (f *fakeRegistry) NoteRefusal(path, _, _, reason string) {
	f.refusals = append(f.refusals, path+"|"+reason)
}
func (f *fakeRegistry) RegisterLocalApproved(_ context.Context, id string, _ []byte, actor string) error {
	if f.approveErr != nil {
		return f.approveErr
	}
	f.approved[id] = actor
	return nil
}
func (f *fakeRegistry) RetireExecutable(_ context.Context, id, actor, _ string) error {
	if f.retireErr != nil {
		return f.retireErr
	}
	f.retired[id] = actor
	return nil
}
func (f *fakeRegistry) ResolveExecutable(_ context.Context, id string) (ExecutableVersion, error) {
	return ExecutableVersion{ContentID: id, VersionID: "v-" + id, Version: 1, Scenario: &Scenario{ID: id}}, nil
}

type devV struct{}

func (devV) Verify([]byte, []byte) (bool, error) { return false, nil }
func (devV) SigningEnabled() bool                { return false }

func write(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_IntakesBuiltinBeforeCustomBeforeIntel(t *testing.T) { // plan amendment 6 / A12 ordering
	dir := t.TempDir()
	write(t, dir, "zzz-builtin.yaml", "id: lolbin\nname: B\nlocal_check: true\n")
	write(t, dir, "custom/lolbin.yaml", "id: lolbin-c\nname: C\nlocal_check: true\n")
	write(t, dir, "intel/intel-1.yaml", "id: intel-1\nname: I\nart_techniques: [T1082]\n")
	e := NewEngine(dir)
	e.SetVerifier(devV{})
	f := newFake()
	e.AttachRegistry(f)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	want := []string{"builtin:lolbin", "custom:lolbin-c", "intel:intel-1"}
	if len(f.order) != 3 || f.order[0] != want[0] || f.order[1] != want[1] || f.order[2] != want[2] {
		t.Fatalf("intake order = %v, want %v", f.order, want)
	}
}

func TestLoad_RefusedFileNotInMap(t *testing.T) { // A12 engine half
	dir := t.TempDir()
	write(t, dir, "apt.yaml", "id: apt\nname: B\nlocal_check: true\n")
	write(t, dir, "custom/apt.yaml", "id: apt\nname: shadow\nlocal_check: true\n")
	e := NewEngine(dir)
	e.SetVerifier(devV{})
	f := newFake()
	// The second intake of "apt" (the custom one) is refused by the registry.
	calls := 0
	f2 := &countingRefuser{fakeRegistry: f, refuseAfter: 1, calls: &calls}
	e.AttachRegistry(f2)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	sc, ok := e.Get("apt")
	if !ok || sc.Name != "B" || sc.Source != "builtin" {
		t.Fatalf("builtin must keep the map slot: %+v", sc)
	}
}

type countingRefuser struct {
	*fakeRegistry
	refuseAfter int
	calls       *int
}

func (c *countingRefuser) Intake(ctx context.Context, in IntakeFile) (IntakeDecision, error) {
	*c.calls++
	if *c.calls > c.refuseAfter {
		return IntakeDecision{Accepted: false, Reason: "collision"}, nil
	}
	return c.fakeRegistry.Intake(ctx, in)
}

func TestLoad_IntakeErrorKeepsLoadingAndDoesNotExecute(t *testing.T) { // Review Focus 4
	dir := t.TempDir()
	write(t, dir, "custom/a.yaml", "id: a\nname: A\nlocal_check: true\n")
	write(t, dir, "custom/b.yaml", "id: b\nname: B\nlocal_check: true\n")
	e := NewEngine(dir)
	e.SetVerifier(devV{})
	f := newFake()
	f.errIDs["a"] = true
	e.AttachRegistry(f)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Get("a"); ok {
		t.Fatal("a file whose intake errored must not be listed as loaded")
	}
	if _, ok := e.Get("b"); !ok {
		t.Fatal("load must continue past one intake error")
	}
	if n := e.LastLoadIntakeFailures(); n != 1 {
		t.Fatalf("intake failures = %d, want 1", n)
	}
	delete(f.errIDs, "a")
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if n := e.LastLoadIntakeFailures(); n != 0 {
		t.Fatalf("intake failures after recovery = %d, want 0 (counter must reset per load)", n)
	}
}

func TestResolveExecutable_NoRegistryFailsClosed(t *testing.T) {
	e := NewEngine(t.TempDir())
	if _, err := e.ResolveExecutable(context.Background(), "x"); !errors.Is(err, ErrNoRegistry) {
		t.Fatalf("want ErrNoRegistry, got %v", err)
	}
}

func TestSaveAs_ApprovesAndRestoresOnFailure(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	f := newFake()
	e.AttachRegistry(f)
	sc := &Scenario{ID: "sv", Name: "S", LocalCheck: true}
	if err := e.SaveAs(context.Background(), sc, "user:op"); err != nil {
		t.Fatal(err)
	}
	if f.approved["sv"] != "user:op" {
		t.Fatalf("approval actor = %q", f.approved["sv"])
	}
	before, _ := os.ReadFile(filepath.Join(dir, "custom", "sv.yaml"))
	f.approveErr = errors.New("db down")
	if err := e.SaveAs(context.Background(), &Scenario{ID: "sv", Name: "changed", LocalCheck: true}, "user:op"); err == nil {
		t.Fatal("registry failure must fail the save")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "custom", "sv.yaml"))
	if string(before) != string(after) {
		t.Fatal("failed save must restore the previous file")
	}
	if got, _ := e.Get("sv"); got.Name != "S" {
		t.Fatalf("map must keep the previous scenario, got %q", got.Name)
	}
}

func TestDeleteAs_RetiresBeforeRemovingFile(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	f := newFake()
	e.AttachRegistry(f)
	if err := e.SaveAs(context.Background(), &Scenario{ID: "dl", Name: "D", LocalCheck: true}, "user:op"); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteAs(context.Background(), "dl", "user:op"); err != nil {
		t.Fatal(err)
	}
	if f.retired["dl"] != "user:op" {
		t.Fatal("delete must retire executable versions")
	}
	if _, err := os.Stat(filepath.Join(dir, "custom", "dl.yaml")); !os.IsNotExist(err) {
		t.Fatal("file must be removed")
	}
}

// Fix round 1 ruling (a): custom and intel are both LOCAL, so the registry
// may accept both; the engine map must still keep the higher-precedence file.
func TestLoad_CustomKeepsSlotOverIntelDuplicate(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "custom/x.yaml", "id: x\nname: C\nlocal_check: true\n")
	write(t, dir, "intel/x.yaml", "id: x\nname: I\nart_techniques: [T1082]\n")
	e := NewEngine(dir)
	e.SetVerifier(devV{})
	f := newFake()
	e.AttachRegistry(f)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	sc, ok := e.Get("x")
	if !ok || sc.Source != "custom" || sc.Name != "C" {
		t.Fatalf("custom must keep the map slot: %+v", sc)
	}
	want := filepath.Join(dir, "intel", "x.yaml") + "|duplicate id; higher-precedence file wins"
	if len(f.refusals) != 1 || f.refusals[0] != want {
		t.Fatalf("refusals = %v, want [%s]", f.refusals, want)
	}
}

func TestLoad_NoRegistryBuiltinBeatsCustomDuplicate(t *testing.T) {
	dir := t.TempDir()
	// zzz.yaml walks after custom/ and aaa.yaml before it: under the old
	// last-write-wins the winner depended on the file name. Builtin must win
	// both ways.
	write(t, dir, "zzz.yaml", "id: dup\nname: Builtin\nlocal_check: true\n")
	write(t, dir, "custom/dup.yaml", "id: dup\nname: Custom\nlocal_check: true\n")
	write(t, dir, "aaa.yaml", "id: dup2\nname: Builtin2\nlocal_check: true\n")
	write(t, dir, "custom/dup2.yaml", "id: dup2\nname: Custom2\nlocal_check: true\n")
	e := NewEngine(dir)
	e.SetVerifier(devV{})
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	for id, name := range map[string]string{"dup": "Builtin", "dup2": "Builtin2"} {
		sc, ok := e.Get(id)
		if !ok || sc.Source != "builtin" || sc.Name != name {
			t.Fatalf("%s: builtin must win: %+v", id, sc)
		}
	}
}

// badSigV reports signing enabled and rejects every signature.
type badSigV struct{}

func (badSigV) Verify([]byte, []byte) (bool, error) { return false, errors.New("signature invalid") }
func (badSigV) SigningEnabled() bool                { return true }

func TestLoad_TamperedBuiltinNotedAndNeverIntaken(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "tampered.yaml", "id: tampered\nname: T\nlocal_check: true\n")
	write(t, dir, "tampered.yaml.sig", "AAAA")
	e := NewEngine(dir)
	e.SetVerifier(badSigV{})
	f := newFake()
	e.AttachRegistry(f)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if len(f.order) != 0 {
		t.Fatalf("a tampered builtin must never reach Intake: %v", f.order)
	}
	if len(f.refusals) != 1 {
		t.Fatalf("tampered builtin must be noted as a refusal: %v", f.refusals)
	}
	if _, ok := e.Get("tampered"); ok {
		t.Fatal("tampered builtin must not be loaded")
	}
}

func TestSaveAs_FirstSaveRegistryFailureRemovesFile(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	f := newFake()
	f.approveErr = errors.New("db down")
	e.AttachRegistry(f)
	sc := &Scenario{ID: "fresh", Name: "F", LocalCheck: true, Source: "preset"}
	err := e.SaveAs(context.Background(), sc, "user:op")
	if err == nil || !errors.Is(err, f.approveErr) {
		t.Fatalf("want the registry error, got %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "custom", "fresh.yaml")); !os.IsNotExist(serr) {
		t.Fatalf("new file must be removed when there was no previous file: %v", serr)
	}
	if _, ok := e.Get("fresh"); ok {
		t.Fatal("failed save must not enter the map")
	}
	if sc.Source != "preset" {
		t.Fatalf("Source must be restored on failure, got %q", sc.Source)
	}
}

func TestDeleteAs_RetireErrorLeavesFileAndMap(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	f := newFake()
	e.AttachRegistry(f)
	if err := e.SaveAs(context.Background(), &Scenario{ID: "keep", Name: "K", LocalCheck: true}, "user:op"); err != nil {
		t.Fatal(err)
	}
	f.retireErr = errors.New("db down")
	if err := e.DeleteAs(context.Background(), "keep", "user:op"); err == nil || !errors.Is(err, f.retireErr) {
		t.Fatalf("want the retire error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "custom", "keep.yaml")); err != nil {
		t.Fatalf("file must remain after a failed retire: %v", err)
	}
	if _, ok := e.Get("keep"); !ok {
		t.Fatal("map entry must remain after a failed retire")
	}
}

// Final-review I1: Load rebuilds the map while handlers read it. Readers must
// never observe a map being written (fatal "concurrent map ..." throw).
func TestLoad_ConcurrentWithReaders(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 150; i++ {
		write(t, dir, fmt.Sprintf("s%03d.yaml", i), fmt.Sprintf("id: s%03d\nname: S\nlocal_check: true\n", i))
	}
	e := NewEngine(dir)
	e.SetVerifier(devV{})
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = e.List()
				_, _ = e.Get("s001")
				_ = e.Count()
				_ = e.Profiles()
			}
		}()
	}
	for i := 0; i < 15; i++ {
		if err := e.Load(); err != nil {
			t.Error(err)
		}
	}
	close(stop)
	wg.Wait()
	if e.Count() != 150 {
		t.Fatalf("count = %d, want 150", e.Count())
	}
}

// Final-review I2: a builtin refused at Load (bad/missing .sig) leaves no map
// entry and no registry row; its id must stay reserved so nothing LOCAL can
// claim it and lock the vendor builtin out forever.
func TestSaveAs_RefusesIDOfRefusedBuiltin(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "vendor.yaml", "id: vendor\nname: V\nlocal_check: true\n")
	write(t, dir, "vendor.yaml.sig", "AAAA")
	e := NewEngine(dir)
	e.SetVerifier(badSigV{})
	f := newFake()
	e.AttachRegistry(f)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	err := e.SaveAs(context.Background(), &Scenario{ID: "vendor", Name: "Mine", LocalCheck: true}, "user:op")
	if err == nil || !strings.Contains(err.Error(), "reserved by a built-in scenario") {
		t.Fatalf("want reserved-id refusal, got %v", err)
	}
	if _, ok := f.approved["vendor"]; ok {
		t.Fatal("reserved id must never reach the registry")
	}
	if _, serr := os.Stat(filepath.Join(dir, "custom", "vendor.yaml")); !os.IsNotExist(serr) {
		t.Fatalf("no custom file may be written for a reserved id: %v", serr)
	}
	// A normal custom id still saves.
	if err := e.SaveAs(context.Background(), &Scenario{ID: "mine", Name: "Mine", LocalCheck: true}, "user:op"); err != nil {
		t.Fatalf("normal save: %v", err)
	}
}

func TestLoad_LocalIntakeOfReservedBuiltinIDRefused(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "vendor.yaml", "id: vendor\nname: V\nlocal_check: true\n")
	write(t, dir, "vendor.yaml.sig", "AAAA")
	// Unparseable as a Scenario but its id is readable: still reserved.
	write(t, dir, "broken.yaml", "id: broken\nname: B\nsteps: not-a-list\n")
	write(t, dir, "custom/vendor.yaml", "id: vendor\nname: Shadow\nlocal_check: true\n")
	write(t, dir, "intel/broken.yaml", "id: broken\nname: Shadow\nart_techniques: [T1082]\n")
	write(t, dir, "custom/mine.yaml", "id: mine\nname: Mine\nlocal_check: true\n")
	e := NewEngine(dir)
	e.SetVerifier(badSigV{})
	f := newFake()
	e.AttachRegistry(f)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	for _, o := range f.order {
		if o == "custom:vendor" || o == "intel:broken" {
			t.Fatalf("a reserved builtin id must not be intaken as LOCAL: %v", f.order)
		}
	}
	for _, id := range []string{"vendor", "broken"} {
		if _, ok := e.Get(id); ok {
			t.Fatalf("%s must not be loaded", id)
		}
	}
	reserved := 0
	for _, r := range f.refusals {
		if strings.Contains(r, "reserved by a built-in scenario") {
			reserved++
		}
	}
	if reserved != 2 {
		t.Fatalf("want 2 reserved-id refusals, got %v", f.refusals)
	}
	if _, ok := e.Get("mine"); !ok {
		t.Fatal("a normal custom id must still load")
	}
}
