package threatgraph

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestTechniqueNeighborhood_IncludesActorsFromGroupTechniqueIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	// "Wizard Spider" is a real bundled ATT&CK group -- internal/connector's
	// otx_test.go already relies on this exact fixture assumption.
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) == 0 {
		t.Fatal("test fixture assumption broken: \"Wizard Spider\" not found in GroupTechniqueIndex()")
	}
	techID := wantTechs[0]

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		n, err := TechniqueNeighborhood(context.Background(), pool, techID)
		if err != nil {
			t.Fatalf("TechniqueNeighborhood: %v", err)
		}
		if len(n.Nodes) < 2 {
			t.Fatalf("Nodes = %+v, want at least 2 (the technique itself + Wizard Spider)", n.Nodes)
		}
		if n.Nodes[0].Type != NodeTypeTechnique || n.Nodes[0].ID != "technique:"+techID {
			t.Fatalf("Nodes[0] = %+v, want the technique itself first", n.Nodes[0])
		}
		foundActor := false
		for _, node := range n.Nodes {
			if node.Type == NodeTypeActor && node.Label == "Wizard Spider" {
				foundActor = true
			}
		}
		if !foundActor {
			t.Errorf("Nodes = %+v, want to include actor Wizard Spider", n.Nodes)
		}
		foundEdge := false
		for _, e := range n.Edges {
			if e.To == "technique:"+techID && e.Relationship == "uses" {
				foundEdge = true
			}
		}
		if !foundEdge {
			t.Errorf("Edges = %+v, want at least one uses-edge into the technique", n.Edges)
		}
	})
}

func TestTechniqueNeighborhood_UnknownIDReturnsEmptyNeighborhood(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		n, err := TechniqueNeighborhood(context.Background(), pool, "T9999.999")
		if err != nil {
			t.Fatalf("TechniqueNeighborhood: %v", err)
		}
		if len(n.Nodes) != 0 || len(n.Edges) != 0 {
			t.Fatalf("Neighborhood = %+v, want empty for an unknown technique ID", n)
		}
	})
}
