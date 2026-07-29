package threatgraph

import (
	"context"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/intelligence"
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

func TestActorNeighborhood_AssemblesTechniquesCampaignsMalwareToolsSectorsRegions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	// Uses the real "Wizard Spider" bundled ATT&CK group (same fixture
	// TechniqueNeighborhood's test and internal/connector/otx_test.go rely
	// on) specifically so this test exercises ActorNeighborhood's
	// GroupTechniqueIndex()-backed technique lookup for real, not just the
	// DB-backed campaign/malware/tool/sector/region lookups. A fake actor
	// name would have zero GroupTechniqueIndex() entries and silently skip
	// that code path entirely.
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) == 0 {
		t.Fatal("test fixture assumption broken: \"Wizard Spider\" not found in GroupTechniqueIndex()")
	}

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source)
			 VALUES ($1, '{}', $2, $3, 'test')`,
			"Wizard Spider", []string{"banking"}, []string{"APAC"})
		if err != nil {
			t.Fatalf("seed threat_actor_profiles: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider)
			 VALUES ('kgtestcampaign', 'KG Test Campaign', '', $1, '{}', 'test')`,
			[]string{"Wizard Spider"})
		if err != nil {
			t.Fatalf("seed intelligence_campaigns: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_malware (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgtestmalware', 'KG Test Malware', '{}', '{}', $1, '{}', 'test')`,
			[]string{"Wizard Spider"})
		if err != nil {
			t.Fatalf("seed intelligence_malware: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_tools (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgtesttool', 'KG Test Tool', '{}', '{}', $1, '{}', 'test')`,
			[]string{"Wizard Spider"})
		if err != nil {
			t.Fatalf("seed intelligence_tools: %v", err)
		}

		n, err := ActorNeighborhood(ctx, pool, "Wizard Spider")
		if err != nil {
			t.Fatalf("ActorNeighborhood: %v", err)
		}
		if n.Nodes[0].ID != "actor:"+intelligence.NormalizeKey("Wizard Spider") || n.Nodes[0].Type != NodeTypeActor {
			t.Fatalf("Nodes[0] = %+v, want the actor itself first", n.Nodes[0])
		}
		wantTypes := map[string]bool{NodeTypeTechnique: false, NodeTypeCampaign: false, NodeTypeMalware: false, NodeTypeTool: false, NodeTypeSector: false, NodeTypeRegion: false}
		for _, node := range n.Nodes[1:] {
			if _, ok := wantTypes[node.Type]; ok {
				wantTypes[node.Type] = true
			}
		}
		for nodeType, found := range wantTypes {
			if !found {
				t.Errorf("Nodes = %+v, missing a node of type %q", n.Nodes, nodeType)
			}
		}
		actorNodeID := "actor:" + intelligence.NormalizeKey("Wizard Spider")
		techniqueEdges := 0
		for _, e := range n.Edges {
			if e.Relationship == "uses" && e.From == actorNodeID && strings.HasPrefix(e.To, "technique:") {
				techniqueEdges++
			}
		}
		if techniqueEdges != len(wantTechs) {
			t.Errorf("actor->technique 'uses' edges = %d, want %d (len(GroupTechniqueIndex()[\"Wizard Spider\"]))", techniqueEdges, len(wantTechs))
		}
	})
}

func TestActorNeighborhood_UnknownNameReturnsEmptyNeighborhood(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		n, err := ActorNeighborhood(context.Background(), pool, "NoSuchActor")
		if err != nil {
			t.Fatalf("ActorNeighborhood: %v", err)
		}
		if len(n.Nodes) != 0 || len(n.Edges) != 0 {
			t.Fatalf("Neighborhood = %+v, want empty for an unknown actor", n)
		}
	})
}

func TestCampaignNeighborhood_IncludesActorsTechniquesMalwareTools(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := pool.Exec(ctx,
			`INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider)
			 VALUES ('kgcampaign2', 'KG Campaign Two', '', $1, $2, 'test')`,
			[]string{"KGActor2"}, []string{"T1059"})
		if err != nil {
			t.Fatalf("seed intelligence_campaigns: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_malware (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgmalware2', 'KG Malware Two', '{}', '{}', '{}', $1, 'test')`,
			[]string{"kgcampaign2"})
		if err != nil {
			t.Fatalf("seed intelligence_malware: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_tools (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgtool2', 'KG Tool Two', '{}', '{}', '{}', $1, 'test')`,
			[]string{"kgcampaign2"})
		if err != nil {
			t.Fatalf("seed intelligence_tools: %v", err)
		}

		n, err := CampaignNeighborhood(ctx, pool, "kgcampaign2")
		if err != nil {
			t.Fatalf("CampaignNeighborhood: %v", err)
		}
		if n.Nodes[0].ID != "campaign:kgcampaign2" {
			t.Fatalf("Nodes[0] = %+v, want the campaign itself first", n.Nodes[0])
		}
		wantTypes := map[string]bool{NodeTypeActor: false, NodeTypeTechnique: false, NodeTypeMalware: false, NodeTypeTool: false}
		for _, node := range n.Nodes[1:] {
			if _, ok := wantTypes[node.Type]; ok {
				wantTypes[node.Type] = true
			}
		}
		for nodeType, found := range wantTypes {
			if !found {
				t.Errorf("Nodes = %+v, missing a node of type %q", n.Nodes, nodeType)
			}
		}
	})
}

func TestMalwareNeighborhood_IncludesActorsTechniquesCampaigns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := pool.Exec(ctx,
			`INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider)
			 VALUES ('kgcampaign3', 'KG Campaign Three', '', '{}', '{}', 'test')`)
		if err != nil {
			t.Fatalf("seed intelligence_campaigns: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_malware (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgmalware3', 'KG Malware Three', '{}', $1, $2, $3, 'test')`,
			[]string{"T1105"}, []string{"KGActor3"}, []string{"kgcampaign3"})
		if err != nil {
			t.Fatalf("seed intelligence_malware: %v", err)
		}

		n, err := MalwareNeighborhood(ctx, pool, "kgmalware3")
		if err != nil {
			t.Fatalf("MalwareNeighborhood: %v", err)
		}
		if n.Nodes[0].ID != "malware:kgmalware3" {
			t.Fatalf("Nodes[0] = %+v, want the malware itself first", n.Nodes[0])
		}
		wantTypes := map[string]bool{NodeTypeActor: false, NodeTypeTechnique: false, NodeTypeCampaign: false}
		for _, node := range n.Nodes[1:] {
			if _, ok := wantTypes[node.Type]; ok {
				wantTypes[node.Type] = true
			}
		}
		for nodeType, found := range wantTypes {
			if !found {
				t.Errorf("Nodes = %+v, missing a node of type %q", n.Nodes, nodeType)
			}
		}
	})
}

func TestToolNeighborhood_IncludesActorsTechniquesCampaigns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := pool.Exec(ctx,
			`INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider)
			 VALUES ('kgcampaign4', 'KG Campaign Four', '', '{}', '{}', 'test')`)
		if err != nil {
			t.Fatalf("seed intelligence_campaigns: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO intelligence_tools (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider)
			 VALUES ('kgtool4', 'KG Tool Four', '{}', $1, $2, $3, 'test')`,
			[]string{"T1018"}, []string{"KGActor4"}, []string{"kgcampaign4"})
		if err != nil {
			t.Fatalf("seed intelligence_tools: %v", err)
		}

		n, err := ToolNeighborhood(ctx, pool, "kgtool4")
		if err != nil {
			t.Fatalf("ToolNeighborhood: %v", err)
		}
		if n.Nodes[0].ID != "tool:kgtool4" {
			t.Fatalf("Nodes[0] = %+v, want the tool itself first", n.Nodes[0])
		}
		wantTypes := map[string]bool{NodeTypeActor: false, NodeTypeTechnique: false, NodeTypeCampaign: false}
		for _, node := range n.Nodes[1:] {
			if _, ok := wantTypes[node.Type]; ok {
				wantTypes[node.Type] = true
			}
		}
		for nodeType, found := range wantTypes {
			if !found {
				t.Errorf("Nodes = %+v, missing a node of type %q", n.Nodes, nodeType)
			}
		}
	})
}

func TestLookup_DispatchesByType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := Lookup(context.Background(), pool, NodeTypeActor, "NoSuchActor"); err != nil {
			t.Errorf("Lookup(actor): %v", err)
		}
		if _, err := Lookup(context.Background(), pool, "bogus-type", "x"); err == nil {
			t.Error("Lookup(bogus-type) = nil error, want an error for an unknown type")
		}
	})
}
