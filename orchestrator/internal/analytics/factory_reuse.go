package analytics

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/jackc/pgx/v5/pgxpool"
)

// reuseSet is the content-reuse KPIs folded into the factory report.
type reuseSet struct {
	FactoryVersions         Metric
	ComposedFromLibrary     Metric
	ReuseRate               Metric
	LibraryComponentsReused Metric
}

// factoryReuse measures how much new factory content is assembled from existing
// library components instead of generated fresh.
//
// reuseRate = composed / factory versions created in the window, where a factory
// version is composer output or generator output with a generated_for link (the
// same test as the hands-off rate), and composed means it links at least one
// library component. NO_DATA when no factory content was created.
//
// libraryComponentsReused counts distinct components used by those versions. A
// component's own origin version does not count as a reuse of it.
//
// This is a different question from duplicateGenerationRate, which measures
// regeneration of content that already existed.
func factoryReuse(ctx context.Context, pool *pgxpool.Pool, since time.Time) (reuseSet, error) {
	const factoryFilter = `(cv.created_by = $2 OR (cv.created_by = $3 AND EXISTS (
		SELECT 1 FROM content_version_threats t
		WHERE t.content_version_id = cv.id AND t.relationship_kind = 'generated_for')))`

	var total, composed int
	if err := pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE EXISTS (
		           SELECT 1 FROM content_version_components c WHERE c.content_version_id = cv.id))
		FROM content_versions cv
		WHERE cv.created_at >= $1 AND `+factoryFilter,
		since, contentregistry.ActorComposer, contentregistry.ActorGenerator).Scan(&total, &composed); err != nil {
		return reuseSet{}, err
	}

	var reused int
	if err := pool.QueryRow(ctx, `
		SELECT count(DISTINCT c.component_id)
		FROM content_version_components c
		JOIN content_versions cv ON cv.id = c.content_version_id
		JOIN content_components comp ON comp.id = c.component_id
		WHERE cv.created_at >= $1
		  AND comp.origin_content_version_id IS DISTINCT FROM cv.id
		  AND `+factoryFilter,
		since, contentregistry.ActorComposer, contentregistry.ActorGenerator).Scan(&reused); err != nil {
		return reuseSet{}, err
	}

	return reuseSet{
		FactoryVersions:         measured(float64(total)),
		ComposedFromLibrary:     measured(float64(composed)),
		ReuseRate:               ratioOrNoData(composed, total, "no factory content was created in the window"),
		LibraryComponentsReused: measured(float64(reused)),
	}, nil
}
