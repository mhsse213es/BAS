package openaev

import "context"

// BundleProvider wraps a single manually-uploaded bundle — the air-gapped
// path. List() returns exactly the one scenario it was constructed with;
// Fetch() ignores the id argument and returns the bytes it was given (there
// is only ever one bundle per BundleProvider instance).
type BundleProvider struct {
	id   string
	data []byte
}

func NewBundleProvider(id string, data []byte) *BundleProvider {
	return &BundleProvider{id: id, data: data}
}

func (p *BundleProvider) Name() string { return "openaev-bundle-upload" }

func (p *BundleProvider) List(ctx context.Context) ([]ScenarioRef, error) {
	return []ScenarioRef{{ID: p.id}}, nil
}

func (p *BundleProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	return p.data, nil
}
