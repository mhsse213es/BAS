package modsecwaf

import (
	"context"
	"fmt"
	"sync"

	"github.com/audspect/bas/internal/wafcatalog"
)

// SendBurst fires n real requests built from tmpl at the live WAF
// concurrently -- a genuine bounded burst, not n sequential round trips --
// and returns every response in request order. This is for behavioral,
// multi-request claims (e.g. a declared per-client rate limit) that
// Client.Send's single round trip cannot represent at all: rate-limit
// enforcement is a property of request RATE, so the requests must actually
// overlap in time for a real limiter to have anything to enforce against.
//
// Any single request's transport failure (not an HTTP error status, which is
// a legitimate response) fails the whole burst -- a rate-limit test only
// means something if every request in it genuinely reached the target.
func (c *Client) SendBurst(ctx context.Context, tmpl wafcatalog.RequestTemplate, n int) ([]RawResponse, error) {
	responses := make([]RawResponse, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			responses[i], errs[i] = c.Send(ctx, tmpl)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("modsecwaf: burst request %d/%d: %w", i+1, n, err)
		}
	}
	return responses, nil
}
