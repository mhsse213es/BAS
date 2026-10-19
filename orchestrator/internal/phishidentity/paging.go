package phishidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// maxGraphPages bounds how many pages one listing may read. Hitting the bound is an
// error. A truncated listing is never returned as if it were complete.
const maxGraphPages = 100

// maxGraphPageBytes bounds one response body.
const maxGraphPageBytes = 16 << 20

// getGraphPages GETs firstURL, then every @odata.nextLink in turn, handing each page
// body to handle. A next link must keep the first request's origin, path, and $filter.
// A page therefore cannot widen the query, and a foreign link is never followed.
func (c *Client) getGraphPages(ctx context.Context, firstURL string, handle func(body []byte) error) error {
	first, err := url.Parse(firstURL)
	if err != nil {
		return fmt.Errorf("phishidentity: parsing request URL: %w", err)
	}
	wantFilter := first.Query().Get("$filter")

	next := firstURL
	for page := 0; next != ""; page++ {
		if page >= maxGraphPages {
			return fmt.Errorf("phishidentity: more than %d pages; refusing a truncated result", maxGraphPages)
		}
		body, err := c.getGraphPage(ctx, next)
		if err != nil {
			return err
		}
		if err := handle(body); err != nil {
			return err
		}
		var envelope struct {
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("phishidentity: decoding response: %w", err)
		}
		next = ""
		if envelope.NextLink != "" {
			if err := checkNextLink(first, envelope.NextLink, wantFilter); err != nil {
				return err
			}
			next = envelope.NextLink
		}
	}
	return nil
}

// checkNextLink accepts a next link only when it names the same origin and path as
// the first request, and carries the same $filter. Anything else is refused.
func checkNextLink(first *url.URL, nextLink, wantFilter string) error {
	u, err := url.Parse(nextLink)
	if err != nil {
		return fmt.Errorf("phishidentity: next link is not a valid URL: %w", err)
	}
	if u.Scheme != first.Scheme || u.Host != first.Host || u.Path != first.Path {
		return fmt.Errorf("phishidentity: next link points away from the requested listing; refusing to follow it")
	}
	if u.Query().Get("$filter") != wantFilter {
		return fmt.Errorf("phishidentity: next link changes the filter; refusing to follow it")
	}
	return nil
}

// getGraphPage performs one authenticated GET and returns the body on HTTP 200.
func (c *Client) getGraphPage(ctx context.Context, reqURL string) ([]byte, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGraphPageBytes))
	if err != nil {
		return nil, fmt.Errorf("phishidentity: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		label := reqURL
		if u, perr := url.Parse(reqURL); perr == nil {
			label = u.Path
		}
		return nil, fmt.Errorf("phishidentity: %s returned status %d", label, resp.StatusCode)
	}
	return body, nil
}
