package testhelper

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
)

// redirectRecord captures a single redirect hop for later inspection.
type redirectRecord struct {
	From *url.URL
	To   *url.URL
}

// TestClientTransport wraps an http.RoundTripper and exposes the redirect
// history recorded during the lifetime of the client.
//
// It is exported so tests can inspect redirect chains after a request
// completes.
type TestClientTransport struct {
	// Redirects holds one entry per redirect followed, in order.
	Redirects []redirectRecord
}

// RedirectHistory returns a copy of the recorded redirect chain as a slice
// of (from, to) URL string pairs for readable assertions in tests.
func (tc *TestClientTransport) RedirectHistory() [][2]string {
	out := make([][2]string, len(tc.Redirects))
	for i, r := range tc.Redirects {
		from := ""
		if r.From != nil {
			from = r.From.String()
		}
		to := ""
		if r.To != nil {
			to = r.To.String()
		}
		out[i] = [2]string{from, to}
	}
	return out
}

// NewTestClient returns an *http.Client configured for use in e2e tests:
//
//   - A per-jar CookieJar so cookies are maintained across requests within the
//     same client, mimicking a real browser session.
//   - A custom CheckRedirect function that follows up to 10 redirects while
//     recording each hop in tc.Redirects.
//
// The returned transport pointer allows tests to inspect redirect history after
// making requests.
func NewTestClient(t *testing.T) (*http.Client, *TestClientTransport) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("testhelper.NewTestClient: create cookie jar: %v", err)
	}

	tc := &TestClientTransport{}

	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 {
				return nil
			}

			// Record the redirect: from the previous URL, to the current URL.
			from := via[len(via)-1].URL
			tc.Redirects = append(tc.Redirects, redirectRecord{
				From: from,
				To:   req.URL,
			})

			// Follow up to 10 redirects, which is consistent with browser behaviour.
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return client, tc
}
