package testhelper_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// NewTestClient — happy path
// ---------------------------------------------------------------------------

func TestNewTestClient_MaintainsCookies(t *testing.T) {
	// Arrange — a minimal server that sets a cookie on the first request and
	// echoes whether the cookie was present on subsequent requests.
	cookieName := "session"
	cookieValue := "test-session-token"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set-cookie":
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: cookieValue, Path: "/"})
			w.WriteHeader(http.StatusOK)
		case "/check-cookie":
			c, err := r.Cookie(cookieName)
			if err != nil || c.Value != cookieValue {
				http.Error(w, "cookie missing", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	// Act
	client, _ := testhelper.NewTestClient(t)

	// First request — server sets the cookie.
	resp1, err := client.Get(srv.URL + "/set-cookie")
	if err != nil {
		t.Fatalf("GET /set-cookie: %v", err)
	}
	resp1.Body.Close()

	// Second request — client must send the cookie back automatically.
	resp2, err := client.Get(srv.URL + "/check-cookie")
	if err != nil {
		t.Fatalf("GET /check-cookie: %v", err)
	}
	defer resp2.Body.Close()

	// Assert
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d — cookie was not maintained across requests", resp2.StatusCode, http.StatusOK)
	}
}

func TestNewTestClient_TracksRedirects(t *testing.T) {
	// Arrange — a server that performs a single redirect:
	//   /start  → 302 → /end
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	// Act
	client, transport := testhelper.NewTestClient(t)

	resp, err := client.Get(srv.URL + "/start")
	if err != nil {
		t.Fatalf("GET /start: %v", err)
	}
	defer resp.Body.Close()

	// Assert — the final response must be 200 (redirect was followed).
	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Assert — exactly one redirect must have been recorded.
	history := transport.RedirectHistory()
	if len(history) != 1 {
		t.Fatalf("redirect history length = %d, want 1", len(history))
	}

	// Assert — the redirect went from /start to /end.
	if !containsPath(history[0][0], "/start") {
		t.Errorf("redirect from = %q, want path /start", history[0][0])
	}
	if !containsPath(history[0][1], "/end") {
		t.Errorf("redirect to = %q, want path /end", history[0][1])
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// containsPath reports whether rawURL contains the given path segment.
func containsPath(rawURL, path string) bool {
	return len(rawURL) > 0 && len(path) > 0 &&
		(rawURL == path || len(rawURL) >= len(path) && rawURL[len(rawURL)-len(path):] == path)
}
