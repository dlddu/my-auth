package testhelper_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// NewTestServer — happy path
// ---------------------------------------------------------------------------

func TestNewTestServer_StartsAndStops(t *testing.T) {
	// Act
	srv, _ := testhelper.NewTestServer(t)

	// Assert — server must have a non-empty URL.
	if srv.URL == "" {
		t.Fatal("NewTestServer() returned server with empty URL")
	}

	// Assert — a basic TCP connection must succeed (server is listening).
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Cleanup is registered inside NewTestServer via t.Cleanup.
	// No explicit srv.Close() is required here; the test framework calls it.
}

func TestNewTestServer_RespondsToRequests(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("client.Get(/healthz): %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", string(body), "ok")
	}
}
