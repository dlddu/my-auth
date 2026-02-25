// Package main is the entry point for the my-auth OAuth2/OIDC Authorization Server.
//
// The server implementation is work-in-progress. This binary currently serves
// only a /healthz endpoint so that the Playwright e2e test runner can confirm
// the process is alive. All application routes will be wired here in
// subsequent implementation tasks.
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()

	// Health check — used by the Playwright webServer probe and future
	// load-balancer readiness checks.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	addr := ":8080"
	fmt.Fprintf(os.Stdout, "my-auth: listening on %s\n", addr)

	if err := http.ListenAndServe(addr, r); err != nil {
		fmt.Fprintf(os.Stderr, "my-auth: server error: %v\n", err)
		os.Exit(1)
	}
}
