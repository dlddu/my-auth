package handler

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed admin/dist
var adminDistFS embed.FS

// NewAdminSPAHandler returns an http.HandlerFunc that serves the Admin SPA
// from the embedded admin/dist filesystem.
//
//   - Requests for existing regular files (e.g. /admin/assets/main.js) are
//     served directly with the correct Content-Type.
//   - All other /admin/* paths fall back to index.html for SPA client-side routing.
func NewAdminSPAHandler() http.HandlerFunc {
	// Strip the "admin/dist" prefix so the sub-filesystem root is "admin/dist".
	subFS, err := fs.Sub(adminDistFS, "admin/dist")
	if err != nil {
		panic("admin_spa: fs.Sub: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(subFS))

	// isRegularFile returns true when filePath names an existing regular file
	// (not a directory) within subFS.
	isRegularFile := func(filePath string) bool {
		f, err := subFS.Open(filePath)
		if err != nil {
			return false
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return false
		}
		return !info.IsDir()
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Compute the path relative to the embedded sub-filesystem by stripping
		// the /admin prefix that the chi router matched.
		urlPath := r.URL.Path
		relPath := strings.TrimPrefix(urlPath, "/admin")
		if relPath == "" {
			relPath = "/"
		}

		// Only serve a file directly when it exists as a regular file.
		if relPath != "/" {
			filePath := strings.TrimPrefix(relPath, "/")
			if isRegularFile(filePath) {
				// Rewrite the request path so the file server resolves it against
				// the sub-filesystem root (which has no /admin prefix).
				r2 := r.Clone(r.Context())
				r2.URL.Path = relPath
				fileServer.ServeHTTP(w, r2)
				return
			}
		}

		// Fallback: serve index.html for SPA client-side routing.
		f, err := subFS.Open("index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		defer f.Close()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	}
}
