package handler

import (
	"net/http"
	"sync"
)

// adminSessionStore is a package-level in-memory session store shared between
// NewAdminLoginHandler and NewAdminSessionMiddleware.
var adminSessionStore = &sessionStore{
	tokens: make(map[string]bool),
}

// sessionStore holds admin session tokens in memory, protected by a RWMutex.
type sessionStore struct {
	mu     sync.RWMutex
	tokens map[string]bool
}

// Set stores a session token as valid.
func (s *sessionStore) Set(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = true
}

// Has reports whether the given token is a valid session token.
func (s *sessionStore) Has(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokens[token]
}

// NewAdminSessionMiddleware returns a middleware that validates the admin_session
// cookie. Requests without a valid cookie receive a 401 JSON response.
func NewAdminSessionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("admin_session")
			if err != nil || !adminSessionStore.Has(cookie.Value) {
				writeAdminError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
