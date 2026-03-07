package handler

import (
	"net/http"
	"sync"
	"time"
)

const adminSessionTTL = 24 * time.Hour

// adminSessionStore is a package-level in-memory session store shared between
// NewAdminLoginHandler and NewAdminSessionMiddleware.
var adminSessionStore = &sessionStore{
	tokens: make(map[string]time.Time),
}

// sessionStore holds admin session tokens in memory, protected by a RWMutex.
// Each token is stored with its creation time and expires after adminSessionTTL.
type sessionStore struct {
	mu     sync.RWMutex
	tokens map[string]time.Time
}

// Set stores a session token as valid with the current timestamp.
func (s *sessionStore) Set(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = time.Now()
}

// Has reports whether the given token is a valid, non-expired session token.
// Expired tokens are lazily removed on access.
func (s *sessionStore) Has(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	createdAt, ok := s.tokens[token]
	if !ok {
		return false
	}
	if time.Since(createdAt) >= adminSessionTTL {
		delete(s.tokens, token)
		return false
	}
	return true
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
