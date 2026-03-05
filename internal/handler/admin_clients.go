package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/go-chi/chi/v5"
	"github.com/ory/fosite"
)

// AdminClientStore defines the storage operations required by admin client handlers.
type AdminClientStore interface {
	GetClient(ctx context.Context, id string) (fosite.Client, error)
	CreateClient(ctx context.Context, client fosite.Client) error
	ListClients(ctx context.Context) ([]fosite.Client, error)
	UpdateClient(ctx context.Context, client fosite.Client) error
	DeleteClient(ctx context.Context, id string) error
}

// allowedGrantTypes is the set of grant types that the admin API accepts.
var allowedGrantTypes = map[string]bool{
	"authorization_code":                            true,
	"client_credentials":                            true,
	"refresh_token":                                 true,
	"urn:ietf:params:oauth:grant-type:device_code":  true,
}

// grantTypesRequiringRedirectURI lists grant types that require at least one redirect_uri.
var grantTypesRequiringRedirectURI = map[string]bool{
	"authorization_code": true,
	"refresh_token":      true,
}

// adminErrorResponse is the JSON body for error responses from admin endpoints.
type adminErrorResponse struct {
	Error string `json:"error"`
}

// adminClientResponse is the JSON representation of a client for API responses.
type adminClientResponse struct {
	ID                      string   `json:"id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scopes                  []string `json:"scopes"`
	IsPublic                bool     `json:"is_public"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// createClientInput is the JSON body accepted by POST /api/admin/clients.
type createClientInput struct {
	ID                      string   `json:"id"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scopes                  []string `json:"scopes"`
	IsPublic                bool     `json:"is_public"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// updateClientInput is the JSON body accepted by PUT /api/admin/clients/{id}.
type updateClientInput struct {
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	Scopes        []string `json:"scopes"`
}

// writeAdminError writes a JSON error response to w.
func writeAdminError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(adminErrorResponse{Error: message})
}

// writeAdminJSON writes a JSON success response to w.
func writeAdminJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// NewAdminAuthMiddleware returns a middleware that validates a Bearer token
// against adminToken. Requests without a valid "Bearer <token>" header receive
// a 401 JSON response.
func NewAdminAuthMiddleware(adminToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(authHeader, prefix) {
				writeAdminError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}
			token := strings.TrimPrefix(authHeader, prefix)
			if token != adminToken {
				writeAdminError(w, http.StatusUnauthorized, "invalid admin token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// generateClientID generates a cryptographically random 32-character hex string
// suitable for use as a client_id.
func generateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateClientSecret generates a cryptographically random 64-character hex
// string suitable for use as a plain-text client_secret before bcrypt hashing.
func generateClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validateRedirectURIs checks that every URI in the list is a valid URL with a
// scheme and host.
func validateRedirectURIs(uris []string) error {
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid redirect_uri: %q", raw)
		}
	}
	return nil
}

// validateGrantTypes checks that every grant type is in the allowed list.
func validateGrantTypes(grantTypes []string) error {
	for _, gt := range grantTypes {
		if !allowedGrantTypes[gt] {
			return fmt.Errorf("unsupported grant_type: %q", gt)
		}
	}
	return nil
}

// needsRedirectURIs returns true when any of the supplied grant types requires
// a redirect URI.
func needsRedirectURIs(grantTypes []string) bool {
	for _, gt := range grantTypes {
		if grantTypesRequiringRedirectURI[gt] {
			return true
		}
	}
	return false
}

// fositeClientToResponse converts a fosite.Client to the admin API response
// shape, omitting the client_secret field.
func fositeClientToResponse(c fosite.Client) adminClientResponse {
	scopes := c.GetScopes()
	if scopes == nil {
		scopes = []string{}
	}
	resp := adminClientResponse{
		ID:            c.GetID(),
		RedirectURIs:  c.GetRedirectURIs(),
		GrantTypes:    []string(c.GetGrantTypes()),
		ResponseTypes: []string(c.GetResponseTypes()),
		Scopes:        scopes,
		IsPublic:      c.IsPublic(),
	}
	if dc, ok := c.(*fosite.DefaultOpenIDConnectClient); ok {
		resp.TokenEndpointAuthMethod = dc.TokenEndpointAuthMethod
	}
	if resp.RedirectURIs == nil {
		resp.RedirectURIs = []string{}
	}
	if resp.GrantTypes == nil {
		resp.GrantTypes = []string{}
	}
	if resp.ResponseTypes == nil {
		resp.ResponseTypes = []string{}
	}
	return resp
}

// NewCreateClientHandler returns an http.HandlerFunc that handles
// POST /api/admin/clients.
func NewCreateClientHandler(store AdminClientStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input createClientInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Validate grant types.
		if err := validateGrantTypes(input.GrantTypes); err != nil {
			writeAdminError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Validate redirect URIs format.
		if err := validateRedirectURIs(input.RedirectURIs); err != nil {
			writeAdminError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Require redirect_uris for grant types that need them.
		if needsRedirectURIs(input.GrantTypes) && len(input.RedirectURIs) == 0 {
			writeAdminError(w, http.StatusBadRequest, "redirect_uris required for the specified grant_types")
			return
		}

		// Use the provided client_id or generate one if not supplied.
		clientID := input.ID
		if clientID == "" {
			var genErr error
			clientID, genErr = generateClientID()
			if genErr != nil {
				writeAdminError(w, http.StatusInternalServerError, "failed to generate client ID")
				return
			}
		}

		tokenEndpointAuthMethod := input.TokenEndpointAuthMethod
		if tokenEndpointAuthMethod == "" {
			if input.IsPublic {
				tokenEndpointAuthMethod = "none"
			} else {
				tokenEndpointAuthMethod = "client_secret_basic"
			}
		}

		scopes := input.Scopes
		if scopes == nil {
			scopes = []string{}
		}

		var plainSecret string
		var secretHash []byte

		if !input.IsPublic {
			// Generate and hash a client secret for confidential clients.
			var secretErr error
			plainSecret, secretErr = generateClientSecret()
			if secretErr != nil {
				writeAdminError(w, http.StatusInternalServerError, "failed to generate client secret")
				return
			}
			secretHash, secretErr = bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
			if secretErr != nil {
				writeAdminError(w, http.StatusInternalServerError, "failed to hash client secret")
				return
			}
		}

		client := &fosite.DefaultOpenIDConnectClient{
			DefaultClient: &fosite.DefaultClient{
				ID:            clientID,
				Secret:        secretHash,
				Public:        input.IsPublic,
				RedirectURIs:  input.RedirectURIs,
				GrantTypes:    input.GrantTypes,
				ResponseTypes: input.ResponseTypes,
				Scopes:        scopes,
			},
			TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		}

		if err := store.CreateClient(r.Context(), client); err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to create client")
			return
		}

		resp := fositeClientToResponse(client)
		// Include the plain-text secret in the creation response (one-time exposure).
		resp.ClientSecret = plainSecret

		writeAdminJSON(w, http.StatusCreated, resp)
	}
}

// NewListClientsHandler returns an http.HandlerFunc that handles
// GET /api/admin/clients.
func NewListClientsHandler(store AdminClientStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clients, err := store.ListClients(r.Context())
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to list clients")
			return
		}

		items := make([]adminClientResponse, 0, len(clients))
		for _, c := range clients {
			item := fositeClientToResponse(c)
			// Do not expose client_secret in list responses.
			item.ClientSecret = ""
			items = append(items, item)
		}

		writeAdminJSON(w, http.StatusOK, items)
	}
}

// NewGetClientHandler returns an http.HandlerFunc that handles
// GET /api/admin/clients/{id}.
func NewGetClientHandler(store AdminClientStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		c, err := store.GetClient(r.Context(), id)
		if err == fosite.ErrNotFound {
			writeAdminError(w, http.StatusNotFound, "client not found")
			return
		}
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to get client")
			return
		}

		resp := fositeClientToResponse(c)
		// Do not expose client_secret in get responses.
		resp.ClientSecret = ""
		writeAdminJSON(w, http.StatusOK, resp)
	}
}

// NewUpdateClientHandler returns an http.HandlerFunc that handles
// PUT /api/admin/clients/{id}.
func NewUpdateClientHandler(store AdminClientStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		var input updateClientInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Validate grant types.
		if err := validateGrantTypes(input.GrantTypes); err != nil {
			writeAdminError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Validate redirect URIs format.
		if err := validateRedirectURIs(input.RedirectURIs); err != nil {
			writeAdminError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Fetch the existing client to preserve secret and public flag.
		existing, err := store.GetClient(r.Context(), id)
		if err == fosite.ErrNotFound {
			writeAdminError(w, http.StatusNotFound, "client not found")
			return
		}
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to get client")
			return
		}

		// Preserve the existing secret.
		var existingSecret []byte
		var tokenEndpointAuthMethod string
		if dc, ok := existing.(*fosite.DefaultOpenIDConnectClient); ok {
			existingSecret = dc.Secret
			tokenEndpointAuthMethod = dc.TokenEndpointAuthMethod
		}

		scopes := input.Scopes
		if scopes == nil {
			scopes = []string{}
		}

		updated := &fosite.DefaultOpenIDConnectClient{
			DefaultClient: &fosite.DefaultClient{
				ID:            id,
				Secret:        existingSecret,
				Public:        existing.IsPublic(),
				RedirectURIs:  input.RedirectURIs,
				GrantTypes:    input.GrantTypes,
				ResponseTypes: input.ResponseTypes,
				Scopes:        scopes,
			},
			TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		}

		if err := store.UpdateClient(r.Context(), updated); err != nil {
			// If error message contains "not found", treat as 404.
			if strings.Contains(err.Error(), "not found") {
				writeAdminError(w, http.StatusNotFound, "client not found")
				return
			}
			writeAdminError(w, http.StatusInternalServerError, "failed to update client")
			return
		}

		resp := fositeClientToResponse(updated)
		resp.ClientSecret = ""
		writeAdminJSON(w, http.StatusOK, resp)
	}
}

// NewDeleteClientHandler returns an http.HandlerFunc that handles
// DELETE /api/admin/clients/{id}.
func NewDeleteClientHandler(store AdminClientStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		err := store.DeleteClient(r.Context(), id)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				writeAdminError(w, http.StatusNotFound, "client not found")
				return
			}
			writeAdminError(w, http.StatusInternalServerError, "failed to delete client")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
