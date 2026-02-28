package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// oidcSessionAccessor provides access to OIDC session data. Both
// *openid.DefaultSession and custom wrapper types (like JWTOIDCSession)
// that embed it satisfy this interface.
type oidcSessionAccessor interface {
	IDTokenClaims() *jwt.IDTokenClaims
	GetSubject() string
}

// requestData is the JSON-serializable form of a fosite.Requester.
// We store only the fields we need for token operations.
type requestData struct {
	ID            string              `json:"id"`
	RequestedAt   time.Time           `json:"requested_at"`
	ClientID      string              `json:"client_id"`
	Scopes        []string            `json:"scopes"`
	GrantedScopes []string            `json:"granted_scopes"`
	Form          map[string][]string `json:"form,omitempty"`
	Session       *oidcSessionData    `json:"session,omitempty"`
}

// oidcSessionData holds the serializable fields of openid.DefaultSession.
type oidcSessionData struct {
	Subject string          `json:"subject"`
	Claims  *oidcClaimsData `json:"claims,omitempty"`
}

// oidcClaimsData holds the serializable fields of jwt.IDTokenClaims.
type oidcClaimsData struct {
	Issuer                              string                 `json:"iss,omitempty"`
	Subject                             string                 `json:"sub,omitempty"`
	Audience                            []string               `json:"aud,omitempty"`
	Nonce                               string                 `json:"nonce,omitempty"`
	ExpiresAt                           time.Time              `json:"exp,omitempty"`
	IssuedAt                            time.Time              `json:"iat,omitempty"`
	RequestedAt                         time.Time              `json:"rat,omitempty"`
	AuthTime                            time.Time              `json:"auth_time,omitempty"`
	AccessTokenHash                     string                 `json:"at_hash,omitempty"`
	AuthenticationContextClassReference string                 `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string               `json:"amr,omitempty"`
	CodeHash                            string                 `json:"c_hash,omitempty"`
	Extra                               map[string]interface{} `json:"ext,omitempty"`
}

// serializeRequest converts a fosite.Requester into JSON bytes.
// It captures the OIDC session data if present.
func serializeRequest(req fosite.Requester) ([]byte, error) {
	rd := &requestData{
		ID:            req.GetID(),
		RequestedAt:   req.GetRequestedAt(),
		ClientID:      req.GetClient().GetID(),
		Scopes:        []string(req.GetRequestedScopes()),
		GrantedScopes: []string(req.GetGrantedScopes()),
	}

	// Serialize the session. Use the oidcSessionAccessor interface so that
	// both *openid.DefaultSession and wrapper types (e.g. JWTOIDCSession)
	// are handled without a concrete type assertion.
	if sess := req.GetSession(); sess != nil {
		if oidcSess, ok := sess.(oidcSessionAccessor); ok {
			sd := &oidcSessionData{
				Subject: oidcSess.GetSubject(),
			}
			claims := oidcSess.IDTokenClaims()
			if claims != nil {
				sd.Claims = &oidcClaimsData{
					Issuer:                              claims.Issuer,
					Subject:                             claims.Subject,
					Audience:                            []string(claims.Audience),
					Nonce:                               claims.Nonce,
					ExpiresAt:                           claims.ExpiresAt,
					IssuedAt:                            claims.IssuedAt,
					RequestedAt:                         claims.RequestedAt,
					AuthTime:                            claims.AuthTime,
					AccessTokenHash:                     claims.AccessTokenHash,
					AuthenticationContextClassReference: claims.AuthenticationContextClassReference,
					AuthenticationMethodsReferences:     claims.AuthenticationMethodsReferences,
					CodeHash:                            claims.CodeHash,
					Extra:                               claims.Extra,
				}
			}
			rd.Session = sd
		}
	}

	data, err := json.Marshal(rd)
	if err != nil {
		return nil, fmt.Errorf("storage: serialize request: %w", err)
	}
	return data, nil
}

// deserializeRequest reconstructs a fosite.Request from JSON bytes.
// The sessionContainer is used as the concrete session type and populated
// from the stored session data.
func deserializeRequest(data []byte, sessionContainer fosite.Session, _ *ClientStore) (*fosite.Request, error) {
	var rd requestData
	if err := json.Unmarshal(data, &rd); err != nil {
		return nil, fmt.Errorf("storage: deserialize request: %w", err)
	}

	// Restore session fields into the provided container.
	if rd.Session != nil {
		// Populate the OIDC claims via interface (works for both
		// *openid.DefaultSession and wrapper types like JWTOIDCSession).
		if accessor, ok := sessionContainer.(oidcSessionAccessor); ok {
			claims := accessor.IDTokenClaims()
			if rd.Session.Claims != nil && claims != nil {
				claims.Issuer = rd.Session.Claims.Issuer
				claims.Subject = rd.Session.Claims.Subject
				claims.Audience = rd.Session.Claims.Audience
				claims.Nonce = rd.Session.Claims.Nonce
				claims.ExpiresAt = rd.Session.Claims.ExpiresAt
				claims.IssuedAt = rd.Session.Claims.IssuedAt
				claims.RequestedAt = rd.Session.Claims.RequestedAt
				claims.AuthTime = rd.Session.Claims.AuthTime
				claims.AccessTokenHash = rd.Session.Claims.AccessTokenHash
				claims.AuthenticationContextClassReference = rd.Session.Claims.AuthenticationContextClassReference
				claims.AuthenticationMethodsReferences = rd.Session.Claims.AuthenticationMethodsReferences
				claims.CodeHash = rd.Session.Claims.CodeHash
				claims.Extra = rd.Session.Claims.Extra
			}
		}

		// Set Subject on the session struct. Use the concrete type for
		// *openid.DefaultSession (direct field access) and a SetSubject
		// interface for wrapper types that embed it.
		switch s := sessionContainer.(type) {
		case *openid.DefaultSession:
			s.Subject = rd.Session.Subject
		case interface{ SetSubject(string) }:
			s.SetSubject(rd.Session.Subject)
		}
	}

	req := &fosite.Request{
		ID:             rd.ID,
		RequestedAt:    rd.RequestedAt,
		RequestedScope: fosite.Arguments(rd.Scopes),
		GrantedScope:   fosite.Arguments(rd.GrantedScopes),
		Session:        sessionContainer,
		// Re-attach a minimal client representation so GetClient().GetID() works.
		Client: &fosite.DefaultClient{ID: rd.ClientID},
	}

	return req, nil
}
