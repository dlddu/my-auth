package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

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
	Subject string         `json:"subject"`
	Claims  *oidcClaimsData `json:"claims,omitempty"`
}

// oidcClaimsData holds the serializable fields of openid.IDTokenClaims.
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

	// Serialize the session.
	if sess := req.GetSession(); sess != nil {
		if oidcSess, ok := sess.(*openid.DefaultSession); ok {
			sd := &oidcSessionData{
				Subject: oidcSess.Subject,
			}
			if oidcSess.Claims != nil {
				sd.Claims = &oidcClaimsData{
					Issuer:                              oidcSess.Claims.Issuer,
					Subject:                             oidcSess.Claims.Subject,
					Audience:                            []string(oidcSess.Claims.Audience),
					Nonce:                               oidcSess.Claims.Nonce,
					ExpiresAt:                           oidcSess.Claims.ExpiresAt,
					IssuedAt:                            oidcSess.Claims.IssuedAt,
					RequestedAt:                         oidcSess.Claims.RequestedAt,
					AuthTime:                            oidcSess.Claims.AuthTime,
					AccessTokenHash:                     oidcSess.Claims.AccessTokenHash,
					AuthenticationContextClassReference: oidcSess.Claims.AuthenticationContextClassReference,
					AuthenticationMethodsReferences:     oidcSess.Claims.AuthenticationMethodsReferences,
					CodeHash:                            oidcSess.Claims.CodeHash,
					Extra:                               oidcSess.Claims.Extra,
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
		if oidcSess, ok := sessionContainer.(*openid.DefaultSession); ok {
			oidcSess.Subject = rd.Session.Subject
			if rd.Session.Claims != nil {
				if oidcSess.Claims == nil {
					oidcSess.Claims = &openid.IDTokenClaims{}
				}
				oidcSess.Claims.Issuer = rd.Session.Claims.Issuer
				oidcSess.Claims.Subject = rd.Session.Claims.Subject
				oidcSess.Claims.Audience = rd.Session.Claims.Audience
				oidcSess.Claims.Nonce = rd.Session.Claims.Nonce
				oidcSess.Claims.ExpiresAt = rd.Session.Claims.ExpiresAt
				oidcSess.Claims.IssuedAt = rd.Session.Claims.IssuedAt
				oidcSess.Claims.RequestedAt = rd.Session.Claims.RequestedAt
				oidcSess.Claims.AuthTime = rd.Session.Claims.AuthTime
				oidcSess.Claims.AccessTokenHash = rd.Session.Claims.AccessTokenHash
				oidcSess.Claims.AuthenticationContextClassReference = rd.Session.Claims.AuthenticationContextClassReference
				oidcSess.Claims.AuthenticationMethodsReferences = rd.Session.Claims.AuthenticationMethodsReferences
				oidcSess.Claims.CodeHash = rd.Session.Claims.CodeHash
				oidcSess.Claims.Extra = rd.Session.Claims.Extra
			}
		}
	}

	req := &fosite.Request{
		ID:              rd.ID,
		RequestedAt:     rd.RequestedAt,
		RequestedScopes: fosite.Arguments(rd.Scopes),
		GrantedScopes:   fosite.Arguments(rd.GrantedScopes),
		Session:         sessionContainer,
		// Re-attach a minimal client representation so GetClient().GetID() works.
		Client: &fosite.DefaultClient{ID: rd.ClientID},
	}

	return req, nil
}
