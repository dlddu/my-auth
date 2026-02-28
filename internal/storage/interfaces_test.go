// Package storage_test verifies that the storage implementations satisfy the
// required fosite storage interfaces at compile time.
//
// Each interface assertion uses a typed nil value assigned to the relevant
// fosite interface variable. If the type does not implement the interface,
// the build will fail with a clear compile error — which is the intended
// Red Phase outcome until the implementation is written.
package storage_test

import (
	"github.com/dlddu/my-auth/internal/storage"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
)

// The blank identifier assignments below are compile-time interface checks.
// They do not generate any executable code.

// ClientStore must implement fosite.ClientManager.
var _ fosite.ClientManager = (*storage.ClientStore)(nil)

// AuthorizeCodeStore must implement oauth2.AuthorizeCodeStorage.
var _ oauth2.AuthorizeCodeStorage = (*storage.AuthorizeCodeStore)(nil)

// AccessTokenStore must implement oauth2.AccessTokenStorage.
var _ oauth2.AccessTokenStorage = (*storage.AccessTokenStore)(nil)

// RefreshTokenStore must implement oauth2.RefreshTokenStorage.
var _ oauth2.RefreshTokenStorage = (*storage.RefreshTokenStore)(nil)

// OpenIDConnectSessionStore must implement openid.OpenIDConnectRequestStorage.
var _ openid.OpenIDConnectRequestStorage = (*storage.OpenIDConnectSessionStore)(nil)
