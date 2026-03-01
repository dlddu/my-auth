// Package storage_test — Device Code (RFC 8628) storage unit tests.
//
// Test coverage (Device Authorization Grant - RFC 8628):
//   - CreateDeviceCodeSession: happy path — device code row persisted without error
//   - GetDeviceCodeSession: returns the stored requester by device_code
//   - GetDeviceCodeSession: returns fosite.ErrNotFound for an unknown device_code
//   - InvalidateDeviceCodeSession: marks device_code as used; subsequent Get returns ErrNotFound
//   - CreateDeviceUserCodeSession: happy path — user_code row persisted without error
//   - GetDeviceUserCodeSession: returns the stored requester by user_code
//   - GetDeviceUserCodeSession: returns fosite.ErrNotFound for an unknown user_code
//   - InvalidateDeviceUserCodeSession: marks user_code as used; subsequent Get returns ErrNotFound
//   - UpdateDeviceCodeSessionStatus (approve): status → "approved", subject set
//   - UpdateDeviceCodeSessionStatus (deny): status → "denied"
//   - GetDeviceCodeSessionByUserCode: returns device code row for given user_code
//   - GetDeviceCodeSessionByUserCode: returns error for unknown user_code
//
// These tests follow the TDD Red Phase: the DeviceCodeStorage methods do not
// yet exist on *storage.Store, so the package will not compile until the
// implementation is provided.
package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Test helpers for device code tests
// ---------------------------------------------------------------------------

// newDeviceTestStore creates an isolated test database and returns a ready
// *storage.Store. The database connection is closed automatically via t.Cleanup.
func newDeviceTestStore(t *testing.T) *storage.Store {
	t.Helper()
	dsn := testhelper.NewTestDB(t)
	return newTestStore(t, dsn)
}

// newDeviceCodeRequest builds a minimal *fosite.Request that satisfies
// fosite.Requester for device code storage tests.
func newDeviceCodeRequest(client fosite.Client) *fosite.Request {
	sess := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: "user-456",
		},
		Headers: &jwt.Headers{},
	}
	return &fosite.Request{
		ID:             "device-req-001",
		Client:         client,
		Session:        sess,
		RequestedAt:    time.Now().UTC(),
		GrantedScope:   fosite.Arguments{"openid"},
		RequestedScope: fosite.Arguments{"openid"},
	}
}

// ---------------------------------------------------------------------------
// CreateDeviceCodeSession
// ---------------------------------------------------------------------------

// TestDeviceCodeStore_CreateSession verifies that CreateDeviceCodeSession
// persists a device code session without error (happy path).
//
// fosite calls CreateDeviceCodeSession when a device initiates the
// Device Authorization Grant flow (RFC 8628 §3.2).
func TestDeviceCodeStore_CreateSession(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)

	client := newTestClient("device-client-create")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newDeviceCodeRequest(client)
	deviceCode := "dc-create-001"

	// Act
	err := store.CreateDeviceCodeSession(ctx, deviceCode, req)

	// Assert
	if err != nil {
		t.Errorf("CreateDeviceCodeSession() returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetDeviceCodeSession
// ---------------------------------------------------------------------------

// TestDeviceCodeStore_GetSession verifies that GetDeviceCodeSession returns
// the requester that was stored by CreateDeviceCodeSession.
func TestDeviceCodeStore_GetSession(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)

	client := newTestClient("device-client-get")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newDeviceCodeRequest(client)
	deviceCode := "dc-get-001"

	if err := store.CreateDeviceCodeSession(ctx, deviceCode, req); err != nil {
		t.Fatalf("CreateDeviceCodeSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	got, err := store.GetDeviceCodeSession(ctx, deviceCode, sess)

	// Assert
	if err != nil {
		t.Fatalf("GetDeviceCodeSession() returned unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetDeviceCodeSession() returned nil Requester, want non-nil")
	}
	if got.GetClient().GetID() != client.GetID() {
		t.Errorf("Requester.Client.ID = %q, want %q", got.GetClient().GetID(), client.GetID())
	}
}

// TestDeviceCodeStore_GetSession_NotFound verifies that GetDeviceCodeSession
// returns fosite.ErrNotFound when no session exists for the given device_code.
//
// fosite relies on this sentinel to detect unknown device codes during polling.
func TestDeviceCodeStore_GetSession_NotFound(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)
	ctx := context.Background()

	sess := &openid.DefaultSession{}
	nonExistentCode := "dc-does-not-exist-999"

	// Act
	_, err := store.GetDeviceCodeSession(ctx, nonExistentCode, sess)

	// Assert — fosite requires ErrNotFound for an unknown device_code.
	if err == nil {
		t.Fatal("GetDeviceCodeSession() returned nil error for non-existent code, want fosite.ErrNotFound")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetDeviceCodeSession() error = %v, want fosite.ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// InvalidateDeviceCodeSession
// ---------------------------------------------------------------------------

// TestDeviceCodeStore_InvalidateSession verifies that
// InvalidateDeviceCodeSession marks the code so that subsequent
// GetDeviceCodeSession calls return fosite.ErrNotFound.
//
// RFC 8628 §3.5: after an access token is issued the device_code must be
// invalidated to prevent replay.
func TestDeviceCodeStore_InvalidateSession(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)

	client := newTestClient("device-client-invalidate")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newDeviceCodeRequest(client)
	deviceCode := "dc-invalidate-001"

	if err := store.CreateDeviceCodeSession(ctx, deviceCode, req); err != nil {
		t.Fatalf("CreateDeviceCodeSession(): %v", err)
	}

	// Act
	err := store.InvalidateDeviceCodeSession(ctx, deviceCode)

	// Assert — invalidation itself must succeed.
	if err != nil {
		t.Errorf("InvalidateDeviceCodeSession() returned unexpected error: %v", err)
	}

	// Assert — subsequent Get must return ErrNotFound (or equivalent sentinel).
	sess := &openid.DefaultSession{}
	_, getErr := store.GetDeviceCodeSession(ctx, deviceCode, sess)
	if getErr == nil {
		t.Error("GetDeviceCodeSession() after invalidation returned nil error, want an error")
	}
}

// ---------------------------------------------------------------------------
// CreateDeviceUserCodeSession
// ---------------------------------------------------------------------------

// TestDeviceUserCodeStore_CreateSession verifies that
// CreateDeviceUserCodeSession persists a user_code session without error.
//
// fosite calls CreateDeviceUserCodeSession alongside CreateDeviceCodeSession
// so that the short user_code (e.g. "ABCD-EFGH") can be looked up
// independently when the user visits /device/verify.
func TestDeviceUserCodeStore_CreateSession(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)

	client := newTestClient("user-code-client-create")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newDeviceCodeRequest(client)
	userCode := "AAAA-BBBB"

	// Act
	err := store.CreateDeviceUserCodeSession(ctx, userCode, req)

	// Assert
	if err != nil {
		t.Errorf("CreateDeviceUserCodeSession() returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetDeviceUserCodeSession
// ---------------------------------------------------------------------------

// TestDeviceUserCodeStore_GetSession verifies that GetDeviceUserCodeSession
// returns the requester stored by CreateDeviceUserCodeSession.
func TestDeviceUserCodeStore_GetSession(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)

	client := newTestClient("user-code-client-get")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newDeviceCodeRequest(client)
	userCode := "CCCC-DDDD"

	if err := store.CreateDeviceUserCodeSession(ctx, userCode, req); err != nil {
		t.Fatalf("CreateDeviceUserCodeSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	got, err := store.GetDeviceUserCodeSession(ctx, userCode, sess)

	// Assert
	if err != nil {
		t.Fatalf("GetDeviceUserCodeSession() returned unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetDeviceUserCodeSession() returned nil Requester, want non-nil")
	}
	if got.GetClient().GetID() != client.GetID() {
		t.Errorf("Requester.Client.ID = %q, want %q", got.GetClient().GetID(), client.GetID())
	}
}

// TestDeviceUserCodeStore_GetSession_NotFound verifies that
// GetDeviceUserCodeSession returns fosite.ErrNotFound when no session exists
// for the given user_code.
//
// This is the error fosite returns when a user enters an invalid code on the
// /device/verify page.
func TestDeviceUserCodeStore_GetSession_NotFound(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)
	ctx := context.Background()

	sess := &openid.DefaultSession{}
	nonExistentCode := "ZZZZ-9999"

	// Act
	_, err := store.GetDeviceUserCodeSession(ctx, nonExistentCode, sess)

	// Assert — fosite requires ErrNotFound for an unknown user_code.
	if err == nil {
		t.Fatal("GetDeviceUserCodeSession() returned nil error for non-existent user_code, want fosite.ErrNotFound")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetDeviceUserCodeSession() error = %v, want fosite.ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// InvalidateDeviceUserCodeSession
// ---------------------------------------------------------------------------

// TestDeviceUserCodeStore_InvalidateSession verifies that
// InvalidateDeviceUserCodeSession marks the user_code so that subsequent
// GetDeviceUserCodeSession calls return fosite.ErrNotFound.
func TestDeviceUserCodeStore_InvalidateSession(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)

	client := newTestClient("user-code-client-invalidate")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newDeviceCodeRequest(client)
	userCode := "EEEE-FFFF"

	if err := store.CreateDeviceUserCodeSession(ctx, userCode, req); err != nil {
		t.Fatalf("CreateDeviceUserCodeSession(): %v", err)
	}

	// Act
	err := store.InvalidateDeviceUserCodeSession(ctx, userCode)

	// Assert — invalidation itself must succeed.
	if err != nil {
		t.Errorf("InvalidateDeviceUserCodeSession() returned unexpected error: %v", err)
	}

	// Assert — subsequent Get must return an error.
	sess := &openid.DefaultSession{}
	_, getErr := store.GetDeviceUserCodeSession(ctx, userCode, sess)
	if getErr == nil {
		t.Error("GetDeviceUserCodeSession() after invalidation returned nil error, want an error")
	}
}

// ---------------------------------------------------------------------------
// UpdateDeviceCodeSessionStatus
// ---------------------------------------------------------------------------

// TestDeviceCodeStore_UpdateStatus_Approve verifies that
// UpdateDeviceCodeSessionStatus transitions a device_code row from
// status="pending" to status="approved" and sets the subject field.
//
// This is called from the POST /device/verify handler when the user approves
// the device request (RFC 8628 §3.3).
func TestDeviceCodeStore_UpdateStatus_Approve(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)

	client := newTestClient("device-client-approve")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newDeviceCodeRequest(client)
	deviceCode := "dc-approve-001"

	if err := store.CreateDeviceCodeSession(ctx, deviceCode, req); err != nil {
		t.Fatalf("CreateDeviceCodeSession(): %v", err)
	}

	subject := "admin@test.local"

	// Act
	err := store.UpdateDeviceCodeSessionByDeviceCode(ctx, deviceCode, subject, "approved")

	// Assert — status update must succeed.
	if err != nil {
		t.Errorf("UpdateDeviceCodeSessionByDeviceCode() (approve) returned unexpected error: %v", err)
	}
}

// TestDeviceCodeStore_UpdateStatus_Deny verifies that
// UpdateDeviceCodeSessionStatus transitions a device_code row from
// status="pending" to status="denied".
//
// This is called from the POST /device/verify handler when the user denies
// the device request (RFC 8628 §3.5 error: access_denied).
func TestDeviceCodeStore_UpdateStatus_Deny(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)

	client := newTestClient("device-client-deny")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newDeviceCodeRequest(client)
	deviceCode := "dc-deny-001"

	if err := store.CreateDeviceCodeSession(ctx, deviceCode, req); err != nil {
		t.Fatalf("CreateDeviceCodeSession(): %v", err)
	}

	// Act
	err := store.UpdateDeviceCodeSessionByDeviceCode(ctx, deviceCode, "", "denied")

	// Assert
	if err != nil {
		t.Errorf("UpdateDeviceCodeSessionByDeviceCode() (deny) returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetDeviceCodeSessionByUserCode
// ---------------------------------------------------------------------------

// TestDeviceCodeStore_GetByUserCode verifies that
// GetDeviceCodeSessionByUserCode returns the device_code row corresponding
// to the given user_code.
//
// This is used by the POST /device/verify handler to look up the device
// session by the user-entered code before updating its status.
func TestDeviceCodeStore_GetByUserCode(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)

	client := newTestClient("device-client-byusercode")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newDeviceCodeRequest(client)
	deviceCode := "dc-byusercode-001"
	userCode := "GGGG-HHHH"

	if err := store.CreateDeviceCodeSession(ctx, deviceCode, req); err != nil {
		t.Fatalf("CreateDeviceCodeSession(): %v", err)
	}
	if err := store.CreateDeviceUserCodeSession(ctx, userCode, req); err != nil {
		t.Fatalf("CreateDeviceUserCodeSession(): %v", err)
	}

	// Act
	gotDeviceCode, err := store.GetDeviceCodeByUserCode(ctx, userCode)

	// Assert
	if err != nil {
		t.Fatalf("GetDeviceCodeByUserCode() returned unexpected error: %v", err)
	}
	if gotDeviceCode == "" {
		t.Error("GetDeviceCodeByUserCode() returned empty device_code, want non-empty")
	}
}

// TestDeviceCodeStore_GetByUserCode_NotFound verifies that
// GetDeviceCodeByUserCode returns an error when no row exists for the given
// user_code.
func TestDeviceCodeStore_GetByUserCode_NotFound(t *testing.T) {
	// Arrange
	store := newDeviceTestStore(t)
	ctx := context.Background()

	nonExistentUserCode := "XXXX-YYYY"

	// Act
	_, err := store.GetDeviceCodeByUserCode(ctx, nonExistentUserCode)

	// Assert — a missing user_code must return an error (not a silent empty result).
	if err == nil {
		t.Error("GetDeviceCodeByUserCode() returned nil error for non-existent user_code, want an error")
	}
}
