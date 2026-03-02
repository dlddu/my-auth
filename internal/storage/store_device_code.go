package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
)

// ---------------------------------------------------------------------------
// Device Code Storage (RFC 8628)
//
// The device_codes table stores both the device_code (opaque token sent to
// the device) and the user_code (short code shown to the user).  A single
// row represents one Device Authorization Grant session identified by the
// device_code primary key.  An additional row keyed by a placeholder
// device_code value stores the user_code → request mapping.
//
// The request_data column (added by migration 000006) holds the full
// marshalRequester JSON blob so that the Requester can be reconstructed on
// subsequent Get calls.
// ---------------------------------------------------------------------------

// InsertDeviceCode persists a new device-code row with both device_code and
// user_code set, along with the raw scope string and expiry time.
// This is used directly by the device code handler (not by the fosite storage
// layer) to store both codes in a single row.
func (s *Store) InsertDeviceCode(ctx context.Context, deviceCode, userCode, clientID, scope string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO device_codes
		   (device_code, user_code, client_id, scopes, expires_at, status, subject, request_data)
		 VALUES (?, ?, ?, ?, ?, 'pending', '', '{}')`,
		deviceCode,
		userCode,
		clientID,
		scope,
		expiresAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("storage: InsertDeviceCode: %w", err)
	}
	return nil
}

// GetDeviceCodeStatus returns the status and subject for the given device_code.
func (s *Store) GetDeviceCodeStatus(ctx context.Context, deviceCode string) (status, subject string, err error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT status, COALESCE(subject, '') FROM device_codes WHERE device_code = ?`,
		deviceCode,
	)
	if scanErr := row.Scan(&status, &subject); scanErr != nil {
		if scanErr == sql.ErrNoRows {
			return "", "", fosite.ErrNotFound
		}
		return "", "", fmt.Errorf("storage: GetDeviceCodeStatus: %w", scanErr)
	}
	return status, subject, nil
}

// GetDeviceCodeStatusFull returns the status, subject, expires_at, and scopes
// for the given device_code.  It is used by the device token polling handler
// (POST /oauth2/token with grant_type=device_code) to determine whether to
// issue an access token, return authorization_pending, or return expired_token.
//
// Returns fosite.ErrNotFound when no row exists for the given device_code.
func (s *Store) GetDeviceCodeStatusFull(ctx context.Context, deviceCode string) (status, subject string, expiresAt time.Time, scopes string, err error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT status, COALESCE(subject, ''), expires_at, COALESCE(scopes, '')
		 FROM device_codes WHERE device_code = ?`,
		deviceCode,
	)

	var expiresAtStr string
	if scanErr := row.Scan(&status, &subject, &expiresAtStr, &scopes); scanErr != nil {
		if scanErr == sql.ErrNoRows {
			return "", "", time.Time{}, "", fosite.ErrNotFound
		}
		return "", "", time.Time{}, "", fmt.Errorf("storage: GetDeviceCodeStatusFull: %w", scanErr)
	}

	expiresAt, parseErr := time.Parse(time.RFC3339, expiresAtStr)
	if parseErr != nil {
		return "", "", time.Time{}, "", fmt.Errorf("storage: GetDeviceCodeStatusFull: parse expires_at %q: %w", expiresAtStr, parseErr)
	}

	return status, subject, expiresAt, scopes, nil
}

// CreateDeviceCodeSession persists a new device-code session.
// fosite calls this when the device initiates the Device Authorization Grant
// (RFC 8628 §3.2).  The user_code is stored in the same row as a placeholder
// because the user_code is registered separately via CreateDeviceUserCodeSession.
func (s *Store) CreateDeviceCodeSession(ctx context.Context, deviceCode string, req fosite.Requester) error {
	requestData, err := marshalRequester(req)
	if err != nil {
		return fmt.Errorf("storage: CreateDeviceCodeSession marshal: %w", err)
	}

	expiresAt := req.GetRequestedAt().Add(10 * time.Minute).UTC().Format(time.RFC3339)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO device_codes
		   (device_code, user_code, client_id, scopes, expires_at, status, subject, request_data)
		 VALUES (?, ?, ?, ?, ?, 'pending', '', ?)`,
		deviceCode,
		"__dc_placeholder_"+deviceCode,
		req.GetClient().GetID(),
		strings.Join(req.GetGrantedScopes(), " "),
		expiresAt,
		requestData,
	)
	if err != nil {
		return fmt.Errorf("storage: CreateDeviceCodeSession insert: %w", err)
	}
	return nil
}

// GetDeviceCodeSession retrieves the Requester stored for the given device_code.
// Returns fosite.ErrNotFound when no active (non-invalidated) session exists.
func (s *Store) GetDeviceCodeSession(ctx context.Context, deviceCode string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, request_data, status FROM device_codes WHERE device_code = ?`,
		deviceCode,
	)

	var (
		clientID    string
		requestData string
		status      string
	)
	if err := row.Scan(&clientID, &requestData, &status); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetDeviceCodeSession scan: %w", err)
	}

	if status == "invalidated" {
		return nil, fosite.ErrNotFound
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("storage: GetDeviceCodeSession get client: %w", err)
	}

	return unmarshalRequester(requestData, session, client)
}

// InvalidateDeviceCodeSession marks the device_code row as invalidated so
// that subsequent GetDeviceCodeSession calls return fosite.ErrNotFound.
// RFC 8628 §3.5: after an access token is issued the device_code is consumed.
func (s *Store) InvalidateDeviceCodeSession(ctx context.Context, deviceCode string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_codes SET status = 'invalidated' WHERE device_code = ?`,
		deviceCode,
	)
	return err
}

// CreateDeviceUserCodeSession stores the request data keyed by user_code.
// fosite calls this alongside CreateDeviceCodeSession so the short user_code
// can be looked up independently when the user visits /device/verify.
func (s *Store) CreateDeviceUserCodeSession(ctx context.Context, userCode string, req fosite.Requester) error {
	requestData, err := marshalRequester(req)
	if err != nil {
		return fmt.Errorf("storage: CreateDeviceUserCodeSession marshal: %w", err)
	}

	expiresAt := req.GetRequestedAt().Add(10 * time.Minute).UTC().Format(time.RFC3339)

	// Use a deterministic placeholder device_code derived from the user_code so
	// this row can co-exist with the real device_code row without a collision.
	placeholderDeviceCode := "__uc_row_" + userCode

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO device_codes
		   (device_code, user_code, client_id, scopes, expires_at, status, subject, request_data)
		 VALUES (?, ?, ?, ?, ?, 'pending', '', ?)`,
		placeholderDeviceCode,
		userCode,
		req.GetClient().GetID(),
		strings.Join(req.GetGrantedScopes(), " "),
		expiresAt,
		requestData,
	)
	if err != nil {
		return fmt.Errorf("storage: CreateDeviceUserCodeSession insert: %w", err)
	}
	return nil
}

// GetDeviceUserCodeSession retrieves the Requester stored for the given user_code.
// Returns fosite.ErrNotFound when no active session exists for the code.
func (s *Store) GetDeviceUserCodeSession(ctx context.Context, userCode string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, request_data, status FROM device_codes WHERE user_code = ?`,
		userCode,
	)

	var (
		clientID    string
		requestData string
		status      string
	)
	if err := row.Scan(&clientID, &requestData, &status); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetDeviceUserCodeSession scan: %w", err)
	}

	if status == "invalidated" {
		return nil, fosite.ErrNotFound
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("storage: GetDeviceUserCodeSession get client: %w", err)
	}

	return unmarshalRequester(requestData, session, client)
}

// InvalidateDeviceUserCodeSession marks the user_code row as invalidated.
// Subsequent GetDeviceUserCodeSession calls will return fosite.ErrNotFound.
func (s *Store) InvalidateDeviceUserCodeSession(ctx context.Context, userCode string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_codes SET status = 'invalidated' WHERE user_code = ?`,
		userCode,
	)
	return err
}

// UpdateDeviceCodeSessionByDeviceCode transitions the device_code row to the
// given status ("approved" or "denied") and optionally sets the subject.
// Called from POST /device/verify when the user approves or denies the request.
func (s *Store) UpdateDeviceCodeSessionByDeviceCode(ctx context.Context, deviceCode, subject, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_codes SET status = ?, subject = ? WHERE device_code = ?`,
		status, subject, deviceCode,
	)
	return err
}

// GetDeviceCodeByUserCode looks up the device_code for the given user_code.
// Used by POST /device/verify to find the device session before updating its
// status.  Returns fosite.ErrNotFound when no row exists for the user_code.
func (s *Store) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (string, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT device_code FROM device_codes WHERE user_code = ?`,
		userCode,
	)

	var deviceCode string
	if err := row.Scan(&deviceCode); err != nil {
		if err == sql.ErrNoRows {
			return "", fosite.ErrNotFound
		}
		return "", fmt.Errorf("storage: GetDeviceCodeByUserCode scan: %w", err)
	}

	return deviceCode, nil
}
