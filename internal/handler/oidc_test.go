package handler_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/handler"
)

// ---------------------------------------------------------------------------
// TestOIDCDiscoveryHandler_ReturnsOK — HTTP 200 반환
// ---------------------------------------------------------------------------

func TestOIDCDiscoveryHandler_ReturnsOK(t *testing.T) {
	// Arrange
	issuer := "https://auth.test.local"
	h := handler.NewOIDCDiscoveryHandler(issuer)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	// Act
	h(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	// Assert
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// TestOIDCDiscoveryHandler_ReturnsJSON — Content-Type: application/json
// ---------------------------------------------------------------------------

func TestOIDCDiscoveryHandler_ReturnsJSON(t *testing.T) {
	// Arrange
	issuer := "https://auth.test.local"
	h := handler.NewOIDCDiscoveryHandler(issuer)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	// Act
	h(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	// Assert
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want it to contain %q", ct, "application/json")
	}
}

// ---------------------------------------------------------------------------
// TestOIDCDiscoveryHandler_ContainsRequiredFields — 필수 OIDC 필드 포함
// ---------------------------------------------------------------------------

func TestOIDCDiscoveryHandler_ContainsRequiredFields(t *testing.T) {
	// Arrange
	issuer := "https://auth.test.local"
	h := handler.NewOIDCDiscoveryHandler(issuer)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	// Act
	h(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v — body: %s", err, body)
	}

	// Assert — OIDC Discovery 1.0 필수 문자열 필드
	requiredStringFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
	}
	for _, field := range requiredStringFields {
		val, ok := doc[field]
		if !ok {
			t.Errorf("response body missing required field %q", field)
			continue
		}
		s, ok := val.(string)
		if !ok || s == "" {
			t.Errorf("field %q = %v, want a non-empty string", field, val)
		}
	}

	// Assert — OIDC Discovery 1.0 필수 배열 필드
	requiredArrayFields := []string{
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	}
	for _, field := range requiredArrayFields {
		val, ok := doc[field]
		if !ok {
			t.Errorf("response body missing required array field %q", field)
			continue
		}
		arr, ok := val.([]interface{})
		if !ok {
			t.Errorf("field %q is not an array, got %T", field, val)
			continue
		}
		if len(arr) == 0 {
			t.Errorf("field %q is an empty array, want at least one element", field)
		}
	}
}

// ---------------------------------------------------------------------------
// TestOIDCDiscoveryHandler_IssuerMatchesConfig — issuer 필드가 설정값과 일치
// ---------------------------------------------------------------------------

func TestOIDCDiscoveryHandler_IssuerMatchesConfig(t *testing.T) {
	// Arrange
	issuer := "https://auth.example.com"
	h := handler.NewOIDCDiscoveryHandler(issuer)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	// Act
	h(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Assert — issuer 필드는 핸들러에 주입된 값과 정확히 일치해야 한다
	gotIssuer, ok := doc["issuer"].(string)
	if !ok {
		t.Fatal("issuer field is missing or not a string")
	}
	if gotIssuer != issuer {
		t.Errorf("issuer = %q, want %q", gotIssuer, issuer)
	}
}

// ---------------------------------------------------------------------------
// TestOIDCDiscoveryHandler_JwksURIIsValid — jwks_uri가 유효한 URL
// ---------------------------------------------------------------------------

func TestOIDCDiscoveryHandler_JwksURIIsValid(t *testing.T) {
	// Arrange
	issuer := "https://auth.test.local"
	h := handler.NewOIDCDiscoveryHandler(issuer)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	// Act
	h(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Assert — jwks_uri는 http 또는 https 스킴을 가진 절대 URL이어야 한다
	jwksURI, ok := doc["jwks_uri"].(string)
	if !ok || jwksURI == "" {
		t.Fatal("jwks_uri field is missing or not a non-empty string")
	}
	if !strings.HasPrefix(jwksURI, "http://") && !strings.HasPrefix(jwksURI, "https://") {
		t.Errorf("jwks_uri = %q, want an absolute URL starting with http:// or https://", jwksURI)
	}
}
