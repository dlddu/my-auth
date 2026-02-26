package handler_test

import (
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/handler"
	"github.com/dlddu/my-auth/internal/keygen"
)

// newTestRSAKey는 테스트에서 공유할 RSA 키를 생성하는 헬퍼 함수입니다.
// 키 생성은 비용이 크므로 여러 테스트에서 재사용합니다.
func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("keygen.GenerateRSAKeyPair(): %v", err)
	}
	return key
}

// ---------------------------------------------------------------------------
// TestJWKSHandler_ReturnsOK — HTTP 200 반환
// ---------------------------------------------------------------------------

func TestJWKSHandler_ReturnsOK(t *testing.T) {
	// Arrange
	key := newTestRSAKey(t)
	h := handler.NewJWKSHandler(key)
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
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
// TestJWKSHandler_ReturnsJSON — Content-Type: application/json
// ---------------------------------------------------------------------------

func TestJWKSHandler_ReturnsJSON(t *testing.T) {
	// Arrange
	key := newTestRSAKey(t)
	h := handler.NewJWKSHandler(key)
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
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
// TestJWKSHandler_ReturnsValidJWKSet — JWK Set 형식 ({"keys":[...]})
// ---------------------------------------------------------------------------

func TestJWKSHandler_ReturnsValidJWKSet(t *testing.T) {
	// Arrange
	key := newTestRSAKey(t)
	h := handler.NewJWKSHandler(key)
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	w := httptest.NewRecorder()

	// Act
	h(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	var jwkSet map[string]interface{}
	if err := json.Unmarshal(body, &jwkSet); err != nil {
		t.Fatalf("json.Unmarshal: %v — body: %s", err, body)
	}

	// Assert — RFC 7517 JWK Set는 최상위 "keys" 배열을 가져야 한다
	keysVal, ok := jwkSet["keys"]
	if !ok {
		t.Fatal("response body missing required field \"keys\"")
	}
	keys, ok := keysVal.([]interface{})
	if !ok {
		t.Fatalf("\"keys\" field is not an array, got %T", keysVal)
	}
	if len(keys) == 0 {
		t.Error("\"keys\" array is empty, want at least one JWK")
	}
}

// ---------------------------------------------------------------------------
// TestJWKSHandler_ContainsRSAPublicKey — RSA 공개키 존재
// ---------------------------------------------------------------------------

func TestJWKSHandler_ContainsRSAPublicKey(t *testing.T) {
	// Arrange
	key := newTestRSAKey(t)
	h := handler.NewJWKSHandler(key)
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	w := httptest.NewRecorder()

	// Act
	h(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	var jwkSet struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwkSet); err != nil {
		t.Fatalf("json.Unmarshal: %v — body: %s", err, body)
	}

	// Assert — keys 배열 안에 kty === "RSA" 인 키가 최소 한 개 이상 있어야 한다
	rsaKeyCount := 0
	for _, k := range jwkSet.Keys {
		if kty, _ := k["kty"].(string); kty == "RSA" {
			rsaKeyCount++
		}
	}
	if rsaKeyCount == 0 {
		t.Errorf("no RSA key found in JWKS (total keys: %d)", len(jwkSet.Keys))
	}
}

// ---------------------------------------------------------------------------
// TestJWKSHandler_RSAKeyHasRequiredPublicFields — JWT 검증에 필요한 필드 포함
// ---------------------------------------------------------------------------

func TestJWKSHandler_RSAKeyHasRequiredPublicFields(t *testing.T) {
	// Arrange
	key := newTestRSAKey(t)
	h := handler.NewJWKSHandler(key)
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	w := httptest.NewRecorder()

	// Act
	h(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	var jwkSet struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwkSet); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Assert — RSA 공개키는 JWT 라이브러리가 RS256 서명을 검증하기 위해
	// 필요한 모든 필드를 포함해야 한다 (RFC 7517, RFC 7518 §6.3)
	requiredFields := []string{"n", "e", "kty", "kid", "use", "alg"}
	for _, k := range jwkSet.Keys {
		kty, _ := k["kty"].(string)
		if kty != "RSA" {
			continue
		}
		for _, field := range requiredFields {
			val, ok := k[field]
			if !ok {
				t.Errorf("RSA JWK missing required field %q", field)
				continue
			}
			s, ok := val.(string)
			if !ok || s == "" {
				t.Errorf("RSA JWK field %q = %v, want a non-empty string", field, val)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// TestJWKSHandler_DoesNotExposePrivateKey — private key 미노출
// ---------------------------------------------------------------------------

func TestJWKSHandler_DoesNotExposePrivateKey(t *testing.T) {
	// Arrange
	key := newTestRSAKey(t)
	h := handler.NewJWKSHandler(key)
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	w := httptest.NewRecorder()

	// Act
	h(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	var jwkSet struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwkSet); err != nil {
		t.Fatalf("json.Unmarshal: %v — body: %s", err, body)
	}

	// Assert — RFC 7517 §9.3 보안 고려사항:
	// 공개 JWKS 엔드포인트에 RSA 개인키 컴포넌트가 노출되어서는 안 된다
	privateFields := []string{"d", "p", "q", "dp", "dq", "qi"}
	for _, k := range jwkSet.Keys {
		kid, _ := k["kid"].(string)
		for _, field := range privateFields {
			if _, found := k[field]; found {
				t.Errorf("RSA key (kid=%q) exposes private field %q — must not be present in public JWKS", kid, field)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// TestJWKSHandler_ModulusAndExponentAreBase64URL — n, e가 base64url 인코딩
// ---------------------------------------------------------------------------

func TestJWKSHandler_ModulusAndExponentAreBase64URL(t *testing.T) {
	// Arrange
	key := newTestRSAKey(t)
	h := handler.NewJWKSHandler(key)
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	w := httptest.NewRecorder()

	// Act
	h(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	var jwkSet struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwkSet); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Assert — n(modulus)과 e(exponent)는 base64url 인코딩된 non-empty 문자열이어야 한다
	// base64url 문자셋: A-Z a-z 0-9 - _  (패딩 없음, RFC 4648 §5)
	isBase64URL := func(s string) bool {
		if len(s) == 0 {
			return false
		}
		for _, c := range s {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		}
		return true
	}

	for _, k := range jwkSet.Keys {
		kty, _ := k["kty"].(string)
		if kty != "RSA" {
			continue
		}
		n, _ := k["n"].(string)
		if !isBase64URL(n) {
			t.Errorf("RSA JWK field \"n\" = %q, want a non-empty base64url string", n)
		}
		// 2048-bit 모듈러스는 base64url로 약 342자
		if len(n) < 10 {
			t.Errorf("RSA JWK field \"n\" length = %d, seems too short for a valid modulus", len(n))
		}
		e, _ := k["e"].(string)
		if !isBase64URL(e) {
			t.Errorf("RSA JWK field \"e\" = %q, want a non-empty base64url string", e)
		}
	}
}
