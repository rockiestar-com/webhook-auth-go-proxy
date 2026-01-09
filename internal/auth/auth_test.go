package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCodeGenerationAndVerification(t *testing.T) {
	ClearCodesForTest()

	// Test default 32 char
	code, err := GenerateCode(32)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	if len(code) != 32 {
		t.Errorf("Expected 32 character code, got %s (len=%d)", code, len(code))
	}

	// Test custom length
	code16, err := GenerateCode(16)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}
	if len(code16) != 16 {
		t.Errorf("Expected 16 character code, got %s (len=%d)", code16, len(code16))
	}

	if !VerifyCode(code) {
		t.Error("Code should be valid immediately after generation")
	}

	if VerifyCode(code) {
		t.Error("Code should be one-time use")
	}
}

func TestCodeExpiry(t *testing.T) {
	ClearCodesForTest()

	code := "123456"
	// Set expiry in the past
	AddCodeForTest(code, time.Now().Add(-1*time.Minute))

	if VerifyCode(code) {
		t.Error("Expired code should not be valid")
	}
}

func TestSession(t *testing.T) {
	// Ensure a key is set
	SetSessionKeyForTest([]byte("test-key-32-bytes-long-exactly!!"))

	w := httptest.NewRecorder()
	SetSessionCookie(w)

	resp := w.Result()
	cookies := resp.Cookies()

	if len(cookies) == 0 {
		t.Fatal("Expected cookie to be set")
	}

	authCookie := cookies[0]
	if authCookie.Name != cookieName {
		t.Errorf("Expected cookie name %s, got %s", cookieName, authCookie.Name)
	}

	// Create a request with this cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(authCookie)

	if !ValidateSession(req) {
		t.Error("Session should be valid with the cookie we just set")
	}
}

func TestInvalidSession(t *testing.T) {
	SetSessionKeyForTest([]byte("test-key-32-bytes-long-exactly!!"))

	req := httptest.NewRequest("GET", "/", nil)
	// No cookie
	if ValidateSession(req) {
		t.Error("Should not validate request without cookie")
	}

	// Invalid cookie
	req.AddCookie(&http.Cookie{
		Name:  cookieName,
		Value: "invalid.signature",
	})
	if ValidateSession(req) {
		t.Error("Should not validate request with invalid cookie data")
	}
}
