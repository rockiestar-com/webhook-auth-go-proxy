package main

import (
	"net/http"
	"net/http/httptest"

	"testing"
	"time"
)

func TestCodeGenerationAndVerification(t *testing.T) {
	// clear map
	codesMu.Lock()
	pendingCodes = make(map[string]time.Time)
	codesMu.Unlock()

	code, err := generateCode()
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected 6 digit code, got %s", code)
	}

	if !verifyCode(code) {
		t.Error("Code should be valid immediately after generation")
	}

	if verifyCode(code) {
		t.Error("Code should be one-time use")
	}
}

func TestCodeExpiry(t *testing.T) {
	// clear map
	codesMu.Lock()
	pendingCodes = make(map[string]time.Time)
	codesMu.Unlock()

	code := "123456"
	codesMu.Lock()
	// Set expiry in the past
	pendingCodes[code] = time.Now().Add(-1 * time.Minute)
	codesMu.Unlock()

	if verifyCode(code) {
		t.Error("Expired code should not be valid")
	}
}

func TestSession(t *testing.T) {
	// Ensure session key is initialized
	if len(sessionKey) == 0 {
		sessionKey = []byte("test-key-32-bytes-long-exactly!!")
	}

	w := httptest.NewRecorder()
	setSessionCookie(w)

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

	if !validateSession(req) {
		t.Error("Session should be valid with the cookie we just set")
	}
}

func TestInvalidSession(t *testing.T) {
	sessionKey = []byte("test-key-32-bytes-long-exactly!!")

	req := httptest.NewRequest("GET", "/", nil)
	// No cookie
	if validateSession(req) {
		t.Error("Should not validate request without cookie")
	}

	// Invalid cookie
	req.AddCookie(&http.Cookie{
		Name:  cookieName,
		Value: "invalid.signature",
	})
	if validateSession(req) {
		t.Error("Should not validate request with invalid cookie data")
	}
}

func TestHealthCheck(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()

	handleHealth(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestAuthMiddlewareRedirect(t *testing.T) {
	// Setup middleware
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Request without session
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected redirect (302), got %d", resp.StatusCode)
	}

	loc, _ := resp.Location()
	if loc.Path != "/login" {
		t.Errorf("Expected redirect to /login, got %s", loc.Path)
	}
}

func TestSendCodeRateLimit(t *testing.T) {
	// Note: The current implementation doesn't have rate limiting logic in the code provided,
	// but if we were to test it, it would go here.
	// For now, we test that the handler accepts POST and rejects GET.

	// 1. Test GET (Method Not Allowed)
	req := httptest.NewRequest("GET", "/send-code", nil)
	w := httptest.NewRecorder()
	handleSendCode(w, req)
	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed for GET, got %d", w.Result().StatusCode)
	}

	// 2. Test POST (Success - assuming config is set)
	// We need to mock the config or be okay with it failing to actually send to Discord (it logs error but returns 200 usually)
	// However, verifyCode logic runs inside handleSendCode.

	// Set dummy config
	config.DiscordWebhookURL = "http://localhost:9999/webhook" // Dummy URL

	req = httptest.NewRequest("POST", "/send-code", nil)
	req.Host = "example.com"
	w = httptest.NewRecorder()

	handleSendCode(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Result().StatusCode)
	}

	// Check if a code was actually generated in the map
	codesMu.Lock()
	count := len(pendingCodes)
	codesMu.Unlock()

	if count == 0 {
		t.Error("Expected a pending code to be generated")
	}
}
