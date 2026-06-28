package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"webhook-auth-proxy/internal/auth"
	"webhook-auth-proxy/internal/config"
	"webhook-auth-proxy/internal/limiter"
	"webhook-auth-proxy/internal/oauth"
)

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

func TestAuthMiddlewareBearerToken(t *testing.T) {
	oauthSrv = oauth.NewServer()
	oauthSrv.AddAccessTokenForTest("oat_valid_test_token", "test_client", time.Now().Add(time.Hour))

	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied"))
	})

	// Valid Bearer token → 200
	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer oat_valid_test_token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("Expected 200 with valid Bearer, got %d", w.Result().StatusCode)
	}

	// Invalid Bearer token → 401 with WWW-Authenticate
	req = httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer invalid_token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 with invalid Bearer, got %d", w.Result().StatusCode)
	}
	wwwAuth := w.Result().Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("Expected WWW-Authenticate header on 401")
	}
}

func TestAuthMiddlewareAPIClient401(t *testing.T) {
	oauthSrv = oauth.NewServer()

	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// No auth + Accept: application/json → 401 (not redirect)
	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for API client, got %d", w.Result().StatusCode)
	}
}

func TestAuthMiddlewareBrowserRedirectPreserved(t *testing.T) {
	oauthSrv = oauth.NewServer()

	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// No auth + no headers (browser default) → redirect to /login
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusFound {
		t.Errorf("Expected 302 redirect for browser, got %d", w.Result().StatusCode)
	}
	loc, _ := w.Result().Location()
	if loc.Path != "/login" {
		t.Errorf("Expected redirect to /login, got %s", loc.Path)
	}

	// No auth + Accept: text/html → redirect to /login
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusFound {
		t.Errorf("Expected 302 for text/html accept, got %d", w.Result().StatusCode)
	}

	// No auth + Accept: */* (browser sub-resource) → redirect to /login (not 401)
	req = httptest.NewRequest("GET", "/style.css", nil)
	req.Header.Set("Accept", "*/*")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusFound {
		t.Errorf("Expected 302 for Accept: */* (browser sub-resource), got %d", w.Result().StatusCode)
	}
}

func TestSendCodeRateLimit(t *testing.T) {
	// 1. Test GET (Method Not Allowed)
	req := httptest.NewRequest("GET", "/send-code", nil)
	w := httptest.NewRecorder()
	handleSendCode(w, req)
	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed for GET, got %d", w.Result().StatusCode)
	}

	// 2. Test POST (Success)
	// We need to set dummy config
	cfg = &config.Config{
		DiscordWebhookURL: "http://localhost:9999/webhook", // Dummy URL
		RateLimitPerHour:  100,
	}

	// Initialize rate limiter
	rateLimiter = limiter.New(cfg.RateLimitPerHour, time.Hour)

	// Reset auth state
	auth.ClearCodesForTest()

	req = httptest.NewRequest("POST", "/send-code", nil)
	req.Host = "example.com"
	w = httptest.NewRecorder()

	handleSendCode(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Result().StatusCode)
	}
}
