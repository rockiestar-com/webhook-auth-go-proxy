package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"webhook-auth-proxy/internal/auth"
	"webhook-auth-proxy/internal/config"
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
	}

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
