package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if !verifyPKCE(verifier, challenge) {
		t.Error("expected PKCE verification to succeed")
	}
	if verifyPKCE("wrong-verifier", challenge) {
		t.Error("expected PKCE verification to fail with wrong verifier")
	}
	if verifyPKCE("", challenge) {
		t.Error("expected PKCE verification to fail with empty verifier")
	}
	if verifyPKCE(verifier, "") {
		t.Error("expected PKCE verification to fail with empty challenge")
	}
}

func TestClientRegistration(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	client, err := s.RegisterClient("Test Client", []string{"http://localhost/callback"}, nil, nil)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	if client.Name != "Test Client" {
		t.Errorf("expected name 'Test Client', got '%s'", client.Name)
	}
	if client.TokenEndpointAuthMethod != "none" {
		t.Errorf("expected auth method 'none', got '%s'", client.TokenEndpointAuthMethod)
	}

	got := s.GetClient(client.ID)
	if got == nil {
		t.Fatal("GetClient returned nil")
	}
	if got.ID != client.ID {
		t.Errorf("client ID mismatch")
	}
}

func TestClientRegistrationRejectsHTTPNonLoopback(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	_, err := s.RegisterClient("Bad", []string{"http://example.com/callback"}, nil, nil)
	if err == nil {
		t.Error("expected error for non-loopback HTTP redirect_uri")
	}
}

func TestClientRegistrationAcceptsLoopbackVariants(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	for _, uri := range []string{
		"http://localhost/callback",
		"http://localhost:8080/callback",
		"http://127.0.0.1/callback",
		"http://127.0.0.1:54321/callback",
		"http://[::1]/callback",
	} {
		_, err := s.RegisterClient("Test", []string{uri}, nil, nil)
		if err != nil {
			t.Errorf("expected loopback URI %q to be accepted, got error: %v", uri, err)
		}
	}
}

func TestAuthRequestLifecycle(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	client, _ := s.RegisterClient("Agent", []string{"http://localhost/callback"}, nil, nil)

	verifier := "test-verifier-string-for-pkce-challenge-1234567"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authReq, err := s.CreateAuthRequest(client.ID, "http://localhost:9999/callback", "state123", challenge, "S256", "", "", "1.2.3.4", "US")
	if err != nil {
		t.Fatalf("CreateAuthRequest failed: %v", err)
	}
	if authReq.Status != StatusPending {
		t.Errorf("expected pending, got %s", authReq.Status)
	}

	// Status should be pending
	status, _ := s.GetAuthRequestStatus(authReq.ID)
	if status != StatusPending {
		t.Errorf("expected pending status, got %s", status)
	}

	// Wrong CSRF should fail
	if err := s.ApproveAuthRequest(authReq.ID, "wrong-csrf"); err == nil {
		t.Error("expected error for wrong CSRF token")
	}

	// Correct approval
	if err := s.ApproveAuthRequest(authReq.ID, authReq.CSRFToken); err != nil {
		t.Fatalf("ApproveAuthRequest failed: %v", err)
	}

	// Should be approved with redirect URL
	status, redirectURL := s.GetAuthRequestStatus(authReq.ID)
	if status != StatusApproved {
		t.Errorf("expected approved status, got %s", status)
	}
	if redirectURL == "" {
		t.Error("expected redirect URL after approval")
	}

	// Double approval should fail
	if err := s.ApproveAuthRequest(authReq.ID, authReq.CSRFToken); err == nil {
		t.Error("expected error for double approval")
	}
}

func TestDenyAuthRequest(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	client, _ := s.RegisterClient("Agent", []string{"http://localhost/callback"}, nil, nil)

	h := sha256.Sum256([]byte("verifier"))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authReq, _ := s.CreateAuthRequest(client.ID, "http://localhost:9999/callback", "state", challenge, "S256", "", "", "1.2.3.4", "")

	if err := s.DenyAuthRequest(authReq.ID, authReq.CSRFToken); err != nil {
		t.Fatalf("DenyAuthRequest failed: %v", err)
	}

	status, _ := s.GetAuthRequestStatus(authReq.ID)
	if status != StatusDenied {
		t.Errorf("expected denied status, got %s", status)
	}
}

func TestCodeExchangeWithPKCE(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	client, _ := s.RegisterClient("Agent", []string{"http://localhost/callback"}, nil, nil)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	redirectURI := "http://localhost:9999/callback"
	authReq, _ := s.CreateAuthRequest(client.ID, redirectURI, "state", challenge, "S256", "", "", "1.2.3.4", "")
	s.ApproveAuthRequest(authReq.ID, authReq.CSRFToken)

	// Wrong verifier should fail
	_, _, _, err := s.ExchangeCode(authReq.AuthCode, client.ID, redirectURI, "wrong-verifier")
	if err == nil {
		t.Error("expected error for wrong PKCE verifier")
	}

	// Need a new approval since the code was NOT consumed (PKCE failed before consumption)
	// Actually, the code IS consumed on first attempt — let's create a new flow
	authReq2, _ := s.CreateAuthRequest(client.ID, redirectURI, "state2", challenge, "S256", "", "", "1.2.3.4", "")
	s.ApproveAuthRequest(authReq2.ID, authReq2.CSRFToken)

	at, rt, expiresIn, err := s.ExchangeCode(authReq2.AuthCode, client.ID, redirectURI, verifier)
	if err != nil {
		t.Fatalf("ExchangeCode failed: %v", err)
	}
	if at == "" || rt == "" {
		t.Error("expected non-empty tokens")
	}
	if expiresIn <= 0 {
		t.Error("expected positive expires_in")
	}
	if !s.ValidateAccessToken(at) {
		t.Error("access token should be valid")
	}

	// Code should be consumed (one-time use)
	_, _, _, err = s.ExchangeCode(authReq2.AuthCode, client.ID, redirectURI, verifier)
	if err == nil {
		t.Error("expected error for reused auth code")
	}
}

func TestTokenRefresh(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	client, _ := s.RegisterClient("Agent", []string{"http://localhost/callback"}, nil, nil)

	verifier := "test-verifier-for-refresh-test-1234567890abcdef"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	redirectURI := "http://localhost:9999/callback"
	authReq, _ := s.CreateAuthRequest(client.ID, redirectURI, "state", challenge, "S256", "", "", "1.2.3.4", "")
	s.ApproveAuthRequest(authReq.ID, authReq.CSRFToken)

	oldAT, oldRT, _, _ := s.ExchangeCode(authReq.AuthCode, client.ID, redirectURI, verifier)

	// Refresh
	newAT, newRT, _, err := s.RefreshAccessToken(oldRT, client.ID)
	if err != nil {
		t.Fatalf("RefreshAccessToken failed: %v", err)
	}
	if newAT == oldAT {
		t.Error("expected new access token")
	}
	if newRT == oldRT {
		t.Error("expected new refresh token (rotation)")
	}

	// Old tokens should be invalid
	if s.ValidateAccessToken(oldAT) {
		t.Error("old access token should be revoked")
	}

	// New token should be valid
	if !s.ValidateAccessToken(newAT) {
		t.Error("new access token should be valid")
	}

	// Old refresh token should not work
	_, _, _, err = s.RefreshAccessToken(oldRT, client.ID)
	if err == nil {
		t.Error("old refresh token should be rejected")
	}
}

func TestTokenRevocation(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	client, _ := s.RegisterClient("Agent", []string{"http://localhost/callback"}, nil, nil)

	verifier := "revocation-test-verifier-1234567890abcdef"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	redirectURI := "http://localhost:9999/callback"
	authReq, _ := s.CreateAuthRequest(client.ID, redirectURI, "state", challenge, "S256", "", "", "1.2.3.4", "")
	s.ApproveAuthRequest(authReq.ID, authReq.CSRFToken)

	at, _, _, _ := s.ExchangeCode(authReq.AuthCode, client.ID, redirectURI, verifier)

	if !s.ValidateAccessToken(at) {
		t.Fatal("token should be valid before revocation")
	}

	s.RevokeToken(at)

	if s.ValidateAccessToken(at) {
		t.Error("token should be invalid after revocation")
	}
}

func TestExpiredAuthRequest(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	client, _ := s.RegisterClient("Agent", []string{"http://localhost/callback"}, nil, nil)

	h := sha256.Sum256([]byte("verifier"))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authReq, _ := s.CreateAuthRequest(client.ID, "http://localhost:9999/callback", "state", challenge, "S256", "", "", "1.2.3.4", "")

	// Manually expire the request
	s.mu.Lock()
	s.authRequests[authReq.ID].ExpiresAt = time.Now().Add(-1 * time.Second)
	s.mu.Unlock()

	if got := s.GetAuthRequest(authReq.ID); got != nil {
		t.Error("expected nil for expired auth request")
	}

	status, _ := s.GetAuthRequestStatus(authReq.ID)
	if status != StatusExpired {
		t.Errorf("expected expired status, got %s", status)
	}
}

func TestLoopbackRedirectURIIgnoresPort(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	client, _ := s.RegisterClient("Agent", []string{"http://localhost/callback"}, nil, nil)

	verifier := "loopback-port-test-verifier-1234567890abcde"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Register with localhost/callback, but authorize with localhost:54321/callback
	authReq, err := s.CreateAuthRequest(client.ID, "http://localhost:54321/callback", "state", challenge, "S256", "", "", "1.2.3.4", "")
	if err != nil {
		t.Fatalf("should accept loopback with different port: %v", err)
	}

	s.ApproveAuthRequest(authReq.ID, authReq.CSRFToken)

	// Exchange should also work with the port variant
	_, _, _, err = s.ExchangeCode(authReq.AuthCode, client.ID, "http://localhost:54321/callback", verifier)
	if err != nil {
		t.Fatalf("code exchange should work with loopback port variant: %v", err)
	}
}

func TestAddAccessTokenForTest(t *testing.T) {
	s := NewServer()
	defer s.cleanupTicker.Stop()

	s.AddAccessTokenForTest("test_token_123", "client_1", time.Now().Add(time.Hour))
	if !s.ValidateAccessToken("test_token_123") {
		t.Error("test token should be valid")
	}

	s.AddAccessTokenForTest("expired_token", "client_1", time.Now().Add(-time.Second))
	if s.ValidateAccessToken("expired_token") {
		t.Error("expired test token should be invalid")
	}
}
