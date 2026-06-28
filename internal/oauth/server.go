package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sync"
	"time"
)

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"

	AuthRequestTTL  = 5 * time.Minute
	AuthCodeTTL     = 60 * time.Second
	AccessTokenTTL  = 24 * time.Hour
	RefreshTokenTTL = 30 * 24 * time.Hour
)

type Client struct {
	ID                      string   `json:"client_id"`
	Name                    string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	IssuedAt                int64    `json:"client_id_issued_at"`
}

type AuthRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Resource            string
	CSRFToken           string
	Status              string
	AuthCode            string
	ClientName          string
	ClientIP            string
	Country             string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

type authCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Scope         string
	ExpiresAt     time.Time
}

type accessToken struct {
	Token    string
	ClientID string
	Scope    string
	Expires  time.Time
}

type refreshToken struct {
	Token       string
	ClientID    string
	Scope       string
	AccessToken string
	Expires     time.Time
}

type Server struct {
	mu            sync.RWMutex
	clients       map[string]*Client
	authRequests  map[string]*AuthRequest
	authCodes     map[string]*authCode
	accessTokens  map[string]*accessToken
	refreshTokens map[string]*refreshToken
	cleanupTicker *time.Ticker
}

func NewServer() *Server {
	s := &Server{
		clients:       make(map[string]*Client),
		authRequests:  make(map[string]*AuthRequest),
		authCodes:     make(map[string]*authCode),
		accessTokens:  make(map[string]*accessToken),
		refreshTokens: make(map[string]*refreshToken),
		cleanupTicker: time.NewTicker(5 * time.Minute),
	}
	go s.cleanupLoop()
	return s
}

func (s *Server) RegisterClient(name string, redirectURIs, grantTypes, responseTypes []string) (*Client, error) {
	for _, uri := range redirectURIs {
		parsed, err := url.Parse(uri)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect_uri: %s", uri)
		}
		host := parsed.Hostname()
		if !isLoopback(host) && parsed.Scheme != "https" {
			return nil, fmt.Errorf("non-loopback redirect_uri must use https: %s", uri)
		}
	}

	id, err := generateRandomHex(16)
	if err != nil {
		return nil, err
	}

	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	client := &Client{
		ID:                      "mcp_" + id,
		Name:                    name,
		RedirectURIs:            redirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: "none",
		IssuedAt:                time.Now().Unix(),
	}

	s.mu.Lock()
	s.clients[client.ID] = client
	s.mu.Unlock()

	return client, nil
}

func (s *Server) GetClient(clientID string) *Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients[clientID]
}

func (s *Server) CreateAuthRequest(clientID, redirectURI, state, codeChallenge, codeChallengeMethod, scope, resource, clientIP, country string) (*AuthRequest, error) {
	client := s.GetClient(clientID)
	if client == nil {
		return nil, fmt.Errorf("unknown client_id")
	}
	if !s.validateRedirectURI(client, redirectURI) {
		return nil, fmt.Errorf("invalid redirect_uri")
	}
	if codeChallenge == "" {
		return nil, fmt.Errorf("code_challenge is required (PKCE)")
	}
	if codeChallengeMethod != "S256" {
		return nil, fmt.Errorf("only S256 code_challenge_method is supported")
	}

	reqID, err := generateRandomHex(16)
	if err != nil {
		return nil, err
	}
	csrfToken, err := generateRandomHex(16)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	req := &AuthRequest{
		ID:                  reqID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scope:               scope,
		Resource:            resource,
		CSRFToken:           csrfToken,
		Status:              StatusPending,
		ClientName:          client.Name,
		ClientIP:            clientIP,
		Country:             country,
		CreatedAt:           now,
		ExpiresAt:           now.Add(AuthRequestTTL),
	}

	s.mu.Lock()
	s.authRequests[reqID] = req
	s.mu.Unlock()

	return req, nil
}

func (s *Server) GetAuthRequest(requestID string) *AuthRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req := s.authRequests[requestID]
	if req == nil {
		return nil
	}
	if time.Now().After(req.ExpiresAt) {
		return nil
	}
	copy := *req
	return &copy
}

func (s *Server) GetAuthRequestStatus(requestID string) (status string, redirectURL string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req := s.authRequests[requestID]
	if req == nil {
		return StatusExpired, ""
	}
	if time.Now().After(req.ExpiresAt) {
		return StatusExpired, ""
	}
	if req.Status == StatusApproved && req.AuthCode != "" {
		u, err := url.Parse(req.RedirectURI)
		if err != nil {
			return StatusApproved, ""
		}
		q := u.Query()
		q.Set("code", req.AuthCode)
		if req.State != "" {
			q.Set("state", req.State)
		}
		u.RawQuery = q.Encode()
		return StatusApproved, u.String()
	}
	return req.Status, ""
}

func (s *Server) ApproveAuthRequest(requestID, csrfToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req := s.authRequests[requestID]
	if req == nil {
		return fmt.Errorf("unknown request")
	}
	if time.Now().After(req.ExpiresAt) {
		return fmt.Errorf("request expired")
	}
	if req.Status != StatusPending {
		return fmt.Errorf("request already %s", req.Status)
	}
	if req.CSRFToken != csrfToken {
		return fmt.Errorf("invalid CSRF token")
	}

	code, err := generateRandomHex(32)
	if err != nil {
		return fmt.Errorf("failed to generate auth code: %w", err)
	}

	req.Status = StatusApproved
	req.AuthCode = code

	now := time.Now()
	s.authCodes[code] = &authCode{
		Code:          code,
		ClientID:      req.ClientID,
		RedirectURI:   req.RedirectURI,
		CodeChallenge: req.CodeChallenge,
		Scope:         req.Scope,
		ExpiresAt:     now.Add(AuthCodeTTL),
	}

	return nil
}

func (s *Server) DenyAuthRequest(requestID, csrfToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req := s.authRequests[requestID]
	if req == nil {
		return fmt.Errorf("unknown request")
	}
	if req.CSRFToken != csrfToken {
		return fmt.Errorf("invalid CSRF token")
	}
	if req.Status != StatusPending {
		return fmt.Errorf("request already %s", req.Status)
	}

	req.Status = StatusDenied
	return nil
}

func (s *Server) ExchangeCode(code, clientID, redirectURI, codeVerifier string) (string, string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ac := s.authCodes[code]
	if ac == nil {
		return "", "", 0, fmt.Errorf("invalid authorization code")
	}
	if time.Now().After(ac.ExpiresAt) {
		delete(s.authCodes, code)
		return "", "", 0, fmt.Errorf("authorization code expired")
	}
	if ac.ClientID != clientID {
		return "", "", 0, fmt.Errorf("client_id mismatch")
	}
	if !matchRedirectURI(ac.RedirectURI, redirectURI) {
		return "", "", 0, fmt.Errorf("redirect_uri mismatch")
	}
	if !verifyPKCE(codeVerifier, ac.CodeChallenge) {
		return "", "", 0, fmt.Errorf("PKCE verification failed")
	}

	delete(s.authCodes, code)

	atStr, err := generateRandomHex(32)
	if err != nil {
		return "", "", 0, err
	}
	atStr = "oat_" + atStr

	rtStr, err := generateRandomHex(32)
	if err != nil {
		return "", "", 0, err
	}
	rtStr = "ort_" + rtStr

	now := time.Now()
	expiresIn := int(AccessTokenTTL.Seconds())

	s.accessTokens[atStr] = &accessToken{
		Token:    atStr,
		ClientID: clientID,
		Scope:    ac.Scope,
		Expires:  now.Add(AccessTokenTTL),
	}

	s.refreshTokens[rtStr] = &refreshToken{
		Token:       rtStr,
		ClientID:    clientID,
		Scope:       ac.Scope,
		AccessToken: atStr,
		Expires:     now.Add(RefreshTokenTTL),
	}

	return atStr, rtStr, expiresIn, nil
}

func (s *Server) RefreshAccessToken(token, clientID string) (string, string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rt := s.refreshTokens[token]
	if rt == nil {
		return "", "", 0, fmt.Errorf("invalid refresh token")
	}
	if time.Now().After(rt.Expires) {
		delete(s.refreshTokens, token)
		return "", "", 0, fmt.Errorf("refresh token expired")
	}
	if rt.ClientID != clientID {
		return "", "", 0, fmt.Errorf("client_id mismatch")
	}

	delete(s.accessTokens, rt.AccessToken)
	delete(s.refreshTokens, token)

	atStr, err := generateRandomHex(32)
	if err != nil {
		return "", "", 0, err
	}
	atStr = "oat_" + atStr

	rtStr, err := generateRandomHex(32)
	if err != nil {
		return "", "", 0, err
	}
	rtStr = "ort_" + rtStr

	now := time.Now()
	expiresIn := int(AccessTokenTTL.Seconds())

	s.accessTokens[atStr] = &accessToken{
		Token:    atStr,
		ClientID: clientID,
		Scope:    rt.Scope,
		Expires:  now.Add(AccessTokenTTL),
	}

	s.refreshTokens[rtStr] = &refreshToken{
		Token:       rtStr,
		ClientID:    clientID,
		Scope:       rt.Scope,
		AccessToken: atStr,
		Expires:     now.Add(RefreshTokenTTL),
	}

	return atStr, rtStr, expiresIn, nil
}

func (s *Server) ValidateAccessToken(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	at := s.accessTokens[token]
	if at == nil {
		return false
	}
	return !time.Now().After(at.Expires)
}

func (s *Server) RevokeToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if at, ok := s.accessTokens[token]; ok {
		delete(s.accessTokens, token)
		for k, rt := range s.refreshTokens {
			if rt.AccessToken == at.Token {
				delete(s.refreshTokens, k)
				break
			}
		}
		return
	}

	if rt, ok := s.refreshTokens[token]; ok {
		delete(s.refreshTokens, token)
		delete(s.accessTokens, rt.AccessToken)
	}
}

func (s *Server) validateRedirectURI(client *Client, uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	for _, registered := range client.RedirectURIs {
		regParsed, err := url.Parse(registered)
		if err != nil {
			continue
		}
		// RFC 8252: for loopback, ignore port
		if isLoopback(parsed.Hostname()) && isLoopback(regParsed.Hostname()) {
			if parsed.Path == regParsed.Path {
				return true
			}
		}
		if uri == registered {
			return true
		}
	}
	return false
}

func (s *Server) cleanupLoop() {
	for range s.cleanupTicker.C {
		s.mu.Lock()
		now := time.Now()
		for k, v := range s.authRequests {
			if now.After(v.ExpiresAt) {
				delete(s.authRequests, k)
			}
		}
		for k, v := range s.authCodes {
			if now.After(v.ExpiresAt) {
				delete(s.authCodes, k)
			}
		}
		for k, v := range s.accessTokens {
			if now.After(v.Expires) {
				delete(s.accessTokens, k)
			}
		}
		for k, v := range s.refreshTokens {
			if now.After(v.Expires) {
				delete(s.refreshTokens, k)
			}
		}
		s.mu.Unlock()
	}
}

// -- Helpers --

func verifyPKCE(codeVerifier, codeChallenge string) bool {
	if codeVerifier == "" || codeChallenge == "" {
		return false
	}
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == codeChallenge
}

func matchRedirectURI(registered, provided string) bool {
	regParsed, err1 := url.Parse(registered)
	provParsed, err2 := url.Parse(provided)
	if err1 != nil || err2 != nil {
		return registered == provided
	}
	if isLoopback(regParsed.Hostname()) && isLoopback(provParsed.Hostname()) {
		return regParsed.Path == provParsed.Path
	}
	return registered == provided
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
}

func generateRandomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// -- Test helpers --

func (s *Server) ClearForTest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients = make(map[string]*Client)
	s.authRequests = make(map[string]*AuthRequest)
	s.authCodes = make(map[string]*authCode)
	s.accessTokens = make(map[string]*accessToken)
	s.refreshTokens = make(map[string]*refreshToken)
}

func (s *Server) AddAccessTokenForTest(token, clientID string, expires time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[token] = &accessToken{
		Token:    token,
		ClientID: clientID,
		Expires:  expires,
	}
}
