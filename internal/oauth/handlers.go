package oauth

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
)

//go:embed templates/waiting.html templates/approve.html
var templateFS embed.FS

type Handlers struct {
	Server     *Server
	WebhookURL string
	SendNotify func(webhookURL, clientName, approveLink, ip, country string) error
	templates  map[string]*template.Template
}

func NewHandlers(server *Server, webhookURL string, sendNotify func(string, string, string, string, string) error) *Handlers {
	waitingTmpl, err := template.ParseFS(templateFS, "templates/waiting.html")
	if err != nil {
		log.Fatalf("Failed to parse waiting template: %v", err)
	}
	approveTmpl, err := template.ParseFS(templateFS, "templates/approve.html")
	if err != nil {
		log.Fatalf("Failed to parse approve template: %v", err)
	}

	return &Handlers{
		Server:     server,
		WebhookURL: webhookURL,
		SendNotify: sendNotify,
		templates: map[string]*template.Template{
			"waiting": waitingTmpl,
			"approve": approveTmpl,
		},
	}
}

type approvePageData struct {
	RequestID  string
	CSRFToken  string
	ClientName string
	ClientIP   string
	Country    string
	CreatedAt  string
	Error      string
	Success    string
}

func (h *Handlers) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	baseURL := determineBaseURL(r)
	resp := map[string]interface{}{
		"resource":                 baseURL,
		"authorization_servers":    []string{baseURL},
		"bearer_methods_supported": []string{"header"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handlers) HandleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	baseURL := determineBaseURL(r)
	resp := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/oauth/authorize",
		"token_endpoint":                        baseURL + "/oauth/token",
		"registration_endpoint":                 baseURL + "/oauth/register",
		"revocation_endpoint":                   baseURL + "/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handlers) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		oauthError(w, "invalid_request", "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.RedirectURIs) == 0 {
		oauthError(w, "invalid_request", "redirect_uris is required", http.StatusBadRequest)
		return
	}

	name := req.ClientName
	if name == "" {
		name = "MCP Client"
	}

	client, err := h.Server.RegisterClient(name, req.RedirectURIs, req.GrantTypes, req.ResponseTypes)
	if err != nil {
		oauthError(w, "invalid_redirect_uri", err.Error(), http.StatusBadRequest)
		return
	}

	resp := map[string]interface{}{
		"client_id":                   client.ID,
		"client_name":                 client.Name,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"client_id_issued_at":        client.IssuedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (h *Handlers) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	scope := q.Get("scope")
	resource := q.Get("resource")

	if responseType != "code" {
		oauthError(w, "unsupported_response_type", "only response_type=code is supported", http.StatusBadRequest)
		return
	}

	clientIP := getClientIP(r)
	country := r.Header.Get("CF-IPCountry")

	authReq, err := h.Server.CreateAuthRequest(clientID, redirectURI, state, codeChallenge, codeChallengeMethod, scope, resource, clientIP, country)
	if err != nil {
		oauthError(w, "invalid_request", err.Error(), http.StatusBadRequest)
		return
	}

	baseURL := determineBaseURL(r)
	approveLink := fmt.Sprintf("%s/oauth/approve?request_id=%s", baseURL, authReq.ID)

	go func() {
		if err := h.SendNotify(h.WebhookURL, authReq.ClientName, approveLink, clientIP, country); err != nil {
			log.Printf("Failed to send MCP approval notification: %v", err)
		}
	}()

	statusURL := fmt.Sprintf("%s/oauth/status?request_id=%s", baseURL, authReq.ID)
	data := struct {
		RequestID string
		StatusURL string
	}{
		RequestID: authReq.ID,
		StatusURL: statusURL,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates["waiting"].Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *Handlers) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := r.URL.Query().Get("request_id")
	if requestID == "" {
		oauthError(w, "invalid_request", "request_id is required", http.StatusBadRequest)
		return
	}

	reqStatus, redirectURL := h.Server.GetAuthRequestStatus(requestID)

	resp := map[string]interface{}{
		"status": reqStatus,
	}
	if redirectURL != "" {
		resp["redirect_url"] = redirectURL
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handlers) HandleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		requestID := r.URL.Query().Get("request_id")
		if requestID == "" {
			h.renderApprove(w, approvePageData{Error: "Missing request_id parameter."})
			return
		}

		authReq := h.Server.GetAuthRequest(requestID)
		if authReq == nil {
			h.renderApprove(w, approvePageData{Error: "This approval request has expired or does not exist."})
			return
		}
		if authReq.Status != StatusPending {
			h.renderApprove(w, approvePageData{Error: fmt.Sprintf("This request has already been %s.", authReq.Status)})
			return
		}

		h.renderApprove(w, approvePageData{
			RequestID:  authReq.ID,
			CSRFToken:  authReq.CSRFToken,
			ClientName: authReq.ClientName,
			ClientIP:   authReq.ClientIP,
			Country:    authReq.Country,
			CreatedAt:  authReq.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		})
		return
	}

	if r.Method == http.MethodPost {
		requestID := r.FormValue("request_id")
		csrfToken := r.FormValue("csrf_token")
		action := r.FormValue("action")

		var err error
		var successMsg string

		switch action {
		case "approve":
			err = h.Server.ApproveAuthRequest(requestID, csrfToken)
			successMsg = "Access approved. The coding agent is now connected."
		case "deny":
			err = h.Server.DenyAuthRequest(requestID, csrfToken)
			successMsg = "Access denied. The coding agent was not connected."
		default:
			h.renderApprove(w, approvePageData{Error: "Invalid action."})
			return
		}

		if err != nil {
			h.renderApprove(w, approvePageData{Error: err.Error()})
			return
		}

		h.renderApprove(w, approvePageData{Success: successMsg})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (h *Handlers) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		code := r.FormValue("code")
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		codeVerifier := r.FormValue("code_verifier")

		at, rt, expiresIn, err := h.Server.ExchangeCode(code, clientID, redirectURI, codeVerifier)
		if err != nil {
			oauthError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
			return
		}

		resp := map[string]interface{}{
			"access_token":  at,
			"token_type":    "Bearer",
			"expires_in":    expiresIn,
			"refresh_token": rt,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(resp)

	case "refresh_token":
		refreshTokenStr := r.FormValue("refresh_token")
		clientID := r.FormValue("client_id")

		at, newRT, expiresIn, err := h.Server.RefreshAccessToken(refreshTokenStr, clientID)
		if err != nil {
			oauthError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
			return
		}

		resp := map[string]interface{}{
			"access_token":  at,
			"token_type":    "Bearer",
			"expires_in":    expiresIn,
			"refresh_token": newRT,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(resp)

	case "":
		oauthError(w, "invalid_request", "grant_type is required", http.StatusBadRequest)

	default:
		oauthError(w, "unsupported_grant_type", fmt.Sprintf("grant_type '%s' is not supported", grantType), http.StatusBadRequest)
	}
}

func (h *Handlers) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		oauthError(w, "invalid_request", "token is required", http.StatusBadRequest)
		return
	}

	h.Server.RevokeToken(token)
	w.WriteHeader(http.StatusOK)
}

// -- Helpers --

func (h *Handlers) renderApprove(w http.ResponseWriter, data approvePageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	if err := h.templates["approve"].Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func oauthError(w http.ResponseWriter, errorCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

func determineBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if cfVisitor := r.Header.Get("CF-Visitor"); cfVisitor != "" {
		if strings.Contains(cfVisitor, `"scheme":"https"`) {
			scheme = "https"
		}
	}
	host := r.Host
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		host = fh
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func getClientIP(r *http.Request) string {
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return cfIP
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}
