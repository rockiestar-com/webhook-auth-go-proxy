package main

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"webhook-auth-proxy/internal/auth"
	"webhook-auth-proxy/internal/config"
	"webhook-auth-proxy/internal/discord"
	"webhook-auth-proxy/internal/limiter"
	"webhook-auth-proxy/internal/oauth"
)

//go:embed templates/login.html
var templateFS embed.FS

// Global state
var (
	cfg         *config.Config
	proxy       *httputil.ReverseProxy
	rateLimiter *limiter.Limiter
	loginTmpl   *template.Template
	oauthSrv    *oauth.Server
	oauthH      *oauth.Handlers
)

func init() {
	cfg = config.LoadFromEnv()
}

func main() {
	// Parse template on startup
	var err error
	loginTmpl, err = template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		log.Fatalf("Failed to parse login template: %v", err)
	}

	// Validate essential config
	if cfg.UpstreamURL == "" {
		log.Fatal("UPSTREAM_URL environment variable is required")
	}
	if cfg.DiscordWebhookURL == "" {
		log.Fatal("DISCORD_WEBHOOK_URL environment variable is required")
	}

	targetURL, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("Invalid UPSTREAM_URL: %v", err)
	}

	// Initialize Proxy
	proxy = httputil.NewSingleHostReverseProxy(targetURL)
	// Preserve original director behavior but ensure host is set correctly if needed
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Set the Host header to the upstream host
		req.Host = targetURL.Host
		// Forwarded headers are good practice
		if _, ok := req.Header["X-Forwarded-Host"]; !ok {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}
		if _, ok := req.Header["X-Forwarded-Proto"]; !ok {
			req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)
		}
	}

	// Initialize OAuth 2.1 server for MCP clients
	oauthSrv = oauth.NewServer()
	oauthH = oauth.NewHandlers(oauthSrv, cfg.DiscordWebhookURL, discord.SendMCPApprovalNotification)

	mux := http.NewServeMux()

	// Health check (public)
	mux.HandleFunc("/api/v1/health", handleHealth)

	// Auth routes (public)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/send-code", handleSendCode)

	// OAuth 2.1 routes (public — CSRF-protected where needed)
	mux.HandleFunc("/.well-known/oauth-protected-resource", oauthH.HandleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", oauthH.HandleAuthServerMetadata)
	mux.HandleFunc("/oauth/register", oauthH.HandleRegister)
	mux.HandleFunc("/oauth/authorize", oauthH.HandleAuthorize)
	mux.HandleFunc("/oauth/status", oauthH.HandleStatus)
	mux.HandleFunc("/oauth/approve", oauthH.HandleApprove)
	mux.HandleFunc("/oauth/token", oauthH.HandleToken)
	mux.HandleFunc("/oauth/revoke", oauthH.HandleRevoke)

	// Catch-all (protected)
	mux.HandleFunc("/", authMiddleware(handleProxy))

	log.Printf("Starting proxy on port %s", cfg.Port)
	log.Printf("Upstream: %s", cfg.UpstreamURL)
	log.Printf("Session key generated (ephemeral)")
	log.Printf("Rate limit: %d requests per hour per IP", cfg.RateLimitPerHour)

	rateLimiter = limiter.New(cfg.RateLimitPerHour, 1*time.Hour)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}

// -- Handlers --

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Check if already logged in
		if auth.ValidateSession(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Render login page
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := loginTmpl.Execute(w, nil); err != nil {
			log.Printf("Template execution error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		code := r.FormValue("code")
		if auth.VerifyCode(code) {
			auth.SetSessionCookie(w)
			http.Redirect(w, r, "/", http.StatusFound)
		} else {
			http.Redirect(w, r, "/login?error=1", http.StatusFound)
		}
	}
}

func handleSendCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate Limit Check
	clientIP := getClientIP(r)
	if !rateLimiter.Allow(clientIP) {
		http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
		return
	}

	username := r.FormValue("username")
	if len(username) > 50 {
		username = username[:50] // Truncate long names
	}

	code, err := auth.GenerateCode(cfg.CodeLength)
	if err != nil {
		log.Printf("Error generating code: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Construct public URL
	publicURL := fmt.Sprintf("%s/login?code=%s", determineBaseURL(r), code)

	country := r.Header.Get("CF-IPCountry")

	go func() {
		if err := discord.SendNotification(cfg.DiscordWebhookURL, code, publicURL, username, clientIP, country); err != nil {
			log.Printf("Failed to send notification: %v", err)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Code sent"))
}

func determineBaseURL(r *http.Request) string {
	// Determine Scheme
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// X-Forwarded-Proto is standard for proxies (Cloudflare, Nginx, Traefik)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if cfVisitor := r.Header.Get("CF-Visitor"); cfVisitor != "" {
		// Fallback for Cloudflare if X-Forwarded-Proto is missing
		// CF-Visitor is JSON: {"scheme":"https"}
		if strings.Contains(cfVisitor, "\"scheme\":\"https\"") {
			scheme = "https"
		}
	}

	// Determine Host
	host := r.Host
	// X-Forwarded-Host is standard
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	proxy.ServeHTTP(w, r)
}

// -- Middleware --

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Session cookie (existing browser auth)
		if auth.ValidateSession(r) {
			next(w, r)
			return
		}

		// 2. Bearer token (OAuth 2.1 / MCP clients)
		if token := extractBearerToken(r); token != "" {
			if oauthSrv.ValidateAccessToken(token) {
				next(w, r)
				return
			}
		}

		// 3. No valid auth — decide response format
		authHeader := r.Header.Get("Authorization")
		accept := r.Header.Get("Accept")

		if authHeader != "" || (accept != "" && !strings.Contains(accept, "text/html") && !strings.Contains(accept, "*/*")) {
			// API/MCP client: return 401 with OAuth metadata pointer
			resourceURL := determineBaseURL(r) + "/.well-known/oauth-protected-resource"
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"`, resourceURL))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Browser: redirect to login (existing behavior)
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func extractBearerToken(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if strings.HasPrefix(v, "Bearer ") {
		return v[7:]
	}
	return ""
}

func getClientIP(r *http.Request) string {
	// 1. Check CF-Connecting-IP (Cloudflare)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return cfIP
	}

	// 2. Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF can be a comma-separated list of IPs. The first one is the client.
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// 3. Fallback to RemoteAddr
	// RemoteAddr is "IP:Port"
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}
