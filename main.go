package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"webhook-auth-proxy/internal/auth"
	"webhook-auth-proxy/internal/config"
	"webhook-auth-proxy/internal/discord"
	"webhook-auth-proxy/internal/limiter"
)

//go:embed templates/login.html
var templateFS embed.FS

// Global state
var (
	cfg         *config.Config
	proxy       *httputil.ReverseProxy
	rateLimiter *limiter.Limiter
	loginTmpl   *template.Template
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

	mux := http.NewServeMux()

	// Health check (public)
	mux.HandleFunc("/api/v1/health", handleHealth)

	// Auth routes (public)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/send-code", handleSendCode)

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

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
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

	code, err := auth.GenerateCode(cfg.CodeLength)
	if err != nil {
		log.Printf("Error generating code: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Construct public URL
	publicURL := fmt.Sprintf("%s/login?code=%s", determineBaseURL(r), code)

	go func() {
		if err := discord.SendNotification(cfg.DiscordWebhookURL, code, publicURL); err != nil {
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
		if auth.ValidateSession(r) {
			next(w, r)
			return
		}
		// Redirect to login, preserving original path if complex logic needed,
		// but simple redirect is fine for this scope.
		http.Redirect(w, r, "/login", http.StatusFound)
	}
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
