package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"webhook-auth-proxy/internal/auth"
	"webhook-auth-proxy/internal/config"
	"webhook-auth-proxy/internal/discord"
)

// Global state
var (
	cfg   *config.Config
	proxy *httputil.ReverseProxy
)

// HTML Template for the login page
const loginHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Restricted Access</title>
    <style>
        body { font-family: -apple-system, system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; margin: 0; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
        input { padding: 10px; margin: 10px 0; width: 100%; box-sizing: border-box; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #5865F2; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; width: 100%; font-size: 16px; margin-top: 10px; }
        button:hover { background: #4752C4; }
        .secondary { background: #ddd; color: #333; }
        .secondary:hover { background: #ccc; }
        .message { margin-top: 1rem; color: #666; font-size: 0.9rem; }
        .error { color: #dc3545; }
        .success { color: #28a745; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Restricted Access</h2>
        
        <div id="step1">
            <p>Please authenticate to access this service.</p>
            <button onclick="requestToken()" id="reqBtn">Send Login Code to Discord</button>
        </div>

        <div id="step2" style="display: none;">
            <p>A code has been sent to the Discord channel.</p>
            <form action="/login" method="POST">
                <input type="text" name="code" placeholder="Enter 32-character code" required autocomplete="off">
                <button type="submit">Login</button>
            </form>
            <button class="secondary" onclick="showStep1()">Back</button>
        </div>
        
        <div id="message" class="message"></div>
    </div>

    <script>
        const msgParams = new URLSearchParams(window.location.search);
        if (msgParams.has('error')) {
            const el = document.getElementById('message');
            el.textContent = "Invalid or expired code.";
            el.className = "message error";
        }
        if (msgParams.has('code')) {
             document.querySelector('input[name="code"]').value = msgParams.get('code');
             showStep2();
        }

        function showStep1() {
            document.getElementById('step1').style.display = 'block';
            document.getElementById('step2').style.display = 'none';
        }

        function showStep2() {
            document.getElementById('step1').style.display = 'none';
            document.getElementById('step2').style.display = 'block';
        }

        function requestToken() {
            const btn = document.getElementById('reqBtn');
            btn.disabled = true;
            btn.textContent = "Sending...";
            
            fetch('/send-code', { method: 'POST' })
                .then(res => {
                    if (res.ok) {
                        showStep2();
                        document.getElementById('message').textContent = "Code sent!";
                        document.getElementById('message').className = "message success";
                    } else {
                        document.getElementById('message').textContent = "Failed to send code.";
                        document.getElementById('message').className = "message error";
                    }
                })
                .catch(err => {
                    document.getElementById('message').textContent = "Error connecting to server.";
                    document.getElementById('message').className = "message error";
                })
                .finally(() => {
                    btn.disabled = false;
                    btn.textContent = "Send Login Code to Discord";
                });
        }
    </script>
</body>
</html>
`

func init() {
	cfg = config.LoadFromEnv()
}

func main() {
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
		tmpl, err := template.New("login").Parse(loginHTML)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
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

	code, err := auth.GenerateCode()
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
