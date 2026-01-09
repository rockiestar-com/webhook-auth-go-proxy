package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Config holds the application configuration
type Config struct {
	Port              string
	UpstreamURL       string
	DiscordWebhookURL string
}

// Global state
var (
	config       Config
	sessionKey   []byte
	pendingCodes = make(map[string]time.Time)
	codesMu      sync.RWMutex
	proxy        *httputil.ReverseProxy
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
                <input type="text" name="code" placeholder="Enter 6-digit code" required autocomplete="off">
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
	// Initialize configuration
	config.Port = os.Getenv("PORT")
	if config.Port == "" {
		config.Port = "8080"
	}

	config.UpstreamURL = os.Getenv("UPSTREAM_URL")
	config.DiscordWebhookURL = os.Getenv("DISCORD_WEBHOOK_URL")

	// Generate a random session key on startup
	sessionKey = make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		log.Fatal("Failed to generate session key:", err)
	}
}

func main() {
	// Validate essential config
	if config.UpstreamURL == "" {
		log.Fatal("UPSTREAM_URL environment variable is required")
	}
	if config.DiscordWebhookURL == "" {
		log.Fatal("DISCORD_WEBHOOK_URL environment variable is required")
	}

	targetURL, err := url.Parse(config.UpstreamURL)
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

	log.Printf("Starting proxy on port %s", config.Port)
	log.Printf("Upstream: %s", config.UpstreamURL)
	log.Printf("Session key generated (ephemeral)")

	server := &http.Server{
		Addr:         ":" + config.Port,
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
		if validateSession(r) {
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
		if verifyCode(code) {
			setSessionCookie(w)
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

	code, err := generateCode()
	if err != nil {
		log.Printf("Error generating code: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Construct public URL for convenience (best effort guess based on Host header)
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	publicURL := fmt.Sprintf("%s://%s/login?code=%s", scheme, r.Host, code)

	go sendDiscordNotification(code, publicURL)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Code sent"))
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	proxy.ServeHTTP(w, r)
}

// -- Middleware --

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if validateSession(r) {
			next(w, r)
			return
		}
		// Redirect to login, preserving original path if complex logic needed,
		// but simple redirect is fine for this scope.
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

// -- Helpers --

// generateCode creates a 6-digit code, stores it, and returns it
func generateCode() (string, error) {
	b := make([]byte, 3) // 3 bytes = 6 hex chars? No, let's just do random number.
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Simple 6 hex chars for robustness/entropy or just random digits.
	// Users prefer digits.
	// Let's do a secure random number.
	const chars = "0123456789"
	result := make([]byte, 6)
	randBytes := make([]byte, 6)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	for i, b := range randBytes {
		result[i] = chars[b%byte(len(chars))]
	}
	code := string(result)

	codesMu.Lock()
	pendingCodes[code] = time.Now().Add(5 * time.Minute) // 5 minute expiry
	// Cleanup old codes
	for k, v := range pendingCodes {
		if time.Now().After(v) {
			delete(pendingCodes, k)
		}
	}
	codesMu.Unlock()

	return code, nil
}

func verifyCode(code string) bool {
	codesMu.Lock()
	defer codesMu.Unlock()

	expiry, exists := pendingCodes[code]
	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		delete(pendingCodes, code)
		return false
	}

	// Consume code (one-time use)
	delete(pendingCodes, code)
	return true
}

func sendDiscordNotification(code, link string) {
	payload := map[string]interface{}{
		"content": nil,
		"embeds": []map[string]interface{}{
			{
				"title":       "🔐 Login Request",
				"description": fmt.Sprintf("A login attempt was requested.\n\n**Code:** `%s`\n\n[Click here to login](%s)", code, link),
				"color":       5763719, // Blurple
				"footer": map[string]string{
					"text": "Code expires in 5 minutes",
				},
			},
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(config.DiscordWebhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Failed to send webhook: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Discord API returned error: %d", resp.StatusCode)
	}
}

// -- Session Management (Signed Cookie) --

const cookieName = "auth_session"

func setSessionCookie(w http.ResponseWriter) {
	// Create a random session ID
	sessionID := make([]byte, 16)
	rand.Read(sessionID)
	sessionIDStr := hex.EncodeToString(sessionID)

	// Sign it
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write([]byte(sessionIDStr))
	signature := mac.Sum(nil)

	// Value = sessionID + "." + signature
	cookieValue := sessionIDStr + "." + base64.URLEncoding.EncodeToString(signature)

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Can be true if behind TLS proxy, but keeping simple for now
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7, // 7 days
	})
}

func validateSession(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}

	sessionIDStr := parts[0]
	signatureStr := parts[1]

	signature, err := base64.URLEncoding.DecodeString(signatureStr)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, sessionKey)
	mac.Write([]byte(sessionIDStr))
	expectedSignature := mac.Sum(nil)

	return hmac.Equal(signature, expectedSignature)
}
