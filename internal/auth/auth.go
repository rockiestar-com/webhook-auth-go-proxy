package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	sessionKey   []byte
	pendingCodes = make(map[string]time.Time)
	codesMu      sync.RWMutex
)

const cookieName = "auth_session"

func init() {
	// Generate a random session key on startup
	sessionKey = make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		log.Fatal("Failed to generate session key:", err)
	}
}

// GenerateCode creates a hex code of specified length, stores it, and returns it.
// Length is in characters, so bytes needed = length / 2
func GenerateCode(length int) (string, error) {
	if length <= 0 {
		length = 32
	}
	// Ensure even length for hex encoding
	if length%2 != 0 {
		length++
	}

	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	code := hex.EncodeToString(bytes)

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

// VerifyCode checks if the code is valid and consumes it
func VerifyCode(code string) bool {
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

// SetSessionCookie creates and sets a signed session cookie
func SetSessionCookie(w http.ResponseWriter) {
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
		Secure:   false, // Can be true if behind TLS proxy
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7, // 7 days
	})
}

// ValidateSession checks if the request has a valid session cookie
func ValidateSession(r *http.Request) bool {
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

// Debug: SetSessionKeyForTest allows tests to set a predictable key
func SetSessionKeyForTest(key []byte) {
	sessionKey = key
}

// Debug: ClearCodesForTest allows tests to clear codes
func ClearCodesForTest() {
	codesMu.Lock()
	defer codesMu.Unlock()
	pendingCodes = make(map[string]time.Time)
}

// Debug: AddCodeForTest allows tests to add a code manually
func AddCodeForTest(code string, expiry time.Time) {
	codesMu.Lock()
	defer codesMu.Unlock()
	pendingCodes[code] = expiry
}

// Debug: CookieName exposes the cookie name for tests
func CookieName() string {
	return cookieName
}
