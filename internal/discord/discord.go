package discord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// SendNotification sends the login code to the Discord webhook
func SendNotification(webhookURL, code, link string) error {
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

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord API returned error: %d", resp.StatusCode)
	}

	return nil
}
