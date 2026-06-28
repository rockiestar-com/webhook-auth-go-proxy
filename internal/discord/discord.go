package discord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SendNotification sends the login code to the Discord webhook
func SendNotification(webhookURL, code, link, username, ip, country string) error {
	description := fmt.Sprintf("**Code:** `%s`\n[Click here to login](%s)", code, link)

	fields := []map[string]interface{}{}

	// User Field
	userVal := "Anonymous"
	if username != "" {
		userVal = username
	}
	fields = append(fields, map[string]interface{}{
		"name":   "User",
		"value":  userVal,
		"inline": true,
	})

	// IP Field
	fields = append(fields, map[string]interface{}{
		"name":   "IP Address",
		"value":  ip,
		"inline": true,
	})

	// Country Field (only if present)
	if country != "" {
		fields = append(fields, map[string]interface{}{
			"name":   "Country",
			"value":  country,
			"inline": true,
		})
	}

	payload := map[string]interface{}{
		"content": nil,
		"embeds": []map[string]interface{}{
			{
				"title":       "🔐 Login Request",
				"description": description,
				"color":       5763719, // Blurple
				"fields":      fields,
				"footer": map[string]string{
					"text": "Code expires in 5 minutes",
				},
				"timestamp": time.Now().Format(time.RFC3339),
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

// SendMCPApprovalNotification sends an MCP access approval request to Discord
func SendMCPApprovalNotification(webhookURL, clientName, approveLink, ip, country string) error {
	fields := []map[string]interface{}{
		{"name": "Client", "value": clientName, "inline": true},
		{"name": "IP Address", "value": ip, "inline": true},
	}
	if country != "" {
		fields = append(fields, map[string]interface{}{
			"name":   "Country",
			"value":  country,
			"inline": true,
		})
	}

	payload := map[string]interface{}{
		"content": nil,
		"embeds": []map[string]interface{}{
			{
				"title":       "\xf0\x9f\xa4\x96 MCP Access Request",
				"description": fmt.Sprintf("A coding agent is requesting access.\n\n[**Review & Approve**](%s)", approveLink),
				"color":       15105570, // Orange
				"fields":      fields,
				"footer": map[string]string{
					"text": "Request expires in 5 minutes",
				},
				"timestamp": time.Now().Format(time.RFC3339),
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
