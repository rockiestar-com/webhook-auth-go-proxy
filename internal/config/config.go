package config

import (
	"os"
)

// Config holds the application configuration
type Config struct {
	Port              string
	UpstreamURL       string
	DiscordWebhookURL string
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() *Config {
	cfg := &Config{
		Port:              os.Getenv("PORT"),
		UpstreamURL:       os.Getenv("UPSTREAM_URL"),
		DiscordWebhookURL: os.Getenv("DISCORD_WEBHOOK_URL"),
	}

	if cfg.Port == "" {
		cfg.Port = "8080"
	}

	return cfg
}
