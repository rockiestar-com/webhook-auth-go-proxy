package config

import (
	"os"
	"strconv"
)

// Config holds the application configuration
type Config struct {
	Port              string
	UpstreamURL       string
	DiscordWebhookURL string
	CodeLength        int
	RateLimitPerHour  int
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() *Config {
	codeLength := 32 // Default
	if clStr := os.Getenv("CODE_LENGTH"); clStr != "" {
		if cl, err := strconv.Atoi(clStr); err == nil && cl > 0 {
			codeLength = cl
		}
	}

	rateLimit := 100 // Default
	if rlStr := os.Getenv("RATE_LIMIT_PER_HOUR"); rlStr != "" {
		if rl, err := strconv.Atoi(rlStr); err == nil && rl > 0 {
			rateLimit = rl
		}
	}

	cfg := &Config{
		Port:              os.Getenv("PORT"),
		UpstreamURL:       os.Getenv("UPSTREAM_URL"),
		DiscordWebhookURL: os.Getenv("DISCORD_WEBHOOK_URL"),
		CodeLength:        codeLength,
		RateLimitPerHour:  rateLimit,
	}

	if cfg.Port == "" {
		cfg.Port = "8080"
	}

	return cfg
}
