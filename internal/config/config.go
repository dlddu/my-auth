// Package config provides configuration loading and validation for my-auth.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// OwnerCredentials holds the owner's username and bcrypt-hashed password.
type OwnerCredentials struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// Config holds all application configuration values loaded from config.yaml.
type Config struct {
	Issuer     string           `yaml:"issuer"`
	Port       int              `yaml:"port"`
	Owner      OwnerCredentials `yaml:"owner"`
	JWTKeyPath string           `yaml:"jwt_key_path"`
}

// Load reads and parses a YAML configuration file from the given path.
// It returns an error if the file cannot be read or if the YAML is invalid.
// If Port is not set, it defaults to 8080.
// Trailing slashes are stripped from Issuer.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse YAML: %w", err)
	}

	// Apply defaults.
	if cfg.Port == 0 {
		cfg.Port = 8080
	}

	// Normalise issuer by stripping trailing slashes.
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")

	return &cfg, nil
}

// Validate checks that all required configuration fields are present and valid.
// It returns an error describing the first validation failure found.
func (c *Config) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("config: issuer is required")
	}
	if !strings.HasPrefix(c.Issuer, "https://") {
		return fmt.Errorf("config: issuer must use HTTPS scheme, got %q", c.Issuer)
	}
	if c.Owner.Username == "" {
		return fmt.Errorf("config: owner.username is required")
	}
	if c.Owner.PasswordHash == "" {
		return fmt.Errorf("config: owner.password_hash is required")
	}
	if c.JWTKeyPath == "" {
		return fmt.Errorf("config: jwt_key_path is required")
	}
	if c.Port <= 0 {
		return fmt.Errorf("config: port must be greater than 0, got %d", c.Port)
	}
	return nil
}
