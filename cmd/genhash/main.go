// Command genhash generates a bcrypt hash for the given password and
// optionally writes a complete config.yaml file.
//
// Usage:
//
//	# Print hash to stdout:
//	go run ./cmd/genhash [password]
//
//	# Write config.yaml:
//	go run ./cmd/genhash write-config \
//	  --username admin \
//	  --password secret \
//	  --issuer https://auth.example.com \
//	  --jwt-key-path keys/private.pem \
//	  --admin-token token \
//	  --output config.yaml
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "write-config" {
		writeConfigCmd(os.Args[2:])
		return
	}

	// Default: print hash to stdout.
	password := "admin-password-placeholder-dld686"
	if len(os.Args) > 1 {
		password = os.Args[1]
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}

func writeConfigCmd(args []string) {
	fs := flag.NewFlagSet("write-config", flag.ExitOnError)
	username := fs.String("username", "admin", "owner username")
	password := fs.String("password", "", "owner password (required)")
	issuer := fs.String("issuer", "https://auth.example.com", "OIDC issuer URL")
	jwtKeyPath := fs.String("jwt-key-path", "keys/private.pem", "RSA private key PEM path")
	adminToken := fs.String("admin-token", "", "admin bearer token")
	output := fs.String("output", "config.yaml", "output config file path")
	_ = fs.Parse(args)

	if *password == "" {
		fmt.Fprintln(os.Stderr, "error: --password is required")
		os.Exit(1)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(*password), 12)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating bcrypt hash: %v\n", err)
		os.Exit(1)
	}

	// Build config as a map to avoid YAML marshalling issues with $ signs.
	type ownerCfg struct {
		Username     string `yaml:"username"`
		PasswordHash string `yaml:"password_hash"`
	}
	type configCfg struct {
		Issuer      string   `yaml:"issuer"`
		Port        int      `yaml:"port"`
		Owner       ownerCfg `yaml:"owner"`
		JWTKeyPath  string   `yaml:"jwt_key_path"`
		AdminToken  string   `yaml:"admin_token,omitempty"`
	}

	cfg := configCfg{
		Issuer: strings.TrimRight(*issuer, "/"),
		Port:   8080,
		Owner: ownerCfg{
			Username:     *username,
			PasswordHash: string(hash),
		},
		JWTKeyPath: *jwtKeyPath,
		AdminToken: *adminToken,
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshalling YAML: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *output, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "wrote %s\n", *output)
}
