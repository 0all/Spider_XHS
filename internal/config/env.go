package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadCookiesFromEnv reads the COOKIES value from the current environment or .env file.
func LoadCookiesFromEnv() (string, error) {
	if value := strings.TrimSpace(os.Getenv("COOKIES")); value != "" {
		return value, nil
	}

	cwd, _ := os.Getwd()
	envPath := filepath.Join(cwd, ".env")
	file, err := os.Open(envPath)
	if err != nil {
		return "", fmt.Errorf("COOKIES is empty and .env not found: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		if key == "COOKIES" && value != "" {
			return value, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read .env: %w", err)
	}
	return "", fmt.Errorf("COOKIES is empty; please populate .env with a valid xhs cookie string")
}
