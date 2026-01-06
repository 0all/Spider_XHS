package downloader

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// SaveImage downloads a single image to the target directory using the provided filename.
func SaveImage(url, dir, filename string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create dir %s: %w", dir, err)
	}

	resp, err := http.Get(url) //nolint:gosec // external url comes from XHS API
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("download %s: http %d: %s", url, resp.StatusCode, string(body))
	}

	targetPath := filepath.Join(dir, filename)
	file, err := os.Create(targetPath)
	if err != nil {
		return "", fmt.Errorf("create file %s: %w", targetPath, err)
	}
	defer file.Close()

	if _, err := io.Copy(file, resp.Body); err != nil {
		return "", fmt.Errorf("write %s: %w", targetPath, err)
	}
	return targetPath, nil
}
