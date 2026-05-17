package prompt

import (
	"os"
	"path/filepath"
	"strings"
)

// maxPromptBytes is the maximum allowed size for a prompt file (64 KB).
// Files larger than this limit are rejected to prevent excessive memory use.
const maxPromptBytes = 1 << 16 // 64 KB

// Load reads a prompt file from dir/<name>.txt.
// Falls back to fallback string if the file does not exist, cannot be read,
// or exceeds maxPromptBytes in size.
func Load(dir, name, fallback string) string {
	if dir == "" {
		return fallback
	}
	// filepath.Base returns "." for empty strings and strips all directory
	// components, so "../../etc/passwd" becomes "passwd" and is safe to join.
	safe := filepath.Base(name)
	if safe == "." || safe == "" || strings.ContainsAny(safe, "/\\") {
		return fallback
	}
	b, err := os.ReadFile(filepath.Join(dir, safe+".txt"))
	if err != nil {
		return fallback
	}
	if len(b) > maxPromptBytes {
		return fallback
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return fallback
	}
	return s
}
