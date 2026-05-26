package prompt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	content := "You are a test persona."
	os.WriteFile(filepath.Join(dir, "test_persona.txt"), []byte(content), 0644)

	got := Load(dir, "test_persona", "fallback")
	if got != content {
		t.Errorf("Load() = %q, want %q", got, content)
	}
}

func TestLoad_MissingFile_ReturnsFallback(t *testing.T) {
	dir := t.TempDir()
	fallback := "default system prompt"
	got := Load(dir, "nonexistent", fallback)
	if got != fallback {
		t.Errorf("Load() = %q, want fallback %q", got, fallback)
	}
}

func TestLoad_EmptyDir_ReturnsFallback(t *testing.T) {
	fallback := "fallback prompt"
	got := Load("", "any", fallback)
	if got != fallback {
		t.Errorf("Load() = %q, want fallback %q", got, fallback)
	}
}

func TestLoad_EmptyFileContent_ReturnsFallback(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "empty.txt"), []byte("   \n\t  "), 0644)
	fallback := "fallback"
	got := Load(dir, "empty", fallback)
	if got != fallback {
		t.Errorf("Load() on whitespace-only file = %q, want fallback %q", got, fallback)
	}
}

func TestLoad_TrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "padded.txt"), []byte("\n\n  Hello world.  \n\n"), 0644)
	got := Load(dir, "padded", "fallback")
	if got != "Hello world." {
		t.Errorf("Load() = %q, want trimmed content", got)
	}
}

func TestLoad_MultilineContent(t *testing.T) {
	dir := t.TempDir()
	content := "Line one.\nLine two.\nLine three."
	os.WriteFile(filepath.Join(dir, "multi.txt"), []byte(content), 0644)
	got := Load(dir, "multi", "fallback")
	if got != content {
		t.Errorf("Load() = %q, want %q", got, content)
	}
}
