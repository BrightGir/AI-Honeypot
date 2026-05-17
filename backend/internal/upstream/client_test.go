package upstream_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/BrightGir/AI-Honeypot/backend/internal/upstream"
)

// ── helpers ──────────────────────────────────────────────────

func newClient() *upstream.Client { return upstream.New() }

func history(pairs ...string) []model.Message {
	msgs := make([]model.Message, 0, len(pairs))
	for i := 0; i+1 < len(pairs); i += 2 {
		msgs = append(msgs, model.Message{Role: pairs[i], Content: pairs[i+1]})
	}
	return msgs
}

// ── OpenAI provider ───────────────────────────────────────────

func TestForwardOpenAI_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing or wrong auth header")
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		msgs := body["messages"].([]any)
		// system prompt + history (2) + user message = 4
		if len(msgs) != 4 {
			t.Errorf("expected 4 messages, got %d", len(msgs))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": "hello from upstream"}},
			},
		})
	}))
	defer srv.Close()

	c := newClient()
	hist := history("user", "hi", "assistant", "hello")
	got, err := c.Forward(context.Background(), upstream.ProviderOpenAI, srv.URL, "test-key", "gpt-4o", "You are helpful.", "what is 2+2?", hist)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello from upstream" {
		t.Errorf("got %q, want %q", got, "hello from upstream")
	}
}

func TestForwardOpenAI_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"message": "invalid API key"},
		})
	}))
	defer srv.Close()

	c := newClient()
	_, err := c.Forward(context.Background(), upstream.ProviderOpenAI, srv.URL, "bad-key", "gpt-4o", "", "hello", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 in error, got: %v", err)
	}
}

func TestForwardOpenAI_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{}})
	}))
	defer srv.Close()

	c := newClient()
	_, err := c.Forward(context.Background(), upstream.ProviderOpenAI, srv.URL, "", "gpt-4o", "", "hello", nil)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty response error, got: %v", err)
	}
}

func TestForwardOpenAI_NoAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("expected no auth header, got: %s", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": "ok"}},
			},
		})
	}))
	defer srv.Close()

	c := newClient()
	got, err := c.Forward(context.Background(), upstream.ProviderOpenAI, srv.URL, "", "gpt-4o", "", "hello", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ok" {
		t.Errorf("got %q, want %q", got, "ok")
	}
}

func TestForwardOpenAI_HistoryTruncatedTo20(t *testing.T) {
	received := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		msgs := body["messages"].([]any)
		received = len(msgs)
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": "ok"}},
			},
		})
	}))
	defer srv.Close()

	// Build 30 history messages (15 pairs)
	var hist []model.Message
	for i := 0; i < 30; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		hist = append(hist, model.Message{Role: role, Content: "msg"})
	}

	c := newClient()
	c.Forward(context.Background(), upstream.ProviderOpenAI, srv.URL, "", "gpt-4o", "", "new msg", hist)
	// 20 history + 1 current user = 21 (no system prompt)
	if received != 21 {
		t.Errorf("expected 21 messages (20 history + 1 current), got %d", received)
	}
}

// ── Anthropic provider ────────────────────────────────────────

func TestForwardAnthropic_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/messages" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "anth-key" {
			t.Errorf("missing x-api-key header")
		}
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("missing anthropic-version header")
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["system"] != "Be helpful." {
			t.Errorf("system prompt not forwarded")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": "anthropic reply"},
			},
		})
	}))
	defer srv.Close()

	c := newClient()
	got, err := c.Forward(context.Background(), upstream.ProviderAnthropic, srv.URL, "anth-key", "claude-3-5-haiku-20241022", "Be helpful.", "hello", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "anthropic reply" {
		t.Errorf("got %q, want %q", got, "anthropic reply")
	}
}

func TestForwardAnthropic_EmptyContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"content": []any{}})
	}))
	defer srv.Close()

	c := newClient()
	_, err := c.Forward(context.Background(), upstream.ProviderAnthropic, srv.URL, "", "", "", "hello", nil)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty response error, got: %v", err)
	}
}

// ── Raw / custom provider ─────────────────────────────────────

func TestForwardRaw_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["message"] != "test question" {
			t.Errorf("message field not forwarded, got: %v", body["message"])
		}
		if _, ok := body["history"]; !ok {
			t.Errorf("history field missing")
		}
		json.NewEncoder(w).Encode(map[string]any{"response": "custom reply"})
	}))
	defer srv.Close()

	c := newClient()
	hist := history("user", "prev", "assistant", "prev reply")
	got, err := c.Forward(context.Background(), upstream.ProviderRaw, srv.URL, "", "", "", "test question", hist)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "custom reply" {
		t.Errorf("got %q, want %q", got, "custom reply")
	}
}

func TestForwardRaw_AlternativeFields(t *testing.T) {
	for _, field := range []string{"text", "content", "answer", "output"} {
		field := field
		t.Run(field, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{field: "value from " + field})
			}))
			defer srv.Close()

			c := newClient()
			got, err := c.Forward(context.Background(), upstream.ProviderRaw, srv.URL, "", "", "", "hi", nil)
			if err != nil {
				t.Fatalf("field %q: unexpected error: %v", field, err)
			}
			if got != "value from "+field {
				t.Errorf("field %q: got %q", field, got)
			}
		})
	}
}

func TestForwardRaw_UnknownFieldError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"result": "something"})
	}))
	defer srv.Close()

	c := newClient()
	_, err := c.Forward(context.Background(), upstream.ProviderRaw, srv.URL, "", "", "", "hi", nil)
	if err == nil || !strings.Contains(err.Error(), "no recognised") {
		t.Errorf("expected 'no recognised' error, got: %v", err)
	}
}

func TestForwardRaw_BearerToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer raw-secret" {
			t.Errorf("expected Bearer raw-secret, got: %s", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(map[string]any{"response": "ok"})
	}))
	defer srv.Close()

	c := newClient()
	got, err := c.Forward(context.Background(), upstream.ProviderRaw, srv.URL, "raw-secret", "", "", "hi", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ok" {
		t.Errorf("got %q", got)
	}
}

// ── Provider fallback ─────────────────────────────────────────

func TestForward_EmptyProviderFallsBackToOpenAI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("expected openai path, got: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": "fallback ok"}},
			},
		})
	}))
	defer srv.Close()

	c := newClient()
	got, err := c.Forward(context.Background(), "", srv.URL, "", "gpt-4o", "", "hi", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "fallback ok" {
		t.Errorf("got %q", got)
	}
}

// ── Network errors ────────────────────────────────────────────

func TestForward_ConnectionRefused(t *testing.T) {
	c := newClient()
	_, err := c.Forward(context.Background(), upstream.ProviderOpenAI, "http://127.0.0.1:1", "", "gpt-4o", "", "hi", nil)
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
}

func TestForward_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// block until context is cancelled
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	c := newClient()
	_, err := c.Forward(ctx, upstream.ProviderOpenAI, srv.URL, "", "gpt-4o", "", "hi", nil)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
}
