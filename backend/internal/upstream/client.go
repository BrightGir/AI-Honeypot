// Package upstream forwards benign chat requests to the customer's real LLM.
// Supports three provider types:
//   - openai  — OpenAI-compatible API (OpenAI, Azure, Ollama, vLLM, LM Studio, …)
//   - anthropic — Anthropic Messages API
//   - raw     — any custom REST endpoint: POST {"message","history"} → {"response"}
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
)

const defaultTimeout = 30 * time.Second

const (
	ProviderOpenAI    = "openai"
	ProviderAnthropic = "anthropic"
	ProviderRaw       = "raw"
)

type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: defaultTimeout}}
}

// Forward dispatches to the correct provider implementation based on providerType.
// Falls back to openai when providerType is empty.
func (c *Client) Forward(ctx context.Context, providerType, baseURL, apiKey, modelName, systemPrompt, userMessage string, history []model.Message) (string, error) {
	switch providerType {
	case ProviderAnthropic:
		return c.forwardAnthropic(ctx, baseURL, apiKey, modelName, systemPrompt, userMessage, history)
	case ProviderRaw:
		return c.forwardRaw(ctx, baseURL, apiKey, userMessage, history)
	default: // openai or empty
		return c.forwardOpenAI(ctx, baseURL, apiKey, modelName, systemPrompt, userMessage, history)
	}
}

// ── OpenAI-compatible ─────────────────────────────────────────

type oaiMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type oaiRequest struct {
	Model    string   `json:"model"`
	Messages []oaiMsg `json:"messages"`
}

type oaiResponse struct {
	Choices []struct {
		Message oaiMsg `json:"message"`
	} `json:"choices"`
	Error *struct{ Message string `json:"message"` } `json:"error,omitempty"`
}

func (c *Client) forwardOpenAI(ctx context.Context, baseURL, apiKey, modelName, systemPrompt, userMessage string, history []model.Message) (string, error) {
	msgs := buildOpenAIMessages(systemPrompt, history, userMessage)
	if modelName == "" {
		modelName = "gpt-4o-mini"
	}

	body, _ := json.Marshal(oaiRequest{Model: modelName, Messages: msgs})
	endpoint := strings.TrimRight(baseURL, "/") + "/chat/completions"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("upstream/openai: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	var oai oaiResponse
	if err := c.do(req, &oai); err != nil {
		return "", fmt.Errorf("upstream/openai: %w", err)
	}
	if oai.Error != nil {
		return "", fmt.Errorf("upstream/openai: API error: %s", oai.Error.Message)
	}
	if len(oai.Choices) == 0 || oai.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("upstream/openai: empty response")
	}

	slog.Debug("upstream/openai: forwarded", "model", modelName, "base_url", baseURL)
	return oai.Choices[0].Message.Content, nil
}

func buildOpenAIMessages(systemPrompt string, history []model.Message, userMessage string) []oaiMsg {
	msgs := make([]oaiMsg, 0, len(history)+2)
	if systemPrompt != "" {
		msgs = append(msgs, oaiMsg{Role: "system", Content: systemPrompt})
	}
	start := 0
	if len(history) > 20 {
		start = len(history) - 20
	}
	for _, m := range history[start:] {
		if m.Role != "user" && m.Role != "assistant" {
			continue
		}
		msgs = append(msgs, oaiMsg{Role: m.Role, Content: m.Content})
	}
	msgs = append(msgs, oaiMsg{Role: "user", Content: userMessage})
	return msgs
}

// ── Anthropic Messages API ────────────────────────────────────

type anthropicRequest struct {
	Model     string     `json:"model"`
	MaxTokens int        `json:"max_tokens"`
	System    string     `json:"system,omitempty"`
	Messages  []oaiMsg   `json:"messages"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct{ Message string `json:"message"` } `json:"error,omitempty"`
}

func (c *Client) forwardAnthropic(ctx context.Context, baseURL, apiKey, modelName, systemPrompt, userMessage string, history []model.Message) (string, error) {
	msgs := buildOpenAIMessages("", history, userMessage) // no system in messages for Anthropic
	if modelName == "" {
		modelName = "claude-3-5-haiku-20241022"
	}

	body, _ := json.Marshal(anthropicRequest{
		Model:     modelName,
		MaxTokens: 2048,
		System:    systemPrompt,
		Messages:  msgs,
	})

	endpoint := strings.TrimRight(baseURL, "/") + "/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("upstream/anthropic: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	if apiKey != "" {
		req.Header.Set("x-api-key", apiKey)
	}

	var anth anthropicResponse
	if err := c.do(req, &anth); err != nil {
		return "", fmt.Errorf("upstream/anthropic: %w", err)
	}
	if anth.Error != nil {
		return "", fmt.Errorf("upstream/anthropic: API error: %s", anth.Error.Message)
	}
	for _, block := range anth.Content {
		if block.Type == "text" && block.Text != "" {
			slog.Debug("upstream/anthropic: forwarded", "model", modelName)
			return block.Text, nil
		}
	}
	return "", fmt.Errorf("upstream/anthropic: empty response")
}

// ── Raw / custom endpoint ─────────────────────────────────────
// Request:  POST baseURL  {"message": "...", "history": [{"role":"...","content":"..."}]}
// Response: {"response": "..."}  — also tries "text", "content", "answer", "output"

type rawRequest struct {
	Message string     `json:"message"`
	History []oaiMsg   `json:"history,omitempty"`
}

func (c *Client) forwardRaw(ctx context.Context, baseURL, apiKey, userMessage string, history []model.Message) (string, error) {
	hist := make([]oaiMsg, 0, len(history))
	start := 0
	if len(history) > 20 {
		start = len(history) - 20
	}
	for _, m := range history[start:] {
		if m.Role == "user" || m.Role == "assistant" {
			hist = append(hist, oaiMsg{Role: m.Role, Content: m.Content})
		}
	}

	body, _ := json.Marshal(rawRequest{Message: userMessage, History: hist})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("upstream/raw: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	// Parse as generic map to support any field name
	var raw map[string]any
	if err := c.do(req, &raw); err != nil {
		return "", fmt.Errorf("upstream/raw: %w", err)
	}

	for _, field := range []string{"response", "text", "content", "answer", "output", "message"} {
		if v, ok := raw[field]; ok {
			if s, ok := v.(string); ok && s != "" {
				slog.Debug("upstream/raw: forwarded", "field", field, "url", baseURL)
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("upstream/raw: no recognised response field in: %v", raw)
}

// ── shared HTTP helper ────────────────────────────────────────

func (c *Client) do(req *http.Request, dest any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return fmt.Errorf("parse response (status %d): %w", resp.StatusCode, err)
	}
	return nil
}
