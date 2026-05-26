package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
)

const defaultBaseURL = "https://api.openai.com/v1"
const defaultModel = "gpt-4o-mini"

const (
	decoyMaxTokens   = 300
	analyzeMaxTokens = 600
)

// openaiTimeout caps the time spent waiting for an OpenAI API response per call.
// Without this, a slow or hung API call would block indefinitely even though
// the http.Client has a global Timeout set.
const openaiTimeout = 30 * time.Second

// maxResponseBytes limits how much data we read from the API response body.
// This prevents an attacker-controlled or misbehaving server from returning
// an unbounded response that exhausts memory.
const maxResponseBytes = 1 << 20 // 1 MB

var fallbackResponses = []string{
	"I understand what you're asking, but I'm not able to share that kind of information.",
	"That's an interesting question. Unfortunately, I'm not in a position to assist with that.",
	"I'm here to help with general queries, but this falls outside what I can support.",
	"I appreciate your curiosity, but I can't provide details on that topic.",
	"This isn't something I'm able to help with. Is there anything else I can do for you?",
	"I want to be helpful, but I have to decline this particular request.",
	"I'm not sure I fully understand what you need, but I don't think I can help with this one.",
	"That's not something I'm able to assist with at this time.",
}

type Client struct {
	apiKey  string
	baseURL string
	model   string
	http    *http.Client
}

func New(apiKey string) *Client {
	return &Client{
		apiKey:  apiKey,
		baseURL: defaultBaseURL,
		model:   defaultModel,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *Client) GenerateDecoyResponse(ctx context.Context, persona *model.Persona, userMessage string) (string, error) {
	messages := []chatMessage{
		{Role: "system", Content: persona.SystemPrompt},
		{Role: "user", Content: userMessage},
	}

	body, err := json.Marshal(chatRequest{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   decoyMaxTokens,
		Temperature: 0.7,
	})
	if err != nil {
		slog.Warn("openai: GenerateDecoyResponse: marshal request", "err", err)
		return fallback(), nil
	}

	// Apply a per-call timeout so a slow OpenAI API cannot block indefinitely.
	callCtx, cancel := context.WithTimeout(ctx, openaiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		slog.Warn("openai: GenerateDecoyResponse: create request", "err", err)
		return fallback(), nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return fallback(), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("openai: GenerateDecoyResponse: unexpected status", "status", resp.StatusCode)
		return fallback(), nil
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fallback(), nil
	}

	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return fallback(), nil
	}
	if cr.Error != nil {
		return fallback(), fmt.Errorf("openai: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 || cr.Choices[0].Message.Content == "" {
		return fallback(), nil
	}
	return cr.Choices[0].Message.Content, nil
}

// AnalyzeText sends a plain text prompt and returns the LLM's response.
// Used for session analysis — no persona involved.
func (c *Client) AnalyzeText(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	messages := []chatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}
	body, err := json.Marshal(chatRequest{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   analyzeMaxTokens,
		Temperature: 0.3,
	})
	if err != nil {
		return "", err
	}

	// Apply a per-call timeout so a slow OpenAI API cannot block indefinitely.
	callCtx, cancel := context.WithTimeout(ctx, openaiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai: AnalyzeText: unexpected status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("openai: read body: %w", err)
	}
	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", err
	}
	if cr.Error != nil {
		return "", fmt.Errorf("openai: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 || cr.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("openai: empty response")
	}
	return cr.Choices[0].Message.Content, nil
}

func fallback() string {
	return fallbackResponses[rand.Intn(len(fallbackResponses))]
}
