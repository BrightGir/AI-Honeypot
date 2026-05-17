package gemini

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

const geminiTimeout = 30 * time.Second

const defaultGeminiModel = "gemini-2.0-flash-lite"

var fallbackResponses = []string{
	"I understand what you're asking, but I'm not able to share that kind of information.",
	"That's an interesting question. Unfortunately, I'm not in a position to assist with that.",
	"I'm here to help with general queries, but this falls outside what I can support.",
	"I appreciate your curiosity, but I can't provide details on that topic.",
	"This isn't something I'm able to help with. Is there anything else I can do for you?",
	"I want to be helpful, but I have to decline this particular request.",
	"I'm not sure I fully understand what you need, but I don't think I can help with this one.",
	"That's not something I'm able to assist with at this time.",
	"I can see you're looking for something specific, but I'm afraid I can't provide that.",
	"Let me be straightforward: I'm not able to engage with that kind of request.",
}

type Client struct {
	client    *genai.Client
	modelName string
}

func New(ctx context.Context, apiKey string) (*Client, error) {
	c, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("gemini init: %w", err)
	}
	modelName := os.Getenv("GEMINI_MODEL")
	if modelName == "" {
		modelName = defaultGeminiModel
	}
	return &Client{client: c, modelName: modelName}, nil
}

// Close releases resources held by the underlying Gemini client.
// The caller should check the returned error and log it if non-nil.
func (c *Client) Close() error {
	return c.client.Close()
}

// GenerateDecoyResponse generates a honeypot response using the given persona.
// Falls back to a randomised static response if the API is unavailable.
func (c *Client) GenerateDecoyResponse(ctx context.Context, persona *model.Persona, userMessage string) (string, error) {
	model := c.client.GenerativeModel(c.modelName)
	model.SystemInstruction = &genai.Content{
		Parts: []genai.Part{genai.Text(persona.SystemPrompt)},
	}

	genCtx, cancel := context.WithTimeout(ctx, geminiTimeout)
	defer cancel()
	resp, err := model.GenerateContent(genCtx, genai.Text(userMessage))
	if err != nil {
		slog.Warn("gemini: GenerateContent failed, using fallback", "err", err)
		return fallbackResponses[rand.Intn(len(fallbackResponses))], nil
	}
	if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil || len(resp.Candidates[0].Content.Parts) == 0 {
		slog.Warn("gemini: empty response, using fallback")
		return fallbackResponses[rand.Intn(len(fallbackResponses))], nil
	}

	text, ok := resp.Candidates[0].Content.Parts[0].(genai.Text)
	if !ok {
		slog.Warn("gemini: empty response, using fallback")
		return fallbackResponses[rand.Intn(len(fallbackResponses))], nil
	}
	return string(text), nil
}
