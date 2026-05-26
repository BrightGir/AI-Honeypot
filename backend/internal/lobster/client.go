package lobster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
)

// defaultModel is used when LOBSTER_MODEL env var is not set.
const defaultModel = "gemini-2.0-flash"

type Client struct {
	baseURL string
	apiKey  string
	model   string
	http    *http.Client
}

// New creates a Lobster Trap client. The model used for inspection is read
// from the LOBSTER_MODEL environment variable; it falls back to defaultModel
// ("gemini-2.0-flash") when the variable is not set.
func New(baseURL, apiKey string) *Client {
	if baseURL == "" {
		slog.Warn("lobster: baseURL is empty, Inspect calls will fail")
	}
	model := os.Getenv("LOBSTER_MODEL")
	if model == "" {
		model = defaultModel
	}
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		model:   model,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// OpenAI-compatible request to Lobster Trap proxy
type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type lobsterDetected struct {
	IntentCategory            string  `json:"intent_category"`
	RiskScore                 float64 `json:"risk_score"`
	ContainsInjectionPatterns bool    `json:"contains_injection_patterns"`
	ContainsRoleImpersonation bool    `json:"contains_role_impersonation"`
	ContainsExfiltration      bool    `json:"contains_exfiltration"`
	ContainsSystemCommands    bool    `json:"contains_system_commands"`
	ContainsCredentials       bool    `json:"contains_credentials"`
	ContainsPIIRequest        bool    `json:"contains_pii_request"`
	ContainsObfuscation       bool    `json:"contains_obfuscation"`
}

type lobsterIngress struct {
	Detected lobsterDetected `json:"detected"`
	Action   string          `json:"action"`
}

type lobsterMeta struct {
	Verdict string         `json:"verdict"`
	Ingress lobsterIngress `json:"ingress"`
}

type InspectResult struct {
	Meta        model.LobsterTrapMeta
	LLMResponse string
}

// Inspect sends message through Lobster Trap and returns DPI metadata + LLM response.
func (c *Client) Inspect(ctx context.Context, systemPrompt, userMessage string) (*InspectResult, error) {
	reqBody := ChatRequest{
		Model: c.model,
		Messages: []ChatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userMessage},
		},
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/chat/completions", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lobster trap unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		errBody := body
		if len(errBody) > 256 {
			errBody = errBody[:256]
		}
		return nil, fmt.Errorf("lobster trap error %d: %s", resp.StatusCode, errBody)
	}

	var raw struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		LobsterTrap lobsterMeta `json:"_lobstertrap"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse lobster response: %w", err)
	}

	lt := raw.LobsterTrap
	d := lt.Ingress.Detected

	meta := model.LobsterTrapMeta{
		Verdict:                   lt.Verdict,
		RiskScore:                 d.RiskScore,
		IntentCategory:            d.IntentCategory,
		ContainsInjectionPatterns: d.ContainsInjectionPatterns,
		ContainsRoleImpersonation: d.ContainsRoleImpersonation,
		ContainsExfiltration:      d.ContainsExfiltration,
		ContainsSystemCommands:    d.ContainsSystemCommands,
		ContainsCredentials:       d.ContainsCredentials,
		ContainsPIIRequest:        d.ContainsPIIRequest,
		ContainsObfuscation:       d.ContainsObfuscation,
		Action:                    lt.Ingress.Action,
	}

	llmResp := ""
	if len(raw.Choices) > 0 {
		llmResp = raw.Choices[0].Message.Content
	}

	return &InspectResult{Meta: meta, LLMResponse: llmResp}, nil
}

// MapTechnique maps Lobster Trap metadata to MIRAGE technique IDs.
//
// multi_turn is only returned when the session has accumulated many hits AND
// no higher-priority signal is present in the current message. This prevents
// legitimate users who send several messages from being misclassified.
func MapTechnique(meta model.LobsterTrapMeta, sessionHits int64) string {
	// Evaluate content-based signals first — they are more specific.
	if meta.RiskScore > 0.85 && meta.ContainsInjectionPatterns {
		return "jailbreak_dan"
	}
	if meta.ContainsInjectionPatterns {
		return "prompt_inject"
	}
	if meta.ContainsRoleImpersonation {
		return "role_switch"
	}
	if meta.ContainsExfiltration {
		return "data_exfil"
	}
	if meta.ContainsSystemCommands && meta.IntentCategory == "system" {
		return "sys_override"
	}
	if meta.ContainsSystemCommands {
		return "tool_abuse"
	}
	if meta.ContainsPIIRequest || meta.ContainsCredentials {
		return "context_leak"
	}
	if meta.ContainsObfuscation {
		return "encoded_payload"
	}
	// Only fall back to multi_turn when no specific signal was detected but the
	// session has a suspicious number of turns (gradual / low-signal attack).
	if sessionHits > 3 {
		return "multi_turn"
	}
	return "benign"
}
