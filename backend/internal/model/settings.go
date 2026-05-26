package model

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// validEdgeDataRetentions is the set of accepted EdgeDataRetention values.
var validEdgeDataRetentions = map[string]bool{
	"1d": true, "7d": true, "30d": true, "90d": true,
}

// validTrapDepths is the set of accepted TrapDepth values.
var validTrapDepths = map[string]bool{
	"shallow": true, "medium": true, "deep": true,
}

// UpstreamConfig holds the customer's real LLM endpoint configuration.
// When set, benign (non-malicious) requests are forwarded here transparently.
// Malicious requests are intercepted before reaching the upstream.
type UpstreamConfig struct {
	// ProviderType selects the request/response format.
	// Valid values: "openai" (default), "anthropic", "raw".
	ProviderType string `json:"provider_type"`
	// BaseURL is the endpoint root for openai/anthropic, or the full URL for raw.
	BaseURL string `json:"base_url"`
	// Model is the LLM model name (not used for raw provider).
	Model string `json:"model"`
	// SystemPrompt is the customer's own system prompt (not used for raw provider).
	SystemPrompt string `json:"system_prompt"`
	// APIKey is stored encrypted in a separate Redis key and NEVER returned in
	// API responses. json:"-" ensures it is never serialised.
	APIKey string `json:"-"`
	// APIKeySet indicates whether an API key has been saved (without exposing it).
	APIKeySet bool `json:"api_key_set"`
	// Enabled controls whether the upstream forwarding is active.
	Enabled bool `json:"enabled"`
}

type Settings struct {
	HoneypotThreshold  float64  `json:"honeypot_threshold"`
	QuarantineMode     bool     `json:"quarantine_mode"`
	DemoMode           bool     `json:"demo_mode"`
	DefaultPersonaID   string   `json:"default_persona_id"`
	CORSOrigins        []string `json:"cors_origins"`
	MaxSessionMessages int      `json:"max_session_messages"`
	AutoBurnAfterTurns int      `json:"auto_burn_after_turns"`
	EgressDomains      []string `json:"egress_domains"`
	// EdgeDataRetention controls how long sessions and attacks are kept in Redis.
	// Valid values: "1d", "7d", "30d", "90d". Defaults to "30d" when empty.
	EdgeDataRetention string `json:"edge_data_retention"`
	// TrapDepth controls the verbosity of decoy responses.
	// Valid values: "shallow", "medium", "deep". Defaults to "medium" when empty.
	TrapDepth string `json:"trap_depth,omitempty"`
	// Upstream is the customer's real LLM configuration for transparent proxying.
	Upstream UpstreamConfig `json:"upstream"`
}

// Validate checks that Settings fields contain valid values.
// EdgeDataRetention must be one of "1d", "7d", "30d", "90d" (or empty, which
// defaults to "30d"). TrapDepth must be one of "shallow", "medium", "deep"
// (or empty, which defaults to "medium").
func (s Settings) Validate() error {
	var errs []error

	if s.EdgeDataRetention != "" && !validEdgeDataRetentions[s.EdgeDataRetention] {
		errs = append(errs, fmt.Errorf(
			"settings: EdgeDataRetention %q is invalid; must be one of 1d, 7d, 30d, 90d",
			s.EdgeDataRetention,
		))
	}

	if s.TrapDepth != "" && !validTrapDepths[s.TrapDepth] {
		errs = append(errs, fmt.Errorf(
			"settings: TrapDepth %q is invalid; must be one of shallow, medium, deep",
			s.TrapDepth,
		))
	}

	return errors.Join(errs...)
}

type IntegrationStatus string

const (
	IntegrationConnected    IntegrationStatus = "connected"
	IntegrationDisconnected IntegrationStatus = "disconnected"
	IntegrationError        IntegrationStatus = "error"
)

type Integration struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Status   IntegrationStatus `json:"status"`
	Endpoint string            `json:"endpoint,omitempty"`
	LastChecked *time.Time        `json:"last_checked,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
	// ApiKey holds the integration's secret credential.
	// It is stored encrypted in Redis and NEVER returned in API responses.
	// The json:"-" tag ensures it is never serialised into any API response.
	ApiKey string `json:"-"`
}

// String masks the ApiKey so it never appears in logs or fmt.Sprintf("%+v", ...) output.
func (i Integration) String() string {
	masked := ""
	if i.ApiKey != "" {
		masked = "***"
	}
	return fmt.Sprintf("Integration{ID:%s Name:%s Type:%s Status:%s ApiKey:%s}",
		i.ID, i.Name, i.Type, i.Status, masked)
}

// LogValue implements [slog.LogValuer] so that when an Integration value is
// passed to slog (directly or via reflection), ApiKey is replaced with the
// literal string "[REDACTED]" rather than its actual value.
func (i Integration) LogValue() slog.Value {
	masked := ""
	if i.ApiKey != "" {
		masked = "[REDACTED]"
	}
	return slog.GroupValue(
		slog.String("id", i.ID),
		slog.String("name", i.Name),
		slog.String("type", i.Type),
		slog.String("status", string(i.Status)),
		slog.String("endpoint", i.Endpoint),
		slog.String("api_key", masked),
	)
}

type LobsterTelemetry struct {
	TotalRequests  int     `json:"total_requests"`
	BlockedCount   int     `json:"blocked_count"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	UptimeSeconds  int64   `json:"uptime_seconds"`
}
