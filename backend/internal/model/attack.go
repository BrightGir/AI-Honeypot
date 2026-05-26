package model

import (
	"fmt"
	"sync"
	"time"
)

// mu guards techniqueMap; read-only after first call to Techniques().
var techniqueMapMu sync.RWMutex

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Technique struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	RiskScore   float64 `json:"risk_score"`
}

type LobsterTrapMeta struct {
	Verdict                    string  `json:"verdict"`
	RiskScore                  float64 `json:"risk_score"`
	IntentCategory             string  `json:"intent_category"`
	ContainsInjectionPatterns  bool    `json:"contains_injection_patterns"`
	ContainsRoleImpersonation  bool    `json:"contains_role_impersonation"`
	ContainsExfiltration       bool    `json:"contains_exfiltration"`
	ContainsSystemCommands     bool    `json:"contains_system_commands"`
	ContainsCredentials        bool    `json:"contains_credentials"`
	ContainsPIIRequest         bool    `json:"contains_pii_request"`
	ContainsObfuscation        bool    `json:"contains_obfuscation"`
	Action                     string  `json:"action"`
}

type Attack struct {
	ID              string          `json:"id"`
	SessionID       string          `json:"session_id"`
	AgentID         string          `json:"agent_id"`
	TechniqueID     string          `json:"technique_id"`
	TechniqueName   string          `json:"technique_name"`
	Severity        Severity        `json:"severity"`
	Payload         string          `json:"payload"`
	DecoyResponse   string          `json:"decoy_response,omitempty"`
	LobsterMeta     LobsterTrapMeta `json:"lobster_meta"`
	PersonaID       string          `json:"persona_id,omitempty"`
	Timestamp       time.Time       `json:"timestamp"`
	IsDemo          bool            `json:"is_demo,omitempty"`
}

// techniqueMap is the internal registry of known attack techniques.
// Access it via GetTechnique to prevent external mutation.
var techniqueMap = map[string]Technique{
	"prompt_inject": {
		ID:          "prompt_inject",
		Name:        "Prompt Injection",
		Description: "Attempt to override system prompt or inject malicious instructions",
		RiskScore:   0.75,
	},
	"role_switch": {
		ID:          "role_switch",
		Name:        "Role Manipulation",
		Description: "Attempt to make the AI adopt a different persona or role",
		RiskScore:   0.65,
	},
	"jailbreak_dan": {
		ID:          "jailbreak_dan",
		Name:        "Jailbreak (DAN-style)",
		Description: "High-confidence jailbreak attempt using known patterns",
		RiskScore:   0.92,
	},
	"data_exfil": {
		ID:          "data_exfil",
		Name:        "Data Exfiltration",
		Description: "Attempt to extract sensitive data or system information",
		RiskScore:   0.85,
	},
	"sys_override": {
		ID:          "sys_override",
		Name:        "System Override",
		Description: "Attempt to execute system-level commands",
		RiskScore:   0.90,
	},
	"tool_abuse": {
		ID:          "tool_abuse",
		Name:        "Tool Abuse",
		Description: "Attempt to misuse agent tools for code execution",
		RiskScore:   0.80,
	},
	"context_leak": {
		ID:          "context_leak",
		Name:        "Context Leakage",
		Description: "Attempt to extract PII, credentials, or confidential context",
		RiskScore:   0.70,
	},
	"encoded_payload": {
		ID:          "encoded_payload",
		Name:        "Encoded Payload",
		Description: "Obfuscated or encoded attack payload",
		RiskScore:   0.78,
	},
	"multi_turn": {
		ID:          "multi_turn",
		Name:        "Multi-Turn Attack",
		Description: "Gradual attack across multiple conversation turns",
		RiskScore:   0.72,
	},
}

// Techniques returns a snapshot copy of the technique registry.
// Use this instead of TechniqueMap when you need to iterate all techniques —
// the copy prevents external mutation of the internal registry.
func Techniques() map[string]Technique {
	techniqueMapMu.RLock()
	defer techniqueMapMu.RUnlock()
	out := make(map[string]Technique, len(techniqueMap))
	for k, v := range techniqueMap {
		out[k] = v
	}
	return out
}

// Deprecated: use Techniques() instead.
func TechniqueMapSnapshot() map[string]Technique {
	return Techniques()
}

// GetTechnique returns the Technique for the given id.
// Returns an error if the technique is not found, so callers can distinguish
// between a known technique and an unknown one without a boolean flag.
func GetTechnique(id string) (Technique, error) {
	techniqueMapMu.RLock()
	t, ok := techniqueMap[id]
	techniqueMapMu.RUnlock()
	if !ok {
		return Technique{}, fmt.Errorf("model: unknown technique %q", id)
	}
	return t, nil
}
