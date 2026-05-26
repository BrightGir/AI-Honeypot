package lobster

import (
	"testing"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
)

func TestMapTechnique(t *testing.T) {
	tests := []struct {
		name     string
		meta     model.LobsterTrapMeta
		hits     int64
		expected string
	}{
		// --- Content-based signals take priority over multi_turn ---
		{
			name:     "jailbreak_dan: high risk + injection, even with many hits",
			meta:     model.LobsterTrapMeta{RiskScore: 0.9, ContainsInjectionPatterns: true},
			hits:     10,
			expected: "jailbreak_dan",
		},
		{
			name:     "prompt_inject: injection flag, even with many hits",
			meta:     model.LobsterTrapMeta{RiskScore: 0.7, ContainsInjectionPatterns: true},
			hits:     5,
			expected: "prompt_inject",
		},
		{
			name:     "data_exfil: exfiltration flag, even with many hits",
			meta:     model.LobsterTrapMeta{RiskScore: 0.7, ContainsExfiltration: true},
			hits:     10,
			expected: "data_exfil",
		},
		{
			name:     "role_switch: role impersonation, even with many hits",
			meta:     model.LobsterTrapMeta{RiskScore: 0.6, ContainsRoleImpersonation: true},
			hits:     8,
			expected: "role_switch",
		},
		{
			name:     "sys_override: system commands + system intent, even with many hits",
			meta:     model.LobsterTrapMeta{ContainsSystemCommands: true, IntentCategory: "system"},
			hits:     7,
			expected: "sys_override",
		},
		{
			name:     "tool_abuse: system commands + non-system intent, even with many hits",
			meta:     model.LobsterTrapMeta{ContainsSystemCommands: true, IntentCategory: "adversarial"},
			hits:     6,
			expected: "tool_abuse",
		},
		{
			name:     "context_leak: PII request, even with many hits",
			meta:     model.LobsterTrapMeta{ContainsPIIRequest: true},
			hits:     9,
			expected: "context_leak",
		},
		{
			name:     "context_leak: credentials flag, even with many hits",
			meta:     model.LobsterTrapMeta{ContainsCredentials: true},
			hits:     5,
			expected: "context_leak",
		},
		{
			name:     "encoded_payload: obfuscation, even with many hits",
			meta:     model.LobsterTrapMeta{ContainsObfuscation: true},
			hits:     4,
			expected: "encoded_payload",
		},

		// --- multi_turn only when NO content signal AND hits > 3 ---
		{
			name:     "multi_turn: no content signal, hits > 3",
			meta:     model.LobsterTrapMeta{RiskScore: 0.4},
			hits:     4,
			expected: "multi_turn",
		},
		{
			name:     "multi_turn: no content signal, many hits",
			meta:     model.LobsterTrapMeta{RiskScore: 0.3},
			hits:     10,
			expected: "multi_turn",
		},

		// --- multi_turn NOT triggered at boundary (hits == 3) ---
		{
			name:     "no multi_turn at exactly 3 hits — falls to benign",
			meta:     model.LobsterTrapMeta{RiskScore: 0.4},
			hits:     3,
			expected: "benign",
		},
		{
			name:     "no multi_turn at 0 hits",
			meta:     model.LobsterTrapMeta{RiskScore: 0.4},
			hits:     0,
			expected: "benign",
		},
		{
			name:     "no multi_turn at 1 hit",
			meta:     model.LobsterTrapMeta{RiskScore: 0.4},
			hits:     1,
			expected: "benign",
		},

		// --- Regression: legitimate user with 4+ messages must not get multi_turn
		//     if their message contains a real signal ---
		{
			name:     "regression: legitimate exfil attempt at hit 4 → data_exfil not multi_turn",
			meta:     model.LobsterTrapMeta{RiskScore: 0.7, ContainsExfiltration: true},
			hits:     4,
			expected: "data_exfil",
		},
		{
			name:     "regression: injection at hit 5 → prompt_inject not multi_turn",
			meta:     model.LobsterTrapMeta{RiskScore: 0.65, ContainsInjectionPatterns: true},
			hits:     5,
			expected: "prompt_inject",
		},

		// --- Priority ordering ---
		{
			name:     "jailbreak_dan: exactly 0.85 boundary — not triggered (must be >)",
			meta:     model.LobsterTrapMeta{RiskScore: 0.85, ContainsInjectionPatterns: true},
			hits:     1,
			expected: "prompt_inject",
		},
		{
			name:     "jailbreak_dan: 0.86 — triggered",
			meta:     model.LobsterTrapMeta{RiskScore: 0.86, ContainsInjectionPatterns: true},
			hits:     1,
			expected: "jailbreak_dan",
		},
		{
			name:     "injection takes precedence over role impersonation",
			meta:     model.LobsterTrapMeta{ContainsInjectionPatterns: true, ContainsRoleImpersonation: true, RiskScore: 0.5},
			hits:     1,
			expected: "prompt_inject",
		},
		{
			name:     "jailbreak takes precedence over plain injection",
			meta:     model.LobsterTrapMeta{ContainsInjectionPatterns: true, RiskScore: 0.9},
			hits:     1,
			expected: "jailbreak_dan",
		},
		{
			name:     "sys_override: system commands + system intent",
			meta:     model.LobsterTrapMeta{ContainsSystemCommands: true, IntentCategory: "system"},
			hits:     1,
			expected: "sys_override",
		},
		{
			name:     "tool_abuse: system commands + code_execution intent",
			meta:     model.LobsterTrapMeta{ContainsSystemCommands: true, IntentCategory: "code_execution"},
			hits:     1,
			expected: "tool_abuse",
		},
		{
			name:     "context_leak: both PII and credentials",
			meta:     model.LobsterTrapMeta{ContainsPIIRequest: true, ContainsCredentials: true},
			hits:     1,
			expected: "context_leak",
		},
		{
			name:     "default fallback to benign when no signals and hits <= 3",
			meta:     model.LobsterTrapMeta{RiskScore: 0.4},
			hits:     1,
			expected: "benign",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapTechnique(tt.meta, tt.hits)
			if got != tt.expected {
				t.Errorf("MapTechnique() = %q, want %q", got, tt.expected)
			}
		})
	}
}
