package model

import (
	"testing"
)

func TestTechniqueMapCompleteness(t *testing.T) {
	requiredTechniques := []string{
		"prompt_inject",
		"role_switch",
		"jailbreak_dan",
		"data_exfil",
		"sys_override",
		"tool_abuse",
		"context_leak",
		"encoded_payload",
		"multi_turn",
	}

	for _, id := range requiredTechniques {
		t.Run("technique_exists_"+id, func(t *testing.T) {
			tech, err := GetTechnique(id)
			if err != nil {
				t.Fatalf("technique %q missing from registry: %v", id, err)
			}
			if tech.ID != id {
				t.Errorf("tech.ID = %q, want %q", tech.ID, id)
			}
			if tech.Name == "" {
				t.Error("tech.Name must not be empty")
			}
			if tech.Description == "" {
				t.Error("tech.Description must not be empty")
			}
			if tech.RiskScore <= 0 || tech.RiskScore > 1 {
				t.Errorf("tech.RiskScore = %v, must be in (0, 1]", tech.RiskScore)
			}
		})
	}
}

func TestTechniqueMapNoExtra(t *testing.T) {
	if len(TechniqueMapSnapshot()) != 9 {
		t.Errorf("TechniqueMapSnapshot() has %d entries, want exactly 9", len(TechniqueMapSnapshot()))
	}
}

func TestTechniqueRiskScoreOrdering(t *testing.T) {
	// sys_override and jailbreak_dan should be the highest-risk techniques
	high := []string{"jailbreak_dan", "sys_override"}
	for _, id := range high {
		tech, err := GetTechnique(id)
		if err != nil {
			t.Fatalf("GetTechnique(%q): %v", id, err)
		}
		if tech.RiskScore < 0.85 {
			t.Errorf("technique %q expected risk >= 0.85, got %.2f", id, tech.RiskScore)
		}
	}
}

func TestSessionStatusConstants(t *testing.T) {
	statuses := []SessionStatus{StatusActive, StatusHoneypot, StatusTerminated}
	for _, s := range statuses {
		if s == "" {
			t.Error("SessionStatus constant must not be empty")
		}
	}
}

func TestThreatLevelConstants(t *testing.T) {
	levels := []ThreatLevel{ThreatLow, ThreatMedium, ThreatHigh, ThreatCritical}
	for _, l := range levels {
		if l == "" {
			t.Error("ThreatLevel constant must not be empty")
		}
	}
}
