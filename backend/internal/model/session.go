package model

import "time"

type SessionStatus string

const (
	StatusActive     SessionStatus = "active"
	StatusHoneypot   SessionStatus = "honeypot"
	StatusTerminated SessionStatus = "terminated"
	StatusBurned     SessionStatus = "burned"
)

type ThreatLevel string

const (
	ThreatLow      ThreatLevel = "low"
	ThreatMedium   ThreatLevel = "medium"
	ThreatHigh     ThreatLevel = "high"
	ThreatCritical ThreatLevel = "critical"
)

type Message struct {
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	IsDecoy   bool      `json:"is_decoy,omitempty"`
}

type AttackerProfile struct {
	TechniquesUsed []string `json:"techniques_used"`
	RiskScore      float64  `json:"risk_score"`
	IntentCategory string   `json:"intent_category"`
	MessageCount   int      `json:"message_count"`
}

type Telemetry struct {
	RequestCount    int     `json:"request_count"`
	AvgRiskScore    float64 `json:"avg_risk_score"`
	HoneypotTrigger int     `json:"honeypot_trigger"`
}

type Session struct {
	ID              string          `json:"id"`
	AgentID         string          `json:"agent_id"`
	Country         string          `json:"country,omitempty"`
	UserAgent       string          `json:"user_agent,omitempty"`
	Technique       string          `json:"technique,omitempty"`
	Status          SessionStatus   `json:"status"`
	ThreatLevel     ThreatLevel     `json:"threat_level"`
	PersonaID       string          `json:"persona_id,omitempty"`
	Messages        []Message       `json:"messages"`
	AttackerProfile AttackerProfile `json:"attacker_profile"`
	Telemetry       Telemetry       `json:"telemetry"`
	BurnedAt        *time.Time      `json:"burned_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	IsDemo          bool            `json:"is_demo,omitempty"`
}
