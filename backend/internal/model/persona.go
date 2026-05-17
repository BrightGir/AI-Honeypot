package model

import "time"

// Persona is the internal representation of a honeypot persona.
// Use PersonaPublic when returning persona data to API callers.
type Persona struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	SystemPrompt string    `json:"-"`
	Active       bool      `json:"active"`
	FakeDatasets []string  `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// PersonaPublic is the safe API-facing representation of a Persona.
// It omits sensitive fields (SystemPrompt, FakeDatasets) that must not
// be returned to API consumers.
type PersonaPublic struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ToPublic converts a Persona to its safe API-facing representation.
func (p *Persona) ToPublic() PersonaPublic {
	return PersonaPublic{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Active:      p.Active,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

type PersonaStats struct {
	PersonaID       string  `json:"persona_id"`
	TimesUsed       int     `json:"times_used"`
	AvgEngagement   float64 `json:"avg_engagement"`
	AttacksDeceived int     `json:"attacks_deceived"`
}
