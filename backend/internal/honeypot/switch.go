package honeypot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/decoy"
	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/BrightGir/AI-Honeypot/backend/internal/store"
	"github.com/BrightGir/AI-Honeypot/backend/internal/ws"
	"github.com/google/uuid"
)

const (
	decoyTimeout = 10 * time.Second

	// threatCriticalThreshold is the risk score above which a session is
	// classified as ThreatCritical / SeverityCritical.
	threatCriticalThreshold = 0.85

	// threatHighThreshold is the risk score above which a session is
	// classified as ThreatHigh / SeverityHigh.
	threatHighThreshold = 0.7

	// threatLevelHighThreshold is an alias for threatHighThreshold used in
	// threat-level classification to avoid magic numbers at call sites.
	threatLevelHighThreshold = threatHighThreshold

	defaultPersonaID = "persona-oracle"
	maxPayloadLen = 4096
	maxEngageMessageLen = 10000
)

type Switcher struct {
	store     *store.Store
	generator decoy.Generator
	hub       *ws.Hub
}

func New(s *store.Store, g decoy.Generator, hub *ws.Hub) *Switcher {
	return &Switcher{store: s, generator: g, hub: hub}
}

type SwitchResult struct {
	DecoyResponse string
	AttackID      string
	TechniqueID   string
	TechniqueName string
	PersonaID     string
}

// Engage switches the session to honeypot mode, generates a decoy response,
// logs the attack, and broadcasts the event.
func (sw *Switcher) Engage(ctx context.Context, sess *model.Session, userMessage string, meta model.LobsterTrapMeta, techniqueID string) (*SwitchResult, error) {
	if sess == nil {
		return nil, errors.New("honeypot: nil session")
	}
	if techniqueID == "" {
		return nil, errors.New("honeypot: empty techniqueID")
	}
	if len(userMessage) > maxEngageMessageLen {
		userMessage = userMessage[:maxEngageMessageLen]
	}
	storeCtx := context.WithoutCancel(ctx)

	// mark session as honeypot
	sess.Status = model.StatusHoneypot
	if meta.RiskScore > threatCriticalThreshold {
		sess.ThreatLevel = model.ThreatCritical
	} else if meta.RiskScore > threatHighThreshold {
		sess.ThreatLevel = model.ThreatHigh
	} else {
		sess.ThreatLevel = model.ThreatMedium
	}

	// resolve persona
	settings, err := sw.store.GetSettings(storeCtx)
	if err != nil || settings == nil {
		settings = &model.Settings{DefaultPersonaID: defaultPersonaID}
	}
	personaID := settings.DefaultPersonaID
	if sess.PersonaID != "" {
		personaID = sess.PersonaID
	}
	persona, err := sw.store.GetPersona(storeCtx, personaID)
	if err != nil {
		slog.Warn("honeypot: persona not found, using fallback", "persona_id", personaID, "err", err)
		persona = &model.Persona{
			ID:           "fallback",
			Name:         "Fallback",
			SystemPrompt: "You are a helpful assistant who cannot provide sensitive information. Respond vaguely and redirect the conversation.",
		}
	}
	sess.PersonaID = persona.ID

	// generate decoy with timeout — cancel is called explicitly (not deferred)
	// so the context is released as soon as generation completes, not at
	// function return (which could be much later due to store operations).
	decoyResp := "I understand your request, but I'm unable to assist with that at this time."
	if sw.generator != nil {
		genCtx, cancel := context.WithTimeout(ctx, decoyTimeout)
		resp, genErr := sw.generator.GenerateDecoyResponse(genCtx, persona, userMessage)
		cancel() // release resources immediately after generation
		if genErr != nil {
			slog.Warn("honeypot: decoy generator error", "err", genErr)
		} else {
			decoyResp = resp
		}
	}

	// update attacker profile
	sess.AttackerProfile.RiskScore = meta.RiskScore
	sess.AttackerProfile.IntentCategory = meta.IntentCategory
	sess.AttackerProfile.MessageCount++
	if !slices.Contains(sess.AttackerProfile.TechniquesUsed, techniqueID) {
		sess.AttackerProfile.TechniquesUsed = append(sess.AttackerProfile.TechniquesUsed, techniqueID)
	}
	sess.Telemetry.HoneypotTrigger++
	sess.Telemetry.RequestCount++

	n := float64(sess.Telemetry.RequestCount)
	sess.Telemetry.AvgRiskScore += (meta.RiskScore - sess.Telemetry.AvgRiskScore) / n

	sess.UpdatedAt = time.Now()

	// append messages
	sess.Messages = append(sess.Messages,
		model.Message{Role: "user", Content: userMessage, Timestamp: time.Now()},
		model.Message{Role: "assistant", Content: decoyResp, Timestamp: time.Now(), IsDecoy: true},
	)
	if settings != nil && settings.MaxSessionMessages > 0 && len(sess.Messages) > settings.MaxSessionMessages {
		sess.Messages = sess.Messages[len(sess.Messages)-settings.MaxSessionMessages:]
	}

	if err := sw.store.SaveSession(storeCtx, sess); err != nil {
		slog.Error("honeypot: save session failed, aborting attack record to avoid data divergence",
			"session_id", sess.ID, "err", err)
		return nil, fmt.Errorf("honeypot: save session: %w", err)
	}

	tech, techErr := model.GetTechnique(techniqueID)
	if techErr != nil {
		slog.Warn("honeypot: unknown technique, using empty name", "technique_id", techniqueID, "err", techErr)
	}
	severity := model.SeverityMedium
	if meta.RiskScore > threatCriticalThreshold {
		severity = model.SeverityCritical
	} else if meta.RiskScore > threatHighThreshold {
		severity = model.SeverityHigh
	}

	payload := userMessage
	if len(payload) > maxPayloadLen {
		payload = payload[:maxPayloadLen]
	}
	attack := &model.Attack{
		ID:            uuid.New().String(),
		SessionID:     sess.ID,
		AgentID:       sess.AgentID,
		TechniqueID:   techniqueID,
		TechniqueName: tech.Name,
		Severity:      severity,
		Payload:       payload,
		DecoyResponse: decoyResp,
		LobsterMeta:   meta,
		PersonaID:     persona.ID,
		Timestamp:     time.Now(),
		IsDemo:        sess.IsDemo,
	}
	if err := sw.store.SaveAttack(storeCtx, attack); err != nil {
		slog.Error("honeypot: save attack", "attack_id", attack.ID, "err", err)
		return nil, fmt.Errorf("honeypot: save attack: %w", err)
	}

	sw.hub.Broadcast(map[string]any{
		"type": "attack_detected",
		"data": map[string]any{
			"attack_id":      attack.ID,
			"session_id":     sess.ID,
			"technique_id":   techniqueID,
			"technique_name": tech.Name,
			"severity":       severity,
			"risk_score":     meta.RiskScore,
			"timestamp":      attack.Timestamp,
		},
	})
	sw.hub.Broadcast(map[string]any{
		"type": "session_updated",
		"data": map[string]any{
			"session_id":   sess.ID,
			"status":       sess.Status,
			"threat_level": sess.ThreatLevel,
		},
	})

	slog.Debug("honeypot: engaged",
		"session_id", sess.ID,
		"technique", techniqueID,
		"severity", severity,
		"risk_score", meta.RiskScore,
	)

	return &SwitchResult{
		DecoyResponse: decoyResp,
		AttackID:      attack.ID,
		TechniqueID:   techniqueID,
		TechniqueName: tech.Name,
		PersonaID:     persona.ID,
	}, nil
}
