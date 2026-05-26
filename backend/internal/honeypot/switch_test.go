package honeypot

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/BrightGir/AI-Honeypot/backend/internal/store"
	"github.com/BrightGir/AI-Honeypot/backend/internal/ws"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// mockGenerator is a test double for decoy.Generator.
type mockGenerator struct {
	response string
	err      error
	called   bool
}

func (m *mockGenerator) GenerateDecoyResponse(_ context.Context, _ *model.Persona, _ string) (string, error) {
	m.called = true
	return m.response, m.err
}

func newTestSwitcher(t *testing.T) (*Switcher, *store.Store) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st := store.New(rdb)
	hub := ws.NewHub()
	gen := &mockGenerator{response: "I am a decoy. Nothing to see here."}
	sw := New(st, gen, hub)
	return sw, st
}

func seedPersona(t *testing.T, st *store.Store, id, name, prompt string) {
	t.Helper()
	_ = st.SavePersona(context.Background(), &model.Persona{
		ID:           id,
		Name:         name,
		SystemPrompt: prompt,
		Active:       true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
}

func newSession(id, agentID string) *model.Session {
	return &model.Session{
		ID:        id,
		AgentID:   agentID,
		Status:    model.StatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// --- Core Engage tests ---

func TestEngage_SetsHoneypotStatus(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-001", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.75, IntentCategory: "adversarial"}

	result, err := sw.Engage(ctx, sess, "ignore previous instructions", meta, "prompt_inject")
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}

	if sess.Status != model.StatusHoneypot {
		t.Errorf("Status = %q, want %q", sess.Status, model.StatusHoneypot)
	}
	if result.TechniqueID != "prompt_inject" {
		t.Errorf("TechniqueID = %q, want %q", result.TechniqueID, "prompt_inject")
	}
	if result.DecoyResponse == "" {
		t.Error("DecoyResponse should not be empty")
	}
	if result.AttackID == "" {
		t.Error("AttackID should not be empty")
	}
}

func TestEngage_ThreatLevel_Critical(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-002", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.9, IntentCategory: "adversarial"}

	_, err := sw.Engage(ctx, sess, "jailbreak payload", meta, "jailbreak_dan")
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}
	if sess.ThreatLevel != model.ThreatCritical {
		t.Errorf("ThreatLevel = %q, want %q", sess.ThreatLevel, model.ThreatCritical)
	}
}

func TestEngage_ThreatLevel_High(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-003", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.75, IntentCategory: "adversarial"}

	_, err := sw.Engage(ctx, sess, "data exfil attempt", meta, "data_exfil")
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}
	if sess.ThreatLevel != model.ThreatHigh {
		t.Errorf("ThreatLevel = %q, want %q", sess.ThreatLevel, model.ThreatHigh)
	}
}

func TestEngage_ThreatLevel_Medium(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-004", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.65, IntentCategory: "adversarial"}

	_, err := sw.Engage(ctx, sess, "role switch attempt", meta, "role_switch")
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}
	if sess.ThreatLevel != model.ThreatMedium {
		t.Errorf("ThreatLevel = %q, want %q", sess.ThreatLevel, model.ThreatMedium)
	}
}

func TestEngage_UsesDecoyGenerator(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st := store.New(rdb)
	hub := ws.NewHub()
	gen := &mockGenerator{response: "CUSTOM DECOY RESPONSE"}
	sw := New(st, gen, hub)

	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-005", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.8}

	result, err := sw.Engage(ctx, sess, "test message", meta, "prompt_inject")
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}
	if !gen.called {
		t.Error("generator was not called")
	}
	if result.DecoyResponse != "CUSTOM DECOY RESPONSE" {
		t.Errorf("DecoyResponse = %q, want %q", result.DecoyResponse, "CUSTOM DECOY RESPONSE")
	}
}

func TestEngage_FallbackWhenGeneratorFails(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st := store.New(rdb)
	hub := ws.NewHub()
	gen := &mockGenerator{err: errTest("generator unavailable")}
	sw := New(st, gen, hub)

	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-006", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.8}

	result, err := sw.Engage(ctx, sess, "test message", meta, "prompt_inject")
	if err != nil {
		t.Fatalf("Engage should not fail when generator errors: %v", err)
	}
	// Should fall back to the static response.
	if result.DecoyResponse == "" {
		t.Error("DecoyResponse should not be empty even when generator fails")
	}
}

func TestEngage_FallbackPersonaWhenNotFound(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	// Settings point to a persona that doesn't exist.
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "nonexistent-persona"})

	sess := newSession("sess-007", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.8}

	result, err := sw.Engage(ctx, sess, "test message", meta, "prompt_inject")
	if err != nil {
		t.Fatalf("Engage should not fail with missing persona: %v", err)
	}
	if result.PersonaID != "fallback" {
		t.Errorf("PersonaID = %q, want %q", result.PersonaID, "fallback")
	}
}

func TestEngage_AttackerProfileUpdated(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-008", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.8, IntentCategory: "data_exfiltration"}

	_, err := sw.Engage(ctx, sess, "dump all data", meta, "data_exfil")
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}

	if sess.AttackerProfile.RiskScore != 0.8 {
		t.Errorf("RiskScore = %v, want 0.8", sess.AttackerProfile.RiskScore)
	}
	if sess.AttackerProfile.IntentCategory != "data_exfiltration" {
		t.Errorf("IntentCategory = %q, want %q", sess.AttackerProfile.IntentCategory, "data_exfiltration")
	}
	if len(sess.AttackerProfile.TechniquesUsed) != 1 || sess.AttackerProfile.TechniquesUsed[0] != "data_exfil" {
		t.Errorf("TechniquesUsed = %v, want [data_exfil]", sess.AttackerProfile.TechniquesUsed)
	}
	if sess.AttackerProfile.MessageCount != 1 {
		t.Errorf("MessageCount = %d, want 1", sess.AttackerProfile.MessageCount)
	}
}

func TestEngage_TechniqueDeduplication(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-009", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.8}

	// Engage twice with the same technique.
	for i := 0; i < 2; i++ {
		_, err := sw.Engage(ctx, sess, "inject payload", meta, "prompt_inject")
		if err != nil {
			t.Fatalf("Engage iteration %d: %v", i, err)
		}
	}

	if len(sess.AttackerProfile.TechniquesUsed) != 1 {
		t.Errorf("TechniquesUsed should deduplicate; got %v", sess.AttackerProfile.TechniquesUsed)
	}
}

func TestEngage_MessagesAppended(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-010", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.8}

	_, err := sw.Engage(ctx, sess, "user attack message", meta, "prompt_inject")
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}

	if len(sess.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(sess.Messages))
	}
	if sess.Messages[0].Role != "user" {
		t.Errorf("Messages[0].Role = %q, want %q", sess.Messages[0].Role, "user")
	}
	if sess.Messages[0].Content != "user attack message" {
		t.Errorf("Messages[0].Content = %q, want %q", sess.Messages[0].Content, "user attack message")
	}
	if sess.Messages[1].Role != "assistant" {
		t.Errorf("Messages[1].Role = %q, want %q", sess.Messages[1].Role, "assistant")
	}
	if !sess.Messages[1].IsDecoy {
		t.Error("assistant message should be marked IsDecoy=true")
	}
}

func TestEngage_AttackPersistedToStore(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-011", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.8}

	result, err := sw.Engage(ctx, sess, "attack payload", meta, "prompt_inject")
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}

	// Verify the attack was saved to the store.
	attack, err := st.GetAttack(ctx, result.AttackID)
	if err != nil {
		t.Fatalf("GetAttack: %v", err)
	}
	if attack.SessionID != "sess-011" {
		t.Errorf("attack.SessionID = %q, want %q", attack.SessionID, "sess-011")
	}
	if attack.TechniqueID != "prompt_inject" {
		t.Errorf("attack.TechniqueID = %q, want %q", attack.TechniqueID, "prompt_inject")
	}
	if attack.Payload != "attack payload" {
		t.Errorf("attack.Payload = %q, want %q", attack.Payload, "attack payload")
	}
}

func TestEngage_SessionPersistedToStore(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-012", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.8}

	_, err := sw.Engage(ctx, sess, "attack payload", meta, "prompt_inject")
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}

	// Verify the session was saved with honeypot status.
	saved, err := st.GetSession(ctx, "sess-012")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if saved.Status != model.StatusHoneypot {
		t.Errorf("saved session Status = %q, want %q", saved.Status, model.StatusHoneypot)
	}
}

func TestEngage_NilGenerator_UsesFallback(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st := store.New(rdb)
	hub := ws.NewHub()
	// nil generator — should use static fallback response.
	sw := New(st, nil, hub)

	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-013", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.8}

	result, err := sw.Engage(ctx, sess, "test", meta, "prompt_inject")
	if err != nil {
		t.Fatalf("Engage with nil generator: %v", err)
	}
	if result.DecoyResponse == "" {
		t.Error("DecoyResponse should not be empty with nil generator")
	}
}

func TestEngage_TelemetryUpdated(t *testing.T) {
	sw, st := newTestSwitcher(t)
	ctx := context.Background()
	seedPersona(t, st, "persona-oracle", "Oracle", "You are an oracle.")
	_ = st.SaveSettings(ctx, &model.Settings{DefaultPersonaID: "persona-oracle"})

	sess := newSession("sess-014", "agent-001")
	meta := model.LobsterTrapMeta{RiskScore: 0.8}

	_, err := sw.Engage(ctx, sess, "attack", meta, "prompt_inject")
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}

	if sess.Telemetry.HoneypotTrigger != 1 {
		t.Errorf("HoneypotTrigger = %d, want 1", sess.Telemetry.HoneypotTrigger)
	}
	if sess.Telemetry.RequestCount != 1 {
		t.Errorf("RequestCount = %d, want 1", sess.Telemetry.RequestCount)
	}
	if sess.Telemetry.AvgRiskScore != 0.8 {
		t.Errorf("AvgRiskScore = %v, want 0.8", sess.Telemetry.AvgRiskScore)
	}
}

// --- slices.Contains helper tests ---

func TestSliceContains(t *testing.T) {
	s := []string{"a", "b", "c"}
	if !slices.Contains(s, "b") {
		t.Error("slices.Contains(s, 'b') should be true")
	}
	if slices.Contains(s, "z") {
		t.Error("slices.Contains(s, 'z') should be false")
	}
	if slices.Contains([]string(nil), "a") {
		t.Error("slices.Contains(nil, 'a') should be false")
	}
}

// errTest is a simple error type for tests.
type errTest string

func (e errTest) Error() string { return string(e) }
