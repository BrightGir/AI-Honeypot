package store

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestStore spins up an in-process miniredis and returns a Store backed by it.
func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return New(rdb), mr
}

// --- Session tests ---

func TestSaveAndGetSession(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	sess := &model.Session{
		ID:        "sess-001",
		AgentID:   "agent-001",
		Status:    model.StatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	got, err := s.GetSession(ctx, "sess-001")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want %q", got.AgentID, "agent-001")
	}
	if got.Status != model.StatusActive {
		t.Errorf("Status = %q, want %q", got.Status, model.StatusActive)
	}
}

func TestSaveSession_TTLIsSet(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	// Seed settings with 1d retention so TTL is applied.
	_ = s.SaveSettings(ctx, &model.Settings{EdgeDataRetention: "1d"})

	sess := &model.Session{
		ID:        "sess-ttl",
		AgentID:   "agent-001",
		Status:    model.StatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	ttl := mr.TTL(sessionKey("sess-ttl"))
	if ttl <= 0 {
		t.Errorf("expected positive TTL on session key, got %v", ttl)
	}
	// 1d = 86400s; allow a small margin for test execution time.
	if ttl > 25*time.Hour {
		t.Errorf("TTL %v exceeds 1d retention", ttl)
	}
}

func TestListSessions_Pipeline(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Insert 5 sessions.
	for i := 0; i < 5; i++ {
		sess := &model.Session{
			ID:        "sess-" + strconv.Itoa(i),
			AgentID:   "agent-001",
			Status:    model.StatusActive,
			CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
			UpdatedAt: time.Now(),
		}
		if err := s.SaveSession(ctx, sess); err != nil {
			t.Fatalf("SaveSession %d: %v", i, err)
		}
	}

	sessions, err := s.ListSessions(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 5 {
		t.Errorf("ListSessions returned %d sessions, want 5", len(sessions))
	}
}

func TestListSessions_Empty(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	sessions, err := s.ListSessions(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListSessions on empty store: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestCountSessions(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_ = s.SaveSession(ctx, &model.Session{
			ID:        "sess-" + strconv.Itoa(i),
			AgentID:   "a",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}
	n, err := s.CountSessions(ctx)
	if err != nil {
		t.Fatalf("CountSessions: %v", err)
	}
	if n != 3 {
		t.Errorf("CountSessions = %d, want 3", n)
	}
}

// --- Attack tests ---

func TestSaveAndGetAttack(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	attack := &model.Attack{
		ID:          "atk-001",
		SessionID:   "sess-001",
		TechniqueID: "prompt_inject",
		Severity:    model.SeverityHigh,
		Timestamp:   time.Now(),
	}
	if err := s.SaveAttack(ctx, attack); err != nil {
		t.Fatalf("SaveAttack: %v", err)
	}

	got, err := s.GetAttack(ctx, "atk-001")
	if err != nil {
		t.Fatalf("GetAttack: %v", err)
	}
	if got.TechniqueID != "prompt_inject" {
		t.Errorf("TechniqueID = %q, want %q", got.TechniqueID, "prompt_inject")
	}
}

func TestSaveAttack_TTLIsSet(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	_ = s.SaveSettings(ctx, &model.Settings{EdgeDataRetention: "7d"})

	attack := &model.Attack{
		ID:        "atk-ttl",
		SessionID: "sess-001",
		Timestamp: time.Now(),
	}
	if err := s.SaveAttack(ctx, attack); err != nil {
		t.Fatalf("SaveAttack: %v", err)
	}

	ttl := mr.TTL(attackKey("atk-ttl"))
	if ttl <= 0 {
		t.Errorf("expected positive TTL on attack key, got %v", ttl)
	}
}

func TestListAttacks_Pipeline(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		_ = s.SaveAttack(ctx, &model.Attack{
			ID:        "atk-" + strconv.Itoa(i),
			SessionID: "sess-001",
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
		})
	}

	attacks, err := s.ListAttacks(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListAttacks: %v", err)
	}
	if len(attacks) != 4 {
		t.Errorf("ListAttacks returned %d, want 4", len(attacks))
	}
}

func TestListAttacks_Empty(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	attacks, err := s.ListAttacks(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListAttacks on empty store: %v", err)
	}
	if len(attacks) != 0 {
		t.Errorf("expected 0 attacks, got %d", len(attacks))
	}
}

// --- Rule tests ---

func TestSaveAndListRules_Pipeline(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	rules := []*model.Rule{
		{ID: "r1", Name: "Rule 1", TechniqueID: "prompt_inject", Enabled: true, Action: model.RuleActionLog, Threshold: 0.6, Priority: 100},
		{ID: "r2", Name: "Rule 2", TechniqueID: "jailbreak_dan", Enabled: true, Action: model.RuleActionQuarantine, Threshold: 0.85, Priority: 90},
		{ID: "r3", Name: "Rule 3", TechniqueID: "data_exfil", Enabled: false, Action: model.RuleActionAllow, Threshold: 0.5, Priority: 50},
	}
	for _, r := range rules {
		if err := s.SaveRule(ctx, r); err != nil {
			t.Fatalf("SaveRule %q: %v", r.ID, err)
		}
	}

	got, err := s.ListRules(ctx)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("ListRules returned %d, want 3", len(got))
	}
}

func TestDeleteRule(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	_ = s.SaveRule(ctx, &model.Rule{ID: "r1", Name: "Rule 1"})
	_ = s.SaveRule(ctx, &model.Rule{ID: "r2", Name: "Rule 2"})

	if err := s.DeleteRule(ctx, "r1"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}

	rules, _ := s.ListRules(ctx)
	for _, r := range rules {
		if r.ID == "r1" {
			t.Error("deleted rule r1 still present in ListRules")
		}
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule after delete, got %d", len(rules))
	}
}

// --- Persona tests ---

func TestSaveAndListPersonas_Pipeline(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	personas := []*model.Persona{
		{ID: "p1", Name: "Oracle", SystemPrompt: "You are an oracle."},
		{ID: "p2", Name: "Confused", SystemPrompt: "You are confused."},
	}
	for _, p := range personas {
		if err := s.SavePersona(ctx, p); err != nil {
			t.Fatalf("SavePersona %q: %v", p.ID, err)
		}
	}

	got, err := s.ListPersonas(ctx)
	if err != nil {
		t.Fatalf("ListPersonas: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ListPersonas returned %d, want 2", len(got))
	}
}

func TestDeletePersona(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	_ = s.SavePersona(ctx, &model.Persona{ID: "p1", Name: "Oracle"})
	_ = s.SavePersona(ctx, &model.Persona{ID: "p2", Name: "Confused"})

	if err := s.DeletePersona(ctx, "p1"); err != nil {
		t.Fatalf("DeletePersona: %v", err)
	}

	personas, _ := s.ListPersonas(ctx)
	for _, p := range personas {
		if p.ID == "p1" {
			t.Error("deleted persona p1 still present in ListPersonas")
		}
	}
}

// --- Settings tests ---

func TestSaveAndGetSettings(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	settings := &model.Settings{
		HoneypotThreshold: 0.7,
		DemoMode:          true,
		EdgeDataRetention: "7d",
		DefaultPersonaID:  "persona-oracle",
	}
	if err := s.SaveSettings(ctx, settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	got, err := s.GetSettings(ctx)
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got.HoneypotThreshold != 0.7 {
		t.Errorf("HoneypotThreshold = %v, want 0.7", got.HoneypotThreshold)
	}
	if got.EdgeDataRetention != "7d" {
		t.Errorf("EdgeDataRetention = %q, want %q", got.EdgeDataRetention, "7d")
	}
}

// --- Panic mode tests ---

func TestPanicMode(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	on, err := s.GetPanicMode(ctx)
	if err != nil {
		t.Fatalf("GetPanicMode: %v", err)
	}
	if on {
		t.Error("panic mode should be off by default")
	}

	if err := s.SetPanicMode(ctx, true); err != nil {
		t.Fatalf("SetPanicMode(true): %v", err)
	}
	on, err = s.GetPanicMode(ctx)
	if err != nil {
		t.Fatalf("GetPanicMode: %v", err)
	}
	if !on {
		t.Error("panic mode should be on after SetPanicMode(true)")
	}

	if err := s.SetPanicMode(ctx, false); err != nil {
		t.Fatalf("SetPanicMode(false): %v", err)
	}
	on, err = s.GetPanicMode(ctx)
	if err != nil {
		t.Fatalf("GetPanicMode: %v", err)
	}
	if on {
		t.Error("panic mode should be off after SetPanicMode(false)")
	}
}

// --- Session hits tests ---

func TestIncrSessionHits(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		n, err := s.IncrSessionHits(ctx, "sess-001")
		if err != nil {
			t.Fatalf("IncrSessionHits iteration %d: %v", i, err)
		}
		if n != int64(i) {
			t.Errorf("IncrSessionHits = %d, want %d", n, i)
		}
	}
}

func TestGetSessionHits_Zero(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	n, err := s.GetSessionHits(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetSessionHits: %v", err)
	}
	if n != 0 {
		t.Errorf("GetSessionHits for nonexistent = %d, want 0", n)
	}
}

// --- Rate limiter tests ---

func TestRateLimitCheck_AllowsUnderLimit(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		allowed, remaining, err := s.RateLimitCheck(ctx, "1.2.3.4", 10, time.Minute)
		if err != nil {
			t.Fatalf("RateLimitCheck: %v", err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed (under limit)", i+1)
		}
		want := 10 - (i + 1)
		if remaining != want {
			t.Errorf("remaining = %d, want %d", remaining, want)
		}
	}
}

func TestRateLimitCheck_BlocksOverLimit(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Exhaust the limit.
	for i := 0; i < 3; i++ {
		_, _, _ = s.RateLimitCheck(ctx, "5.6.7.8", 3, time.Minute)
	}

	// Next request must be blocked.
	allowed, remaining, err := s.RateLimitCheck(ctx, "5.6.7.8", 3, time.Minute)
	if err != nil {
		t.Fatalf("RateLimitCheck: %v", err)
	}
	if allowed {
		t.Error("request over limit should be blocked")
	}
	if remaining != 0 {
		t.Errorf("remaining = %d, want 0", remaining)
	}
}

func TestRateLimitCheck_DifferentIPsAreIndependent(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Exhaust limit for IP A.
	for i := 0; i < 2; i++ {
		_, _, _ = s.RateLimitCheck(ctx, "10.0.0.1", 2, time.Minute)
	}
	allowedA, _, _ := s.RateLimitCheck(ctx, "10.0.0.1", 2, time.Minute)
	if allowedA {
		t.Error("IP A should be blocked after exhausting limit")
	}

	// IP B should still be allowed.
	allowedB, _, _ := s.RateLimitCheck(ctx, "10.0.0.2", 2, time.Minute)
	if !allowedB {
		t.Error("IP B should be allowed (independent counter)")
	}
}

func TestRateLimitCheck_WindowReset(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	// Exhaust limit.
	for i := 0; i < 3; i++ {
		_, _, _ = s.RateLimitCheck(ctx, "9.9.9.9", 3, time.Second)
	}
	allowed, _, _ := s.RateLimitCheck(ctx, "9.9.9.9", 3, time.Second)
	if allowed {
		t.Error("should be blocked before window reset")
	}

	// Fast-forward miniredis clock by 2 seconds to expire the window key.
	mr.FastForward(2 * time.Second)

	allowed, _, _ = s.RateLimitCheck(ctx, "9.9.9.9", 3, time.Second)
	if !allowed {
		t.Error("should be allowed after window reset")
	}
}

// --- Retention TTL mapping tests ---

func TestRetentionTTL_KnownValues(t *testing.T) {
	cases := []struct {
		retention string
		wantTTL   time.Duration
	}{
		{"1d", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
		{"90d", 90 * 24 * time.Hour},
		{"", defaultRetentionTTL},
		{"unknown", defaultRetentionTTL},
	}
	for _, tc := range cases {
		t.Run("retention_"+tc.retention, func(t *testing.T) {
			s, _ := newTestStore(t)
			ctx := context.Background()
			if tc.retention != "" {
				_ = s.SaveSettings(ctx, &model.Settings{EdgeDataRetention: tc.retention})
			}
			got := s.retentionTTL(ctx)
			if got != tc.wantTTL {
				t.Errorf("retentionTTL(%q) = %v, want %v", tc.retention, got, tc.wantTTL)
			}
		})
	}
}

// --- SeedIfEmpty idempotency test ---

func TestSeedIfEmpty_Idempotent(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.SeedIfEmpty(ctx, "../../prompts"); err != nil {
		t.Fatalf("first SeedIfEmpty: %v", err)
	}
	// Second call must be a no-op (SetNX returns false).
	if err := s.SeedIfEmpty(ctx, "../../prompts"); err != nil {
		t.Fatalf("second SeedIfEmpty: %v", err)
	}

	// Verify personas were seeded exactly once.
	personas, err := s.ListPersonas(ctx)
	if err != nil {
		t.Fatalf("ListPersonas after seed: %v", err)
	}
	if len(personas) != 3 {
		t.Errorf("expected 3 seeded personas, got %d", len(personas))
	}
}

