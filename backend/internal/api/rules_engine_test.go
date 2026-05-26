package api

import (
	"context"
	"testing"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/BrightGir/AI-Honeypot/backend/internal/store"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestHandlers creates a minimal Handlers instance backed by miniredis.
func newTestHandlers(t *testing.T) (*Handlers, *store.Store) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st := store.New(rdb)
	h := &Handlers{
		store:     st,
		threshold: 0.6,
	}
	return h, st
}

// --- evaluateRules tests ---

func TestEvaluateRules_NoRules(t *testing.T) {
	h, _ := newTestHandlers(t)
	action := h.evaluateRules(context.Background(), "prompt_inject", 0.8)
	if action != "" {
		t.Errorf("expected empty action with no rules, got %q", action)
	}
}

func TestEvaluateRules_MatchingRule_Log(t *testing.T) {
	h, st := newTestHandlers(t)
	ctx := context.Background()

	_ = st.SaveRule(ctx, &model.Rule{
		ID:          "r1",
		TechniqueID: "prompt_inject",
		Enabled:     true,
		Action:      model.RuleActionLog,
		Threshold:   0.6,
		Priority:    100,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	action := h.evaluateRules(ctx, "prompt_inject", 0.7)
	if action != model.RuleActionLog {
		t.Errorf("action = %q, want %q", action, model.RuleActionLog)
	}
}

func TestEvaluateRules_MatchingRule_Quarantine(t *testing.T) {
	h, st := newTestHandlers(t)
	ctx := context.Background()

	_ = st.SaveRule(ctx, &model.Rule{
		ID:          "r1",
		TechniqueID: "jailbreak_dan",
		Enabled:     true,
		Action:      model.RuleActionQuarantine,
		Threshold:   0.85,
		Priority:    100,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	action := h.evaluateRules(ctx, "jailbreak_dan", 0.9)
	if action != model.RuleActionQuarantine {
		t.Errorf("action = %q, want %q", action, model.RuleActionQuarantine)
	}
}

func TestEvaluateRules_BelowThreshold_NoMatch(t *testing.T) {
	h, st := newTestHandlers(t)
	ctx := context.Background()

	_ = st.SaveRule(ctx, &model.Rule{
		ID:          "r1",
		TechniqueID: "prompt_inject",
		Enabled:     true,
		Action:      model.RuleActionQuarantine,
		Threshold:   0.8,
		Priority:    100,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	// risk_score 0.5 < threshold 0.8 → no match
	action := h.evaluateRules(ctx, "prompt_inject", 0.5)
	if action != "" {
		t.Errorf("expected no action below threshold, got %q", action)
	}
}

func TestEvaluateRules_DisabledRule_Ignored(t *testing.T) {
	h, st := newTestHandlers(t)
	ctx := context.Background()

	_ = st.SaveRule(ctx, &model.Rule{
		ID:          "r1",
		TechniqueID: "prompt_inject",
		Enabled:     false, // disabled
		Action:      model.RuleActionQuarantine,
		Threshold:   0.5,
		Priority:    100,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	action := h.evaluateRules(ctx, "prompt_inject", 0.9)
	if action != "" {
		t.Errorf("disabled rule should not match, got %q", action)
	}
}

func TestEvaluateRules_PriorityWins(t *testing.T) {
	h, st := newTestHandlers(t)
	ctx := context.Background()

	// Lower priority rule says ALLOW.
	_ = st.SaveRule(ctx, &model.Rule{
		ID:          "r-low",
		TechniqueID: "prompt_inject",
		Enabled:     true,
		Action:      model.RuleActionAllow,
		Threshold:   0.5,
		Priority:    10,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	// Higher priority rule says QUARANTINE.
	_ = st.SaveRule(ctx, &model.Rule{
		ID:          "r-high",
		TechniqueID: "prompt_inject",
		Enabled:     true,
		Action:      model.RuleActionQuarantine,
		Threshold:   0.5,
		Priority:    100,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	action := h.evaluateRules(ctx, "prompt_inject", 0.8)
	if action != model.RuleActionQuarantine {
		t.Errorf("highest-priority rule should win; action = %q, want %q", action, model.RuleActionQuarantine)
	}
}

func TestEvaluateRules_WildcardTechnique(t *testing.T) {
	h, st := newTestHandlers(t)
	ctx := context.Background()

	// Rule with empty TechniqueID matches any technique.
	_ = st.SaveRule(ctx, &model.Rule{
		ID:          "r-any",
		TechniqueID: "", // wildcard
		Enabled:     true,
		Action:      model.RuleActionLog,
		Threshold:   0.5,
		Priority:    50,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	for _, tech := range []string{"prompt_inject", "jailbreak_dan", "data_exfil", "role_switch"} {
		action := h.evaluateRules(ctx, tech, 0.7)
		if action != model.RuleActionLog {
			t.Errorf("wildcard rule should match technique %q, got action %q", tech, action)
		}
	}
}

func TestEvaluateRules_WrongTechnique_NoMatch(t *testing.T) {
	h, st := newTestHandlers(t)
	ctx := context.Background()

	_ = st.SaveRule(ctx, &model.Rule{
		ID:          "r1",
		TechniqueID: "jailbreak_dan",
		Enabled:     true,
		Action:      model.RuleActionQuarantine,
		Threshold:   0.5,
		Priority:    100,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	// Different technique — should not match.
	action := h.evaluateRules(ctx, "prompt_inject", 0.9)
	if action != "" {
		t.Errorf("rule for jailbreak_dan should not match prompt_inject, got %q", action)
	}
}

func TestEvaluateRules_AllowOverridesThreshold(t *testing.T) {
	h, st := newTestHandlers(t)
	ctx := context.Background()

	_ = st.SaveRule(ctx, &model.Rule{
		ID:          "r-allow",
		TechniqueID: "role_switch",
		Enabled:     true,
		Action:      model.RuleActionAllow,
		Threshold:   0.3,
		Priority:    200,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	// Even with high risk score, ALLOW rule should win.
	action := h.evaluateRules(ctx, "role_switch", 0.95)
	if action != model.RuleActionAllow {
		t.Errorf("ALLOW rule should win; action = %q, want %q", action, model.RuleActionAllow)
	}
}
