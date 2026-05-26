package model

import (
	"errors"
	"fmt"
	"time"
)

type RuleAction string

const (
	RuleActionLog       RuleAction = "LOG"
	RuleActionQuarantine RuleAction = "QUARANTINE"
	RuleActionAllow     RuleAction = "ALLOW"
)

type Rule struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	TechniqueID string     `json:"technique_id"`
	Enabled     bool       `json:"enabled"`
	Action      RuleAction `json:"action"`
	Threshold   float64    `json:"threshold"`
	Priority    int        `json:"priority"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Validate checks that Rule fields contain valid values.
// Threshold must be in the range [0.0, 1.0] and Priority must be > 0.
// Name must not be empty.
func (r Rule) Validate() error {
	var errs []error

	if r.Name == "" {
		errs = append(errs, errors.New("rule: Name must not be empty"))
	}

	if r.Threshold < 0.0 || r.Threshold > 1.0 {
		errs = append(errs, fmt.Errorf(
			"rule: Threshold %.4f is out of range; must be in [0.0, 1.0]",
			r.Threshold,
		))
	}

	if r.Priority <= 0 {
		errs = append(errs, fmt.Errorf(
			"rule: Priority %d is invalid; must be > 0",
			r.Priority,
		))
	}

	return errors.Join(errs...)
}

type RuleEngineStats struct {
	TotalRules    int            `json:"total_rules"`
	ActiveRules   int            `json:"active_rules"`
	TriggerCounts map[string]int `json:"trigger_counts"`
	LastUpdated   time.Time      `json:"last_updated"`
}
