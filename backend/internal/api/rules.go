package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (h *Handlers) ListRules(c *gin.Context) {
	ctx := c.Request.Context()
	rules, err := h.store.ListRules(ctx)
	if err != nil {
		slog.Error("rules: list rules failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

// validateRule checks technique_id, threshold and action for validity.
// Returns an error message string (non-empty) when validation fails.
func validateRule(rule *model.Rule) string {
	if rule.TechniqueID != "" {
		if _, err := model.GetTechnique(rule.TechniqueID); err != nil {
			return "invalid technique_id"
		}
	}
	if rule.Threshold < 0 || rule.Threshold > 1 {
		return "threshold must be between 0 and 1"
	}
	switch rule.Action {
	case model.RuleActionLog, model.RuleActionQuarantine, model.RuleActionAllow:
	default:
		return "action must be LOG, QUARANTINE, or ALLOW"
	}
	return ""
}

func (h *Handlers) CreateRule(c *gin.Context) {
	ctx := c.Request.Context()
	var rule model.Rule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}
	if msg := validateRule(&rule); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg, "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}
	rule.ID = uuid.New().String()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	if err := h.store.SaveRule(ctx, &rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	h.rulesCache.invalidate()
	c.JSON(http.StatusCreated, rule)
}

func (h *Handlers) UpdateRule(c *gin.Context) {
	ctx := c.Request.Context()
	existing, err := h.store.GetRule(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found", "code": "NOT_FOUND", "status": http.StatusNotFound})
		return
	}
	originalID := existing.ID
	originalCreatedAt := existing.CreatedAt
	if err := c.ShouldBindJSON(existing); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}
	existing.ID = originalID
	existing.CreatedAt = originalCreatedAt
	existing.UpdatedAt = time.Now()
	if msg := validateRule(existing); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg, "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}
	if err := h.store.SaveRule(ctx, existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	h.rulesCache.invalidate()
	c.JSON(http.StatusOK, existing)
}

func (h *Handlers) DeleteRule(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.Param("id")
	if _, err := h.store.GetRule(ctx, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found", "code": "NOT_FOUND", "status": http.StatusNotFound})
		return
	}
	if err := h.store.DeleteRule(ctx, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	h.rulesCache.invalidate()
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

func (h *Handlers) RuleEngineStats(c *gin.Context) {
	ctx := c.Request.Context()
	rules, _ := h.store.ListRules(ctx)
	active := 0
	for _, r := range rules {
		if r.Enabled {
			active++
		}
	}
	techniqueCounts, _ := h.store.GetTechniqueCounts(ctx)
	triggerCounts := make(map[string]int, len(techniqueCounts))
	for k, v := range techniqueCounts {
		triggerCounts[k] = int(v)
	}
	c.JSON(http.StatusOK, model.RuleEngineStats{
		TotalRules:    len(rules),
		ActiveRules:   active,
		TriggerCounts: triggerCounts,
		LastUpdated:   time.Now(),
	})
}
