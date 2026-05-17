package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/BrightGir/AI-Honeypot/backend/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (h *Handlers) TerminateSession(c *gin.Context) {
	ctx := c.Request.Context()
	sess, err := h.store.GetSession(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found", "code": "SESSION_NOT_FOUND", "status": http.StatusNotFound})
		return
	}
	sess.Status = model.StatusTerminated
	sess.UpdatedAt = time.Now()
	if err := h.store.SaveSession(ctx, sess); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	h.hub.Broadcast(map[string]any{
		"type": "session_updated",
		"data": map[string]any{"session_id": sess.ID, "status": sess.Status},
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": "terminated"})
}

func (h *Handlers) InjectMessage(c *gin.Context) {
	ctx := c.Request.Context()
	sess, err := h.store.GetSession(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found", "code": "SESSION_NOT_FOUND", "status": http.StatusNotFound})
		return
	}

	var body struct {
		Message string `json:"message" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}

	// Enforce the same message length limit as /chat to prevent oversized
	// payloads from bloating the Redis session record.
	if len(body.Message) > maxMessageLen {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "message too long",
			"code":   "MESSAGE_TOO_LONG",
			"status": http.StatusBadRequest,
		})
		return
	}

	sess.Messages = append(sess.Messages, model.Message{
		Role:      "assistant",
		Content:   body.Message,
		Timestamp: time.Now(),
		IsDecoy:   true,
	})
	sess.UpdatedAt = time.Now()
	if err := h.store.SaveSession(ctx, sess); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// BurnSession implements the full honeypot burn workflow:
//  1. Mark session as burned (status + timestamp).
//  2. Persist the session key in Redis (remove TTL) to preserve evidence indefinitely.
//  3. Block the attacker's agent ID so future /chat requests are rejected immediately.
//  4. Auto-create an IOC attack record summarising the session for threat intelligence.
//  5. Broadcast the burn event to all connected dashboard clients.
func (h *Handlers) BurnSession(c *gin.Context) {
	ctx := c.Request.Context()
	sess, err := h.store.GetSession(ctx, c.Param("id"))
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found", "code": "SESSION_NOT_FOUND", "status": http.StatusNotFound})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		}
		return
	}

	now := time.Now()

	// 1. Mark burned.
	sess.Status = model.StatusBurned
	sess.BurnedAt = &now
	sess.UpdatedAt = now
	if err := h.store.SaveSession(ctx, sess); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}

	// 2. Persist evidence — remove Redis TTL so the session is never auto-deleted.
	if err := h.store.PersistSession(ctx, sess.ID); err != nil {
		slog.Warn("burn: persist session failed", "session_id", sess.ID, "err", err)
	}

	// 3. Block agent — all future /chat requests from this agent are rejected.
	if sess.AgentID != "" {
		if err := h.store.AddToBlocklist(ctx, sess.AgentID); err != nil {
			slog.Warn("burn: add to blocklist failed", "agent_id", sess.AgentID, "err", err)
		}
	}

	// 4. Auto-create IOC attack record from session data.
	techniqueID := sess.Technique
	if techniqueID == "" && len(sess.AttackerProfile.TechniquesUsed) > 0 {
		techniqueID = sess.AttackerProfile.TechniquesUsed[0]
	}
	if techniqueID == "" {
		techniqueID = "prompt_inject"
	}
	tech, _ := model.GetTechnique(techniqueID)

	// Collect the first attacker message as the representative payload.
	payload := ""
	for _, m := range sess.Messages {
		if m.Role == "user" {
			payload = m.Content
			break
		}
	}

	severity := model.SeverityHigh
	if sess.AttackerProfile.RiskScore > 0.9 {
		severity = model.SeverityCritical
	} else if sess.AttackerProfile.RiskScore < 0.6 {
		severity = model.SeverityMedium
	}

	ioc := &model.Attack{
		ID:            uuid.New().String(),
		SessionID:     sess.ID,
		AgentID:       sess.AgentID,
		TechniqueID:   techniqueID,
		TechniqueName: tech.Name,
		Severity:      severity,
		Payload:       payload,
		DecoyResponse: "Session burned by operator",
		LobsterMeta: model.LobsterTrapMeta{
			Verdict:        "BURN",
			RiskScore:      sess.AttackerProfile.RiskScore,
			IntentCategory: sess.AttackerProfile.IntentCategory,
			Action:         "BURN",
		},
		PersonaID: sess.PersonaID,
		Timestamp: now,
	}
	if err := h.store.SaveAttack(ctx, ioc); err != nil {
		slog.Warn("burn: save IOC failed", "session_id", sess.ID, "err", err)
	}

	// 5. Broadcast to dashboard clients.
	h.hub.Broadcast(map[string]any{
		"type": "session_burned",
		"data": map[string]any{
			"session_id": sess.ID,
			"agent_id":   sess.AgentID,
			"burned_at":  now.UTC(),
			"ioc_id":     ioc.ID,
		},
	})

	slog.Info("session burned",
		"session_id", sess.ID,
		"agent_id", sess.AgentID,
		"technique", techniqueID,
		"risk", sess.AttackerProfile.RiskScore,
	)

	c.JSON(http.StatusOK, gin.H{
		"ok":        true,
		"status":    "burned",
		"ioc_id":    ioc.ID,
		"burned_at": now.UTC(),
	})
}
