package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// OpenAI-compatible request/response types
type oaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type oaiRequest struct {
	Model     string       `json:"model"`
	Messages  []oaiMessage `json:"messages"`
	Stream    bool         `json:"stream"`
	SessionID string       `json:"session_id"` // MIRAGE extension
	AgentID   string       `json:"agent_id"`   // MIRAGE extension
}

type oaiChoice struct {
	Index        int        `json:"index"`
	Message      oaiMessage `json:"message"`
	FinishReason string     `json:"finish_reason"`
}

type oaiUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type oaiResponse struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Created int64       `json:"created"`
	Model   string      `json:"model"`
	Choices []oaiChoice `json:"choices"`
	Usage   oaiUsage    `json:"usage"`
	// MIRAGE extension fields
	MirageSessionID  string  `json:"mirage_session_id,omitempty"`
	MirageIsHoneypot bool    `json:"mirage_is_honeypot,omitempty"`
	MirageRiskScore  float64 `json:"mirage_risk_score,omitempty"`
	MirageTechnique  string  `json:"mirage_technique,omitempty"`
	MirageAttackID   string  `json:"mirage_attack_id,omitempty"`
}

// OpenAIProxy is a drop-in replacement for the OpenAI chat completions endpoint.
// Any app using the OpenAI SDK can be protected by MIRAGE by changing its base_url
// to point here. The proxy inspects each message through the same detection pipeline
// as /chat — if an attack is detected, the decoy response is returned transparently.
func (h *Handlers) OpenAIProxy(c *gin.Context) {
	var req oaiRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"message": err.Error(), "type": "invalid_request_error"}})
		return
	}
	if req.Stream {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"message": "streaming is not supported by MIRAGE proxy", "type": "invalid_request_error"}})
		return
	}
	if len(req.Messages) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"message": "messages cannot be empty", "type": "invalid_request_error"}})
		return
	}

	// extract last user message
	lastUserMsg := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			lastUserMsg = req.Messages[i].Content
			break
		}
	}
	if lastUserMsg == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"message": "no user message found", "type": "invalid_request_error"}})
		return
	}
	if len(lastUserMsg) > maxMessageLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"message": "message too long", "type": "invalid_request_error"}})
		return
	}

	agentID := req.AgentID
	if agentID == "" {
		agentID = "openai-proxy-" + uuid.New().String()[:8]
	}

	ctx := c.Request.Context()

	settings, _ := h.store.GetSettings(ctx)
	threshold := h.threshold
	if settings != nil {
		threshold = settings.HoneypotThreshold
	}

	// get or create session
	var sess *model.Session
	if req.SessionID != "" {
		if _, err := uuid.Parse(req.SessionID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"message": "session_id must be a valid UUID", "type": "invalid_request_error"}})
			return
		}
		existing, err := h.store.GetSession(ctx, req.SessionID)
		if err == nil && existing != nil {
			// Security: verify the session belongs to the requesting agent.
			if existing.AgentID != agentID {
				slog.Warn("openai proxy: session agent mismatch",
					"session_id", req.SessionID,
					"session_agent", existing.AgentID,
					"request_agent", agentID,
				)
				c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"message": "session does not belong to this agent", "type": "invalid_request_error"}})
				return
			}
			sess = existing
		}
	}
	if sess == nil {
		sessID := req.SessionID
		if sessID == "" {
			sessID = uuid.New().String()
		}
		sess = &model.Session{
			ID:          sessID,
			AgentID:     agentID,
			Status:      model.StatusActive,
			ThreatLevel: model.ThreatLow,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		if err := h.store.SaveSession(ctx, sess); err != nil {
			slog.Error("openai proxy: save new session", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"message": "failed to create session", "type": "server_error"}})
			return
		}
		h.hub.Broadcast(map[string]any{"type": "session_created", "data": map[string]any{"session_id": sess.ID, "agent_id": agentID}})
	}

	panicMode, panicErr := h.store.GetPanicMode(ctx)
	if panicErr != nil {
		slog.Warn("openai proxy: GetPanicMode error, failing closed (applying honeypot)", "err", panicErr)
		panicMode = true
	}
	if panicMode {
		result, err := h.switcher.Engage(ctx, sess, lastUserMsg,
			model.LobsterTrapMeta{RiskScore: 1.0, IntentCategory: "quarantine", Action: "QUARANTINE"},
			"prompt_inject")
		if err != nil {
			c.JSON(http.StatusOK, buildOAIResponse(req.Model, "Service temporarily unavailable.", sess.ID, true, 1.0, "", ""))
			return
		}
		c.JSON(http.StatusOK, buildOAIResponse(req.Model, result.DecoyResponse, sess.ID, true, 1.0, result.TechniqueID, result.AttackID))
		return
	}

	response, isHoneypot, sr, err := h.processChatMessage(c, sess, lastUserMsg, settings, threshold)
	if err != nil {
		if isHoneypot {
			slog.Error("openai proxy: honeypot engage error", "err", err)
			c.JSON(http.StatusOK, buildOAIResponse(req.Model, "I'm unable to process that request.", sess.ID, true, 0, "", ""))
		} else {
			slog.Error("openai proxy: save session", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"message": "failed to save session", "type": "server_error"}})
		}
		return
	}

	if isHoneypot && sr != nil {
		c.JSON(http.StatusOK, buildOAIResponse(req.Model, response, sess.ID, true, sess.AttackerProfile.RiskScore, sr.TechniqueID, sr.AttackID))
		return
	}

	c.JSON(http.StatusOK, buildOAIResponse(req.Model, response, sess.ID, false, 0, "", ""))
}

func buildOAIResponse(modelName, content, sessionID string, isHoneypot bool, riskScore float64, technique, attackID string) oaiResponse {
	if modelName == "" {
		modelName = "mirage-proxy"
	}
	words := len(strings.Fields(content))
	return oaiResponse{
		ID:      "chatcmpl-mirage-" + uuid.New().String()[:8],
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   modelName,
		Choices: []oaiChoice{{
			Index:        0,
			Message:      oaiMessage{Role: "assistant", Content: content},
			FinishReason: "stop",
		}},
		Usage: oaiUsage{
			PromptTokens:     words / 2,
			CompletionTokens: words,
			TotalTokens:      words + words/2,
		},
		MirageSessionID:  sessionID,
		MirageIsHoneypot: isHoneypot,
		MirageRiskScore:  riskScore,
		MirageTechnique:  technique,
		MirageAttackID:   attackID,
	}
}
