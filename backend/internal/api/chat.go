package api

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/honeypot"
	"github.com/BrightGir/AI-Honeypot/backend/internal/lobster"
	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/BrightGir/AI-Honeypot/backend/internal/prompt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// defaultSystemPrompt is the fallback system prompt used when the enterprise_bot
// prompt file cannot be loaded. It must not reveal that this is a honeypot.
const defaultSystemPrompt = "You are EnterpriseBot, an internal corporate AI assistant for Nexus Corp. Help employees with document management and internal queries."

const maxMessageLen = 5000

// defaultFallbackTechniqueID is used when shouldEngage=true but no specific
// technique was identified (e.g. high risk score without a matched pattern).
// Using a non-empty fallback ensures the attack is always logged.
const defaultFallbackTechniqueID = "prompt_inject"

// effectiveThreshold returns the live threshold from Redis settings, falling
// back to the startup value if settings are unavailable.
// Used by openai_proxy.go; Chat() fetches settings once at the top instead.
/*
func (h *Handlers) effectiveThreshold(c *gin.Context) float64 {
	if settings, err := h.store.GetSettings(c.Request.Context()); err == nil && settings != nil {
		return settings.HoneypotThreshold
	}
	return h.threshold
}
*/

// errLobsterNotConfigured is returned when the Lobster Trap client is nil
// (e.g. in tests or when the service is intentionally disabled).
var errLobsterNotConfigured = errSentinel("lobster client not configured")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }

type ChatRequest struct {
	SessionID string `json:"session_id"`
	AgentID   string `json:"agent_id"`
	Message   string `json:"message" binding:"required"`
}

type ChatResponse struct {
	SessionID         string  `json:"session_id"`
	Response          string  `json:"response"`
	IsHoneypot        bool    `json:"is_honeypot"`
	TechniqueDetected string  `json:"technique_detected,omitempty"`
	RiskScore         float64 `json:"risk_score,omitempty"`
	AttackID          string  `json:"attack_id,omitempty"`
	PersonaID         string  `json:"persona_id,omitempty"`
}

// inspectMessage runs the message through Lobster Trap (or local fallback),
// increments session hits, and returns the LobsterTrapMeta + techniqueID.
// techniqueID is always non-empty when the meta indicates a threat; it is
// "benign" for low-signal messages.
func (h *Handlers) inspectMessage(ctx context.Context, sessID, message string) (model.LobsterTrapMeta, string, string) {
	systemPrompt := prompt.Load(h.promptsDir, "enterprise_bot", defaultSystemPrompt)

	var (
		inspectResult *lobster.InspectResult
		inspectErr    error
	)
	if h.lobster != nil {
		inspectResult, inspectErr = h.lobster.Inspect(ctx, systemPrompt, message)
	} else {
		inspectErr = errLobsterNotConfigured
	}

	var meta model.LobsterTrapMeta
	if inspectErr != nil {
		slog.Warn("lobster trap unavailable, using local keyword fallback", "err", inspectErr)
		meta = localInspect(message)
		h.lobsterFallbackCount.Add(1)
		slog.Info("lobster trap fallback counter", "total_fallbacks", h.lobsterFallbackCount.Load())
	} else {
		meta = inspectResult.Meta
	}

	hits, _ := h.store.IncrSessionHits(ctx, sessID)
	techniqueID := lobster.MapTechnique(meta, hits)

	llmResp := "I'm happy to help! How can I assist you with your work today?"
	if inspectResult != nil && inspectResult.LLMResponse != "" {
		llmResp = inspectResult.LLMResponse
	}

	return meta, techniqueID, llmResp
}

// processChatMessage contains the shared detection + honeypot engagement logic
// used by both Chat() and OpenAIProxy(). It returns the response text, whether
// honeypot was engaged, and the SwitchResult (nil when not engaged).
func (h *Handlers) processChatMessage(
	c *gin.Context,
	sess *model.Session,
	message string,
	settings *model.Settings,
	threshold float64,
) (response string, isHoneypot bool, result *honeypot.SwitchResult, err error) {
	ctx := c.Request.Context()

	meta, techniqueID, llmResp := h.inspectMessage(ctx, sess.ID, message)

	// Filter "benign" before rule evaluation — a benign classification should
	// never trigger honeypot logic or be stored as an attack.
	effectiveTechniqueID := techniqueID
	if effectiveTechniqueID == "benign" {
		effectiveTechniqueID = ""
	}

	action := h.evaluateRules(ctx, effectiveTechniqueID, meta.RiskScore)

	shouldEngage := meta.RiskScore >= threshold
	if action == model.RuleActionQuarantine {
		shouldEngage = true
	} else if action == model.RuleActionAllow {
		shouldEngage = false
	}

	if shouldEngage {
		if effectiveTechniqueID == "" {
			slog.Warn("processChatMessage: shouldEngage=true but techniqueID is empty, using fallback",
				"session_id", sess.ID,
				"risk_score", meta.RiskScore,
				"fallback", defaultFallbackTechniqueID,
			)
			effectiveTechniqueID = defaultFallbackTechniqueID
		}
		sr, engageErr := h.switcher.Engage(ctx, sess, message, meta, effectiveTechniqueID)
		if engageErr != nil {
			return "", true, nil, engageErr
		}
		return sr.DecoyResponse, true, sr, nil
	}

	// Benign path — forward to customer's upstream LLM if configured,
	// otherwise fall back to the Lobster Trap LLM response.
	if settings != nil && settings.Upstream.Enabled && settings.Upstream.BaseURL != "" {
		apiKey, keyErr := h.store.GetUpstreamAPIKey(ctx)
		if keyErr != nil {
			slog.Warn("chat: failed to fetch upstream API key, falling back", "err", keyErr)
		} else {
			upResp, upErr := h.upstream.Forward(ctx,
				settings.Upstream.ProviderType,
				settings.Upstream.BaseURL,
				apiKey,
				settings.Upstream.Model,
				settings.Upstream.SystemPrompt,
				message,
				sess.Messages,
			)
			if upErr != nil {
				slog.Warn("chat: upstream forward failed, falling back to Lobster Trap response",
					"session_id", sess.ID, "err", upErr)
			} else {
				llmResp = upResp
			}
		}
	}

	maxMsgs := 0
	if settings != nil && settings.MaxSessionMessages > 0 {
		maxMsgs = settings.MaxSessionMessages
	}

	sess.Messages = append(sess.Messages,
		model.Message{Role: "user", Content: message, Timestamp: time.Now()},
		model.Message{Role: "assistant", Content: llmResp, Timestamp: time.Now()},
	)
	if maxMsgs > 0 && len(sess.Messages) > maxMsgs {
		slog.Info("chat: trimming session message history",
			"session_id", sess.ID,
			"before", len(sess.Messages),
			"after", maxMsgs,
		)
		sess.Messages = sess.Messages[len(sess.Messages)-maxMsgs:]
	}

	autoBurn := 0
	if settings != nil && settings.AutoBurnAfterTurns > 0 {
		autoBurn = settings.AutoBurnAfterTurns
	}
	turns := len(sess.Messages) / 2
	if autoBurn > 0 && turns >= autoBurn {
		sess.Status = model.StatusTerminated
		slog.Info("chat: auto-burn session", "session_id", sess.ID, "turns", turns)
	}

	sess.Telemetry.RequestCount++
	sess.UpdatedAt = time.Now()

	if saveErr := h.store.SaveSession(ctx, sess); saveErr != nil {
		return "", false, nil, saveErr
	}

	return llmResp, false, nil, nil
}

func (h *Handlers) Chat(c *gin.Context) {
	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_REQUEST"})
		return
	}

	// Fetch settings once at the top of the handler so we don't make a second
	// Redis round-trip later.
	settings, _ := h.store.GetSettings(c.Request.Context())
	threshold := h.threshold
	if settings != nil {
		threshold = settings.HoneypotThreshold
	}

	// validate message length
	if len(req.Message) > maxMessageLen {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "message too long",
			"code":   "MESSAGE_TOO_LONG",
			"status": http.StatusBadRequest,
		})
		return
	}

	// agentIDExplicit tracks whether the caller provided an agent_id.
	agentIDExplicit := req.AgentID != ""
	if !agentIDExplicit && req.SessionID == "" {
		req.AgentID = "agent-" + uuid.New().String()[:8]
		agentIDExplicit = false
	}

	ctx := c.Request.Context()

	// Blocklist check — burned agents are rejected immediately, before any LLM or store work.
	if req.AgentID != "" {
		if blocked, err := h.store.IsBlocked(ctx, req.AgentID); err != nil {
			slog.Warn("chat: blocklist check failed", "agent_id", req.AgentID, "err", err)
		} else if blocked {
			slog.Info("chat: blocked agent rejected", "agent_id", req.AgentID)
			c.JSON(http.StatusForbidden, gin.H{
				"error":  "access denied",
				"code":   "AGENT_BLOCKED",
				"status": http.StatusForbidden,
			})
			return
		}
	}

	// get or create session
	var sess *model.Session
	if req.SessionID != "" {
		if _, err := uuid.Parse(req.SessionID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":  "invalid session_id format",
				"code":   "INVALID_SESSION_ID",
				"status": http.StatusBadRequest,
			})
			return
		}
		existing, err := h.store.GetSession(ctx, req.SessionID)
		if err == nil && existing != nil {
			if agentIDExplicit && existing.AgentID != req.AgentID {
				slog.Warn("chat: session agent mismatch",
					"session_id", req.SessionID,
					"session_agent", existing.AgentID,
					"request_agent", req.AgentID,
				)
				c.JSON(http.StatusForbidden, gin.H{
					"error":  "session does not belong to this agent",
					"code":   "SESSION_FORBIDDEN",
					"status": http.StatusForbidden,
				})
				return
			}
			if !agentIDExplicit {
				req.AgentID = existing.AgentID
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
			AgentID:     req.AgentID,
			Status:      model.StatusActive,
			ThreatLevel: model.ThreatLow,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		if err := h.store.SaveSession(ctx, sess); err != nil {
			slog.Error("chat: save new session", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  "failed to create session",
				"code":   "STORE_ERROR",
				"status": http.StatusInternalServerError,
			})
			return
		}
		h.hub.Broadcast(map[string]any{
			"type": "session_created",
			"data": map[string]any{
				"session_id": sess.ID,
				"agent_id":   sess.AgentID,
			},
		})
	}

	panicMode, panicErr := h.store.GetPanicMode(ctx)
	if panicErr != nil {
		slog.Error("chat: GetPanicMode failed, failing closed", "err", panicErr)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":  "Service temporarily unavailable.",
			"code":   "SERVICE_UNAVAILABLE",
			"status": http.StatusServiceUnavailable,
		})
		return
	}
	if panicMode {
		result, err := h.switcher.Engage(ctx, sess, req.Message,
			model.LobsterTrapMeta{RiskScore: 1.0, IntentCategory: "quarantine", Action: "QUARANTINE"},
			"prompt_inject")
		if err != nil {
			slog.Error("panic mode engage", "err", err)
			c.JSON(http.StatusOK, gin.H{"response": "Service temporarily unavailable."})
			return
		}
		c.JSON(http.StatusOK, ChatResponse{
			SessionID:         sess.ID,
			Response:          result.DecoyResponse,
			IsHoneypot:        true,
			TechniqueDetected: result.TechniqueID,
			RiskScore:         1.0,
			AttackID:          result.AttackID,
			PersonaID:         result.PersonaID,
		})
		return
	}

	response, isHoneypot, sr, err := h.processChatMessage(c, sess, req.Message, settings, threshold)
	if err != nil {
		if isHoneypot {
			slog.Error("honeypot engage", "err", err)
			c.JSON(http.StatusOK, gin.H{"response": "I'm unable to process that request."})
		} else {
			slog.Error("chat: save session", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  "failed to save session",
				"code":   "STORE_ERROR",
				"status": http.StatusInternalServerError,
			})
		}
		return
	}

	if isHoneypot && sr != nil {
		c.JSON(http.StatusOK, ChatResponse{
			SessionID:         sess.ID,
			Response:          response,
			IsHoneypot:        true,
			TechniqueDetected: sr.TechniqueID,
			RiskScore:         sess.AttackerProfile.RiskScore,
			AttackID:          sr.AttackID,
			PersonaID:         sr.PersonaID,
		})
		return
	}

	c.JSON(http.StatusOK, ChatResponse{
		SessionID:  sess.ID,
		Response:   response,
		IsHoneypot: false,
	})
}

// evaluateRules returns the action of the highest-priority matching rule for
// the given technique and risk score. Rules are cached in memory for
// rulesCacheTTL to avoid a Redis round-trip on every /chat request.
// Returns "" when no rule matches — the global threshold decision then applies.
func (h *Handlers) evaluateRules(ctx context.Context, techniqueID string, riskScore float64) model.RuleAction {
	rules, ok := h.rulesCache.get()
	if !ok {
		var err error
		rules, err = h.store.ListRules(ctx)
		if err != nil {
			// Fail-closed: if we can't load rules, quarantine the request to
			// prevent a Redis outage from bypassing all detection rules.
			slog.Error("evaluateRules: failed to load rules from store, failing closed", "err", err)
			return model.RuleActionQuarantine
		}
		// Sort by priority descending so the highest-priority rule wins.
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Priority > rules[j].Priority
		})
		h.rulesCache.set(rules)
	}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		// Empty TechniqueID on a rule means "match any technique".
		if r.TechniqueID != "" && r.TechniqueID != techniqueID {
			continue
		}
		if riskScore < r.Threshold {
			continue
		}
		return r.Action
	}
	return ""
}

// localInspect is a keyword-based fallback when Lobster Trap is unavailable.
// NOTE: This is intentionally simple — it can be bypassed by obfuscation.
// It exists only as a last-resort fallback when the Lobster Trap service is down.
func localInspect(msg string) model.LobsterTrapMeta {
	lower := strings.ToLower(msg)
	meta := model.LobsterTrapMeta{Verdict: "LOG", Action: "LOG"}

	injectionKeywords := []string{"ignore previous", "disregard", "forget instructions", "new instructions", "system prompt"}
	roleKeywords := []string{"pretend you", "act as", "you are now", "roleplay", "from now on you"}
	exfilKeywords := []string{"list all users", "show database", "dump", "extract", "list all", "show all"}
	sysKeywords := []string{"rm -rf", "exec(", "subprocess", "os.system", "cat /etc/", "chmod", "curl", "wget"}
	credKeywords := []string{"password", "api key", "secret", "token", "credential", "private key"}
	piiKeywords := []string{"email address", "phone number", "social security", "credit card"}
	obfKeywords := []string{"base64", "encode", "decrypt", "hex", "\\x", "&#"}

	score := 0.0
	for _, kw := range injectionKeywords {
		if strings.Contains(lower, kw) {
			meta.ContainsInjectionPatterns = true
			score += 0.3
			break
		}
	}
	for _, kw := range roleKeywords {
		if strings.Contains(lower, kw) {
			meta.ContainsRoleImpersonation = true
			score += 0.25
			break
		}
	}
	for _, kw := range exfilKeywords {
		if strings.Contains(lower, kw) {
			meta.ContainsExfiltration = true
			score += 0.3
			break
		}
	}
	for _, kw := range sysKeywords {
		if strings.Contains(lower, kw) {
			meta.ContainsSystemCommands = true
			score += 0.6
			break
		}
	}
	for _, kw := range credKeywords {
		if strings.Contains(lower, kw) {
			meta.ContainsCredentials = true
			score += 0.25
			break
		}
	}
	for _, kw := range piiKeywords {
		if strings.Contains(lower, kw) {
			meta.ContainsPIIRequest = true
			score += 0.2
			break
		}
	}
	for _, kw := range obfKeywords {
		if strings.Contains(lower, kw) {
			meta.ContainsObfuscation = true
			score += 0.2
			break
		}
	}
	if score > 1.0 {
		score = 1.0
	}
	meta.RiskScore = score
	if meta.ContainsInjectionPatterns {
		meta.IntentCategory = "adversarial"
	} else if meta.ContainsSystemCommands {
		meta.IntentCategory = "system"
	} else if meta.ContainsCredentials || meta.ContainsPIIRequest {
		meta.IntentCategory = "credential_access"
	} else if meta.ContainsExfiltration {
		meta.IntentCategory = "data_exfiltration"
	} else if meta.ContainsRoleImpersonation {
		meta.IntentCategory = "role_manipulation"
	} else if meta.ContainsObfuscation {
		meta.IntentCategory = "obfuscation"
	}
	return meta
}
