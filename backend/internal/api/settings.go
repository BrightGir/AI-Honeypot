package api

import (
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
)

// ConfigureUpstream sets or updates the customer's upstream LLM configuration.
// The API key, if provided, is encrypted and stored in a separate Redis key.
// Omitting api_key leaves the existing key unchanged.
func (h *Handlers) ConfigureUpstream(c *gin.Context) {
	ctx := c.Request.Context()

	var body struct {
		ProviderType string `json:"provider_type"`
		BaseURL      string `json:"base_url"`
		Model        string `json:"model"`
		SystemPrompt string `json:"system_prompt"`
		APIKey       string `json:"api_key"`
		Enabled      *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}

	settings, err := h.store.GetSettings(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}

	if body.ProviderType != "" {
		settings.Upstream.ProviderType = body.ProviderType
	}
	if body.BaseURL != "" {
		settings.Upstream.BaseURL = body.BaseURL
	}
	if body.Model != "" {
		settings.Upstream.Model = body.Model
	}
	if body.SystemPrompt != "" {
		settings.Upstream.SystemPrompt = body.SystemPrompt
	}
	if body.Enabled != nil {
		settings.Upstream.Enabled = *body.Enabled
	}

	// Only update the API key if explicitly provided.
	if body.APIKey != "" {
		if err := h.store.SetUpstreamAPIKey(ctx, body.APIKey); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store API key", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
			return
		}
		settings.Upstream.APIKeySet = true
	}

	if err := h.store.SaveSettings(ctx, settings); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "upstream": gin.H{
		"base_url":      settings.Upstream.BaseURL,
		"model":         settings.Upstream.Model,
		"enabled":       settings.Upstream.Enabled,
		"api_key_set":   settings.Upstream.APIKeySet,
	}})
}

// TestUpstream sends a probe message to the configured upstream LLM and reports
// whether the connection succeeded. Never call this on the hot path.
func (h *Handlers) TestUpstream(c *gin.Context) {
	ctx := c.Request.Context()

	settings, err := h.store.GetSettings(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	if settings.Upstream.BaseURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "upstream not configured", "code": "NOT_CONFIGURED", "status": http.StatusBadRequest})
		return
	}

	apiKey, err := h.store.GetUpstreamAPIKey(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read API key", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}

	resp, err := h.upstream.Forward(ctx,
		settings.Upstream.ProviderType,
		settings.Upstream.BaseURL,
		apiKey,
		settings.Upstream.Model,
		settings.Upstream.SystemPrompt,
		"Hello, this is a connection test from Mirage. Please reply with OK.",
		nil,
	)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"ok": false, "error": err.Error(), "code": "UPSTREAM_ERROR", "status": http.StatusBadGateway})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "response": resp})
}

// validHostname matches a valid DNS hostname (no scheme, no path, no port).
var validHostname = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func (h *Handlers) GetSettings(c *gin.Context) {
	ctx := c.Request.Context()
	settings, err := h.store.GetSettings(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	c.JSON(http.StatusOK, settings)
}

func (h *Handlers) UpdateSettings(c *gin.Context) {
	ctx := c.Request.Context()
	settings, err := h.store.GetSettings(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	if err := c.ShouldBindJSON(settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}
	if settings.HoneypotThreshold < 0 || settings.HoneypotThreshold > 1 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "honeypot_threshold must be between 0 and 1",
			"code":   "INVALID_REQUEST",
			"status": http.StatusBadRequest,
		})
		return
	}
	if settings.MaxSessionMessages < 0 || settings.MaxSessionMessages > 10000 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "max_session_messages must be between 0 and 10000",
			"code":   "INVALID_REQUEST",
			"status": http.StatusBadRequest,
		})
		return
	}
	if settings.AutoBurnAfterTurns < 0 || settings.AutoBurnAfterTurns > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "auto_burn_after_turns must be between 0 and 1000",
			"code":   "INVALID_REQUEST",
			"status": http.StatusBadRequest,
		})
		return
	}
	if err := h.store.SaveSettings(ctx, settings); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handlers) PanicMode(c *gin.Context) {
	ctx := c.Request.Context()
	var body struct {
		Active bool `json:"active"`
	}
	// Ignore bind error intentionally: missing body defaults to Active=false.
	_ = c.ShouldBindJSON(&body)

	if err := h.store.SetPanicMode(ctx, body.Active); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}

	if body.Active {
		h.simulator.Stop()
	} else {
		h.simulator.Start(h.appCtx)
	}

	h.hub.Broadcast(map[string]any{
		"type": "panic_mode",
		"data": map[string]any{"active": body.Active, "timestamp": time.Now().UTC()},
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "panic_mode": body.Active})
}

func (h *Handlers) AddEgressDomain(c *gin.Context) {
	ctx := c.Request.Context()
	var body struct {
		Domain string `json:"domain" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}
	if !validHostname.MatchString(body.Domain) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "domain must be a valid hostname (e.g. example.com)",
			"code":   "INVALID_DOMAIN",
			"status": http.StatusBadRequest,
		})
		return
	}

	settings, err := h.store.GetSettings(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	for _, d := range settings.EgressDomains {
		if d == body.Domain {
			c.JSON(http.StatusOK, gin.H{"ok": true, "domain": body.Domain, "status": "allowed"})
			return
		}
	}
	settings.EgressDomains = append(settings.EgressDomains, body.Domain)
	if err := h.store.SaveSettings(ctx, settings); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "domain": body.Domain, "status": "allowed"})
}

func (h *Handlers) DeleteEgressDomain(c *gin.Context) {
	ctx := c.Request.Context()
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required", "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}

	settings, err := h.store.GetSettings(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	filtered := make([]string, 0, len(settings.EgressDomains))
	for _, d := range settings.EgressDomains {
		if d != domain {
			filtered = append(filtered, d)
		}
	}
	settings.EgressDomains = filtered
	if err := h.store.SaveSettings(ctx, settings); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handlers) WipeData(c *gin.Context) {
	ctx := c.Request.Context()
	settings, err := h.store.GetSettings(ctx)
	if err != nil {
		// Redis error — cannot determine demo mode; fail safe with 500.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	if settings != nil && settings.DemoMode {
		c.JSON(http.StatusForbidden, gin.H{"error": "wipe disabled in demo mode", "code": "FORBIDDEN", "status": http.StatusForbidden})
		return
	}
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented", "code": "NOT_IMPLEMENTED", "status": http.StatusNotImplemented})
}

func (h *Handlers) ResetCluster(c *gin.Context) {
	ctx := c.Request.Context()
	settings, err := h.store.GetSettings(ctx)
	if err != nil {
		// Redis error — cannot determine demo mode; fail safe with 500.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	if settings != nil && settings.DemoMode {
		c.JSON(http.StatusForbidden, gin.H{"error": "reset disabled in demo mode", "code": "FORBIDDEN", "status": http.StatusForbidden})
		return
	}
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented", "code": "NOT_IMPLEMENTED", "status": http.StatusNotImplemented})
}
