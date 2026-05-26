package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/decoy"
	"github.com/BrightGir/AI-Honeypot/backend/internal/demo"
	"github.com/BrightGir/AI-Honeypot/backend/internal/honeypot"
	"github.com/BrightGir/AI-Honeypot/backend/internal/lobster"
	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	openaiClient "github.com/BrightGir/AI-Honeypot/backend/internal/openai"
	"github.com/BrightGir/AI-Honeypot/backend/internal/store"
	"github.com/BrightGir/AI-Honeypot/backend/internal/upstream"
	"github.com/BrightGir/AI-Honeypot/backend/internal/ws"
	"github.com/gin-gonic/gin"
)

// rulesCache is a short-lived in-memory cache for detection rules.
// It prevents a Redis round-trip on every /chat request.
type rulesCache struct {
	mu        sync.RWMutex
	rules     []*model.Rule
	expiresAt time.Time
}

const rulesCacheTTL = 5 * time.Second

func (rc *rulesCache) get() ([]*model.Rule, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	if rc.rules == nil || time.Now().After(rc.expiresAt) {
		return nil, false
	}
	return rc.rules, true
}

func (rc *rulesCache) set(rules []*model.Rule) {
	rc.mu.Lock()
	rc.rules = rules
	rc.expiresAt = time.Now().Add(rulesCacheTTL)
	rc.mu.Unlock()
}

func (rc *rulesCache) invalidate() {
	rc.mu.Lock()
	rc.rules = nil
	rc.mu.Unlock()
}

type Handlers struct {
	store       *store.Store
	lobster     *lobster.Client
	generator   decoy.Generator
	openai      *openaiClient.Client
	upstream    *upstream.Client
	hub         *ws.Hub
	switcher    *honeypot.Switcher
	simulator   *demo.Simulator
	threshold   float64
	promptsDir  string
	corsOrigins []string
	startTime   time.Time
	// apiKey is stored so WebSocketLive can authenticate without a separate middleware.
	apiKey string
	appCtx context.Context

	// rulesCache caches detection rules to avoid a Redis round-trip on every /chat.
	rulesCache rulesCache

	// lobsterFallbackCount counts how many times the local keyword fallback
	// was used instead of the Lobster Trap service (for monitoring).
	lobsterFallbackCount atomic.Int64
}

func NewHandlers(appCtx context.Context, s *store.Store, lc *lobster.Client, gen decoy.Generator, oai *openaiClient.Client, hub *ws.Hub, sw *honeypot.Switcher, sim *demo.Simulator, threshold float64, promptsDir string, corsOrigins []string, apiKey string) *Handlers {
	return &Handlers{
		store:       s,
		lobster:     lc,
		generator:   gen,
		openai:      oai,
		upstream:    upstream.New(),
		hub:         hub,
		switcher:    sw,
		simulator:   sim,
		threshold:   threshold,
		promptsDir:  promptsDir,
		corsOrigins: corsOrigins,
		startTime:   time.Now(),
		apiKey:      apiKey,
		appCtx:      appCtx,
	}
}

// SecurityHeadersMiddleware sets defensive HTTP headers on every response.
// These headers harden the dashboard against XSS, clickjacking, MIME-sniffing,
// and information leakage without requiring a reverse proxy.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent MIME-type sniffing.
		c.Header("X-Content-Type-Options", "nosniff")
		// Deny framing to block clickjacking.
		c.Header("X-Frame-Options", "DENY")
		// HSTS omitted: nginx serves HTTP only (TLS block commented out in nginx.conf).
		// Restore when TLS is configured: c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Restrict referrer information.
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// Permissions policy: disable powerful features not needed by the dashboard.
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		// Content-Security-Policy: allow only same-origin scripts/styles plus
		// the CDN used by the frontend (Babel standalone, React, Tailwind).
		// Adjust cdn.jsdelivr.net / unpkg.com if the frontend CDN changes.
		c.Header("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "+
				"style-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "+
				"connect-src 'self' ws: wss:; "+
				"img-src 'self' data:; "+
				"font-src 'self' https://unpkg.com https://cdn.jsdelivr.net; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'",
		)
		// Remove server fingerprint.
		c.Header("Server", "")
		c.Header("X-Powered-By", "")
		c.Next()
	}
}

func (h *Handlers) Register(r *gin.Engine, apiKey string) {
	// Apply security headers to every response.
	r.Use(SecurityHeadersMiddleware())

	r.GET("/health", h.Health)

	// public — attacker endpoint with Redis-based rate limiting (distributed-safe)
	r.POST("/chat", h.RateLimitMiddleware(h.appCtx, 60, time.Minute), h.Chat)

	// OpenAI-compatible proxy (public, same rate limit)
	r.POST("/v1/chat/completions", h.RateLimitMiddleware(h.appCtx, 60, time.Minute), h.OpenAIProxy)

	// WebSocket — authentication is handled inside WebSocketLive via token query param.
	r.GET("/ws/live", h.WebSocketLive)

	// protected dashboard API — versioned under /api/v1
	v1 := r.Group("/api/v1", APIKeyMiddleware(apiKey))
	{
		v1.GET("/stats", h.GetStats)
		v1.GET("/stats/timeline", h.GetStatsTimeline)
		v1.GET("/stats/techniques", h.GetTechniques)
		v1.GET("/stats/top-agents", h.GetTopAgents)
		v1.GET("/stats/geo", h.GetGeo)
		v1.GET("/stats/export", h.ExportAll)

		v1.GET("/sessions", h.ListSessions)
		v1.GET("/sessions/export", h.ExportSessions)
		v1.GET("/sessions/:id", h.GetSession)
		v1.GET("/sessions/:id/analyze", h.AnalyzeSession)

		v1.GET("/attacks", h.ListAttacks)
		v1.GET("/attacks/export", h.ExportAttacks)
		v1.GET("/attacks/:id", h.GetAttack)
		v1.POST("/attacks/:id/ioc", h.CreateIOC)

		v1.POST("/sessions/:id/terminate", h.TerminateSession)
		v1.POST("/sessions/:id/inject-trail", h.InjectMessage)
		v1.POST("/sessions/:id/burn", h.BurnSession)

		// legacy honeypot session paths (kept for backward compat)
		v1.POST("/honeypot/sessions/:id/terminate", h.TerminateSession)
		v1.POST("/honeypot/sessions/:id/inject", h.InjectMessage)
		v1.POST("/honeypot/sessions/:id/burn", h.BurnSession)

		v1.GET("/rules", h.ListRules)
		v1.POST("/rules", h.CreateRule)
		v1.PATCH("/rules/:id", h.UpdateRule)
		v1.DELETE("/rules/:id", h.DeleteRule)
		v1.GET("/rules/engine/stats", h.RuleEngineStats)

		v1.GET("/personas", h.ListPersonas)
		v1.POST("/personas", h.CreatePersona)
		v1.PATCH("/personas/:id", h.UpdatePersona)
		v1.DELETE("/personas/:id", h.DeletePersona)
		v1.POST("/personas/:id/test", h.TestPersona)
		v1.POST("/personas/:id/datasets", h.AttachDataset)
		v1.GET("/personas/datasets", h.GetDatasets)
		v1.POST("/personas/import", h.ImportPersona)

		v1.GET("/integrations", h.ListIntegrations)
		v1.POST("/integrations", h.AddIntegration)
		v1.PATCH("/integrations/:id", h.UpdateIntegration)
		v1.DELETE("/integrations/:id", h.DeleteIntegration)
		v1.GET("/integrations/veea/telemetry", h.VeeaTelemetry)
		v1.POST("/integrations/veea/diagnostic", h.VeeaDiagnostic)

		v1.GET("/settings", h.GetSettings)
		v1.PATCH("/settings", h.UpdateSettings)
		v1.POST("/settings/egress", h.AddEgressDomain)
		v1.DELETE("/settings/egress/:domain", h.DeleteEgressDomain)
		v1.POST("/settings/panic", h.PanicMode)
		v1.POST("/settings/wipe", h.WipeData)
		v1.POST("/settings/reset", h.ResetCluster)
		v1.PUT("/settings/upstream", h.ConfigureUpstream)
		v1.POST("/settings/upstream/test", h.TestUpstream)
	}
}

// APIKeyMiddleware checks the X-API-Key header using constant-time comparison
// to prevent timing-based key enumeration attacks.
func APIKeyMiddleware(key string) gin.HandlerFunc {
	keyBytes := []byte(key)
	return func(c *gin.Context) {
		got := []byte(c.GetHeader("X-API-Key"))
		if subtle.ConstantTimeCompare(got, keyBytes) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":  "unauthorized",
				"code":   "UNAUTHORIZED",
				"status": http.StatusUnauthorized,
			})
			return
		}
		c.Next()
	}
}

// RateLimitMiddleware returns a Redis-backed fixed-window rate limiter.
// Unlike the previous in-memory implementation, this is safe for use across
// multiple backend instances (horizontal scaling).
func (h *Handlers) RateLimitMiddleware(ctx context.Context, maxReqs int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		allowed, remaining, err := h.store.RateLimitCheck(c.Request.Context(), ip, maxReqs, window)
		if err != nil {
			slog.Warn("rate limiter error", "ip", ip, "err", err)
			// Fail open on Redis errors to avoid blocking legitimate traffic.
			c.Next()
			return
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(maxReqs))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		if !allowed {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":  "rate limit exceeded",
				"code":   "RATE_LIMIT_EXCEEDED",
				"status": http.StatusTooManyRequests,
			})
			return
		}
		c.Next()
	}
}

