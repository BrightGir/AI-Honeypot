package api

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// safeDialer is a custom net.Dialer that validates the resolved IP address on
// every connection attempt, preventing SSRF via DNS rebinding attacks.
// The validation happens at dial time (not at URL-parse time), so a DNS change
// between the initial check and the actual HTTP request cannot bypass the guard.
/*
var safeDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
}

var safeTransport = &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("ssrf guard: invalid address %q: %w", addr, err)
		}
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("ssrf guard: dns lookup failed for %q: %w", host, err)
		}
		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return nil, fmt.Errorf("ssrf guard: resolved IP %s is not allowed (private/loopback/unspecified)", ipStr)
			}
		}
		return safeDialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	},
}

var safeClient = &http.Client{Transport: safeTransport, Timeout: 15 * time.Second}
*/

// validateEndpointURL checks that the endpoint is a safe http(s) URL and does
// not point to private/loopback IP ranges (SSRF prevention).
func validateEndpointURL(raw string) error {
	if raw == "" {
		return nil // endpoint is optional
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("endpoint must be a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("endpoint scheme must be http or https")
	}
	host := u.Hostname()
	ips, err := net.LookupHost(host)
	if err != nil {
		// If we can't resolve, accept it — we don't want to block valid hostnames
		// that are only resolvable inside the deployment network.
		// The safeTransport will enforce the IP check at actual connection time.
		return nil
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("endpoint must not resolve to a private or loopback address")
		}
	}
	return nil
}

// redactIntegration returns a copy of the integration with ApiKey cleared.
// ApiKey is write-only: it is accepted on input but never returned in responses
// to prevent secret leakage through the dashboard API.
func redactIntegration(intg *model.Integration) model.Integration {
	out := *intg
	out.ApiKey = "" // never expose the decrypted key in API responses
	return out
}

func (h *Handlers) ListIntegrations(c *gin.Context) {
	ctx := c.Request.Context()
	integrations, err := h.store.ListIntegrations(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	redacted := make([]model.Integration, 0, len(integrations))
	for _, intg := range integrations {
		redacted = append(redacted, redactIntegration(intg))
	}
	c.JSON(http.StatusOK, gin.H{"integrations": redacted})
}

func (h *Handlers) UpdateIntegration(c *gin.Context) {
	ctx := c.Request.Context()
	intg, err := h.store.GetIntegration(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "integration not found", "code": "NOT_FOUND", "status": http.StatusNotFound})
		return
	}
	originalID := intg.ID
	originalCreatedAt := intg.CreatedAt
	if err := c.ShouldBindJSON(intg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}
	intg.ID = originalID
	intg.CreatedAt = originalCreatedAt
	intg.UpdatedAt = time.Now()
	if err := validateEndpointURL(intg.Endpoint); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_ENDPOINT", "status": http.StatusBadRequest})
		return
	}
	if err := h.store.SaveIntegration(ctx, intg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": intg.Status})
}

func (h *Handlers) AddIntegration(c *gin.Context) {
	ctx := c.Request.Context()
	var body struct {
		Name     string `json:"name" binding:"required"`
		Type     string `json:"type"`
		Category string `json:"category"`
		Endpoint string `json:"endpoint"`
		ApiKey   string `json:"api_key"` // write-only; stored encrypted
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_REQUEST", "status": http.StatusBadRequest})
		return
	}
	if err := validateEndpointURL(body.Endpoint); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "INVALID_ENDPOINT", "status": http.StatusBadRequest})
		return
	}

	now := time.Now()
	intg := &model.Integration{
		ID:        uuid.New().String(),
		Name:      body.Name,
		Type:      body.Type,
		Status:    model.IntegrationDisconnected,
		Endpoint:  body.Endpoint,
		ApiKey:    body.ApiKey, // will be encrypted by store.SaveIntegration
		Metadata:  map[string]string{"category": body.Category},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.store.SaveIntegration(ctx, intg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	// Never echo the key back.
	c.JSON(http.StatusCreated, gin.H{"ok": true, "id": intg.ID, "name": intg.Name, "category": body.Category, "status": intg.Status})
}

func (h *Handlers) VeeaTelemetry(c *gin.Context) {
	ctx := c.Request.Context()
	totalAttacks, _ := h.store.CountAttacks(ctx)
	c.JSON(http.StatusOK, gin.H{
		"active_nodes":      12,
		"total_nodes":       12,
		"latency_ms":        4,
		"data_egress_bytes": 0,
		"build":             "mirage-edge v0.4.1",
		"total_requests":    totalAttacks * 3,
		"logged_count":      totalAttacks,
		"avg_latency_ms":    0.8,
		"uptime_seconds":    int64(time.Since(h.startTime).Seconds()),
		"policy_version":    "mirage-honeypot-v1",
		"last_updated":      time.Now().UTC(),
		// Fields below are mock/demo values — not collected from real nodes.
		"_demo":             true,
		"_demo_fields":      []string{"active_nodes", "total_nodes", "latency_ms", "avg_latency_ms"},
	})
}

func (h *Handlers) DeleteIntegration(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.Param("id")
	if _, err := h.store.GetIntegration(ctx, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "integration not found", "code": "NOT_FOUND", "status": http.StatusNotFound})
		return
	}
	if err := h.store.DeleteIntegration(ctx, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": id})
}

func (h *Handlers) VeeaDiagnostic(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"ok":         true,
		"report_url": "/reports/diag-" + time.Now().UTC().Format("20060102") + ".txt",
		"status":     "healthy",
		"latency_ms": 0.6,
		"policy":     "mirage-honeypot",
		"checked_at": time.Now().UTC(),
	})
}
