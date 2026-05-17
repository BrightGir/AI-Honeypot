package api

import (
	"encoding/csv"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

// Health returns a minimal liveness probe. It intentionally exposes no
// internal metrics (e.g. lobster_fallback_total) to avoid information leakage.
func (h *Handlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

func (h *Handlers) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Run independent Redis calls in parallel to reduce latency.
	var (
		totalSessions   int64
		totalAttacks    int64
		techniqueCounts map[string]int64
		attacks         []*model.Attack
		dataStale       bool
	)

	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		var err error
		totalSessions, err = h.store.CountSessions(egCtx)
		if err != nil {
			slog.Warn("GetStats: CountSessions failed", "err", err)
			dataStale = true
		}
		return nil
	})
	eg.Go(func() error {
		var err error
		totalAttacks, err = h.store.CountAttacks(egCtx)
		if err != nil {
			slog.Warn("GetStats: CountAttacks failed", "err", err)
			dataStale = true
		}
		return nil
	})
	eg.Go(func() error {
		var err error
		techniqueCounts, err = h.store.GetTechniqueCounts(egCtx)
		if err != nil {
			slog.Warn("GetStats: GetTechniqueCounts failed", "err", err)
			dataStale = true
		}
		return nil
	})
	eg.Go(func() error {
		var err error
		attacks, err = h.store.ListAttacks(egCtx, 50, 0)
		if err != nil {
			slog.Warn("GetStats: ListAttacks failed", "err", err)
			dataStale = true
		}
		return nil
	})
	_ = eg.Wait() // errors are logged above; we return partial data with data_stale flag

	// Count honeypot sessions by sampling up to statsSessionCap sessions.
	// and decremented on session termination. This would give an exact count
	// without loading any session objects. Tracked in: TODO(honeypot-counter).
	const statsSessionCap = 200
	honeypotSessions := int64(0)
	sampleSessions, err := h.store.ListSessions(ctx, statsSessionCap, 0)
	if err != nil {
		slog.Warn("GetStats: ListSessions failed", "err", err)
		dataStale = true
	}
	for _, s := range sampleSessions {
		if s.Status == model.StatusHoneypot && !s.IsDemo {
			honeypotSessions++
		}
	}
	// If we hit the cap, extrapolate proportionally.
	if int64(len(sampleSessions)) == statsSessionCap && totalSessions > statsSessionCap {
		honeypotSessions = honeypotSessions * totalSessions / statsSessionCap
	}

	// top technique
	topTechnique := ""
	topCount := int64(0)
	for tech, count := range techniqueCounts {
		if count > topCount {
			topCount = count
			topTechnique = tech
		}
	}

	// avg risk score from recent attacks
	avgRisk := 0.0
	if len(attacks) > 0 {
		sum := 0.0
		for _, a := range attacks {
			sum += a.LobsterMeta.RiskScore
		}
		avgRisk = sum / float64(len(attacks))
	}

	// trap engagement: avg decoy messages per real (non-demo) honeypot session
	avgTrapEngagement := 0.0
	honeypotCount := 0
	for _, s := range sampleSessions {
		if s.Status == model.StatusHoneypot && !s.IsDemo {
			decoyMsgs := 0
			for _, m := range s.Messages {
				if m.IsDecoy {
					decoyMsgs++
				}
			}
			avgTrapEngagement += float64(decoyMsgs)
			honeypotCount++
		}
	}
	if honeypotCount > 0 {
		avgTrapEngagement /= float64(honeypotCount)
	}

	c.JSON(http.StatusOK, gin.H{
		"total_attacks":             totalAttacks,
		"attacks_delta_pct":         0,
		"active_honeypot_sessions":  honeypotSessions,
		"honeypot_delta":            0,
		"data_requests_blocked":     totalAttacks,
		"blocked_delta_pct":         0,
		"protected_agents":          totalSessions,
		"agents_delta_pct":          0,
		"avg_trap_engagement":       avgTrapEngagement,
		// legacy fields kept for compatibility
		"total_sessions":    totalSessions,
		"honeypot_sessions": honeypotSessions,
		"avg_risk_score":    avgRisk,
		"top_technique":     topTechnique,
		"technique_counts":  techniqueCounts,
		"threats_blocked":   totalAttacks,
		"active_sessions":   totalSessions - honeypotSessions,
		// data_stale is true when one or more Redis calls failed; callers
		// should treat the response as a best-effort snapshot.
		"data_stale": dataStale,
	})
}

func (h *Handlers) GetStatsTimeline(c *gin.Context) {
	ctx := c.Request.Context()
	window := c.DefaultQuery("window", "24h")

	var buckets int
	var duration time.Duration
	switch window {
	case "7d":
		buckets = 7
		duration = 24 * time.Hour
	case "30d":
		buckets = 30
		duration = 24 * time.Hour
	default: // 24h
		buckets = 24
		duration = time.Hour
	}

	timelineCap := buckets * 200
	if timelineCap < 1000 {
		timelineCap = 1000
	}
	attacks, _ := h.store.ListAttacks(ctx, timelineCap, 0)
	now := time.Now()

	// Bucket attacks in a single O(n) pass instead of O(n*buckets).
	counts := make([]int, buckets)
	for _, a := range attacks {
		age := now.Sub(a.Timestamp)
		idx := buckets - 1 - int(age/duration)
		if idx >= 0 && idx < buckets {
			counts[idx]++
		}
	}

	data := make([]gin.H, buckets)
	for i := 0; i < buckets; i++ {
		t := now.Add(-time.Duration(buckets-i) * duration)
		label := t.UTC().Format("15:04")
		if window == "7d" || window == "30d" {
			label = t.UTC().Format("Jan 02")
		}
		count := counts[i]
		data[i] = gin.H{"label": label, "attacks": count, "honeypot": 0, "blocked": 0}
	}

	c.JSON(http.StatusOK, data)
}

// GetTechniques returns technique distribution for the donut chart.
func (h *Handlers) GetTechniques(c *gin.Context) {
	ctx := c.Request.Context()
	techniqueCounts, _ := h.store.GetTechniqueCounts(ctx)

	result := make([]gin.H, 0, len(techniqueCounts))
	for name, count := range techniqueCounts {
		result = append(result, gin.H{"name": name, "value": count})
	}
	if len(result) == 0 {
		result = []gin.H{
			{"name": "Prompt Injection", "value": 0},
		}
	}
	c.JSON(http.StatusOK, result)
}

// agentStats holds per-agent counters for GetTopAgents.
type agentStats struct {
	Name     string `json:"name"`
	Sessions int    `json:"sessions"`
	Attacks  int    `json:"attacks"`
	Honeypot int    `json:"honeypot"`
}

// GetTopAgents returns the most-targeted agents table.
func (h *Handlers) GetTopAgents(c *gin.Context) {
	ctx := c.Request.Context()
	sessions, _ := h.store.ListSessions(ctx, 200, 0)

	agentMap := make(map[string]*agentStats)
	for _, s := range sessions {
		if _, ok := agentMap[s.AgentID]; !ok {
			agentMap[s.AgentID] = &agentStats{Name: s.AgentID}
		}
		entry := agentMap[s.AgentID]
		entry.Sessions++
		entry.Attacks += s.Telemetry.RequestCount
		if s.Status == model.StatusHoneypot {
			entry.Honeypot++
		}
	}

	result := make([]*agentStats, 0, len(agentMap))
	for _, v := range agentMap {
		result = append(result, v)
	}
	c.JSON(http.StatusOK, result)
}

func (h *Handlers) GetGeo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"_demo":        true,
		"_demo_reason": "geo enrichment not yet implemented; data is illustrative only",
		"data": []gin.H{
			{"country": "United States", "code": "US", "count": 421, "pct": 28},
			{"country": "China", "code": "CN", "count": 312, "pct": 21},
			{"country": "Russia", "code": "RU", "count": 198, "pct": 13},
			{"country": "Germany", "code": "DE", "count": 145, "pct": 10},
			{"country": "Brazil", "code": "BR", "count": 98, "pct": 7},
		},
	})
}

func (h *Handlers) ExportAll(c *gin.Context) {
	ctx := c.Request.Context()
	format := c.DefaultQuery("format", "csv")

	if format == "json" {
		sessions, err := h.store.ListSessions(ctx, 1000, 0)
		if err != nil {
			slog.Error("export-all: list sessions failed", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
			return
		}
		attacks, err := h.store.ListAttacks(ctx, 1000, 0)
		if err != nil {
			slog.Error("export-all: list attacks failed", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
			return
		}
		totalSess, _ := h.store.CountSessions(ctx)
		totalAtk, _ := h.store.CountAttacks(ctx)
		c.JSON(http.StatusOK, gin.H{
			"sessions":           sessions,
			"attacks":            attacks,
			"exported_at":        time.Now().UTC(),
			"sessions_total":     totalSess,
			"attacks_total":      totalAtk,
			"sessions_truncated": int64(len(sessions)) < totalSess,
			"attacks_truncated":  int64(len(attacks)) < totalAtk,
		})
		return
	}

	// CSV: stream sessions then attacks page-by-page.
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", `attachment; filename="mirage-stats.csv"`)

	w := csv.NewWriter(c.Writer)
	defer w.Flush()

	_ = w.Write([]string{"type", "id", "agent_id", "status", "created_at"})

	offset := 0
	for {
		page, err := h.store.ListSessions(ctx, exportPageSize, offset)
		if err != nil {
			slog.Error("export-all csv: read sessions page", "offset", offset, "err", err)
			return
		}
		for _, s := range page {
			_ = w.Write([]string{"session", s.ID, s.AgentID, string(s.Status), s.CreatedAt.UTC().Format(time.RFC3339)})
		}
		w.Flush()
		if len(page) < exportPageSize {
			break
		}
		offset += exportPageSize
	}

	offset = 0
	for {
		page, err := h.store.ListAttacks(ctx, exportPageSize, offset)
		if err != nil {
			slog.Error("export-all csv: read attacks page", "offset", offset, "err", err)
			return
		}
		for _, a := range page {
			_ = w.Write([]string{"attack", a.ID, a.AgentID, string(a.Severity), a.Timestamp.UTC().Format(time.RFC3339)})
		}
		w.Flush()
		if len(page) < exportPageSize {
			break
		}
		offset += exportPageSize
	}
}

func (h *Handlers) ExportAttacks(c *gin.Context) {
	ctx := c.Request.Context()
	format := c.DefaultQuery("format", "csv")

	if format == "stix" || format == "json" {
		attacks, err := h.store.ListAttacks(ctx, 1000, 0)
		if err != nil {
			slog.Error("export-attacks: list attacks failed", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
			return
		}
		total, _ := h.store.CountAttacks(ctx)
		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", `attachment; filename="mirage-ioc.stix.json"`)
		c.JSON(http.StatusOK, gin.H{
			"type":      "bundle",
			"id":        "bundle--mirage",
			"objects":   attacks,
			"total":     total,
			"truncated": int64(len(attacks)) < total,
		})
		return
	}

	// CSV: stream page-by-page.
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", `attachment; filename="mirage-attacks.csv"`)

	w := csv.NewWriter(c.Writer)
	defer w.Flush()

	_ = w.Write([]string{"id", "session_id", "agent_id", "technique_id", "technique_name", "severity", "risk_score", "timestamp"})

	offset := 0
	for {
		page, err := h.store.ListAttacks(ctx, exportPageSize, offset)
		if err != nil {
			slog.Error("attacks csv: read page", "offset", offset, "err", err)
			return
		}
		for _, a := range page {
			_ = w.Write([]string{
				a.ID,
				a.SessionID,
				a.AgentID,
				a.TechniqueID,
				a.TechniqueName,
				string(a.Severity),
				strconv.FormatFloat(a.LobsterMeta.RiskScore, 'f', 4, 64),
				a.Timestamp.UTC().Format(time.RFC3339),
			})
		}
		w.Flush()
		if len(page) < exportPageSize {
			break
		}
		offset += exportPageSize
	}
}
