package api

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/BrightGir/AI-Honeypot/backend/internal/store"
	"github.com/gin-gonic/gin"
)

func (h *Handlers) ListSessions(c *gin.Context) {
	ctx := c.Request.Context()
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	sessions, err := h.store.ListSessions(ctx, limit, offset)
	if err != nil {
		slog.Error("sessions: list sessions failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	total, err := h.store.CountSessions(ctx)
	if err != nil {
		slog.Error("sessions: count sessions failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions, "total": total, "limit": limit, "offset": offset})
}

func (h *Handlers) GetSession(c *gin.Context) {
	ctx := c.Request.Context()
	sess, err := h.store.GetSession(ctx, c.Param("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found", "code": "SESSION_NOT_FOUND", "status": http.StatusNotFound})
		} else {
			slog.Error("sessions: get session failed", "id", c.Param("id"), "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		}
		return
	}
	c.JSON(http.StatusOK, sess)
}

const exportPageSize = 200

func (h *Handlers) ExportSessions(c *gin.Context) {
	ctx := c.Request.Context()
	format := c.DefaultQuery("format", "csv")

	if format == "json" {
		total, _ := h.store.CountSessions(ctx)
		var all []*model.Session
		offset := 0
		for {
			page, err := h.store.ListSessions(ctx, exportPageSize, offset)
			if err != nil {
				slog.Error("sessions json: read page", "offset", offset, "err", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
				return
			}
			all = append(all, page...)
			if len(page) < exportPageSize {
				break
			}
			offset += exportPageSize
		}
		c.JSON(http.StatusOK, gin.H{
			"sessions":    all,
			"exported_at": time.Now().UTC(),
			"total":       total,
		})
		return
	}

	// CSV: stream page-by-page so we never hold the full dataset in memory.
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", `attachment; filename="mirage-sessions.csv"`)

	w := csv.NewWriter(c.Writer)
	defer w.Flush()

	if err := w.Write([]string{
		"id", "agent_id", "status", "threat_level",
		"persona_id", "request_count", "honeypot_trigger",
		"avg_risk_score", "created_at", "updated_at",
	}); err != nil {
		slog.Error("sessions csv: write header", "err", err)
		return
	}

	offset := 0
	for {
		page, err := h.store.ListSessions(ctx, exportPageSize, offset)
		if err != nil {
			slog.Error("sessions csv: read page", "offset", offset, "err", err)
			return
		}
		for _, s := range page {
			if err := w.Write([]string{
				s.ID,
				s.AgentID,
				string(s.Status),
				string(s.ThreatLevel),
				s.PersonaID,
				strconv.Itoa(s.Telemetry.RequestCount),
				strconv.Itoa(s.Telemetry.HoneypotTrigger),
				fmt.Sprintf("%.4f", s.Telemetry.AvgRiskScore),
				s.CreatedAt.UTC().Format(time.RFC3339),
				s.UpdatedAt.UTC().Format(time.RFC3339),
			}); err != nil {
				slog.Error("sessions csv: write row", "session_id", s.ID, "err", err)
				return
			}
		}
		w.Flush()
		if len(page) < exportPageSize {
			break
		}
		offset += exportPageSize
	}
}
