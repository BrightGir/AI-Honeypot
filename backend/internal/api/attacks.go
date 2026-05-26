package api

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) ListAttacks(c *gin.Context) {
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

	attacks, err := h.store.ListAttacks(ctx, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	total, err := h.store.CountAttacks(ctx)
	if err != nil {
		slog.Error("attacks: count attacks failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": "STORE_ERROR", "status": http.StatusInternalServerError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"attacks": attacks, "total": total, "limit": limit, "offset": offset})
}

func (h *Handlers) GetAttack(c *gin.Context) {
	ctx := c.Request.Context()
	attack, err := h.store.GetAttack(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "attack not found", "code": "ATTACK_NOT_FOUND", "status": http.StatusNotFound})
		return
	}
	c.JSON(http.StatusOK, attack)
}

func (h *Handlers) CreateIOC(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":  "IOC export is not yet implemented",
		"code":   "NOT_IMPLEMENTED",
		"status": http.StatusNotImplemented,
	})
}
