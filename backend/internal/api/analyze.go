package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/gin-gonic/gin"
)

const analyzeSystemPrompt = `You are a security analyst for an AI honeypot system.
Analyze the provided conversation transcript between an attacker and a decoy AI agent.
Be concise and structured. Focus on what is tactically interesting for a defender.`

// AnalyzeSession calls the available LLM to produce a threat intelligence
// summary for a given honeypot session.
func (h *Handlers) AnalyzeSession(c *gin.Context) {
	ctx := c.Request.Context()
	sess, err := h.store.GetSession(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found", "code": "SESSION_NOT_FOUND"})
		return
	}

	if len(sess.Messages) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"summary":      "No messages to analyze.",
			"tactics":      []string{},
			"intent":       sess.AttackerProfile.IntentCategory,
			"risk_level":   "unknown",
			"generated_at": time.Now().UTC(),
		})
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Session ID: %s\nAgent: %s\nStatus: %s\nRisk score: %.2f\n\n",
		sess.ID, sess.AgentID, sess.Status, sess.AttackerProfile.RiskScore))
	sb.WriteString("=== TRANSCRIPT ===\n")
	for _, m := range sess.Messages {
		role := "ATTACKER"
		if m.Role == "assistant" {
			if m.IsDecoy {
				role = "DECOY"
			} else {
				role = "AGENT"
			}
		}
		sb.WriteString(fmt.Sprintf("[%s] %s\n", role, m.Content))
	}
	sb.WriteString(fmt.Sprintf("\nTechniques: %s\nIntent: %s\n",
		strings.Join(sess.AttackerProfile.TechniquesUsed, ", "),
		sess.AttackerProfile.IntentCategory))

	userPrompt := sb.String() + `

Provide a structured analysis in this exact format:
SUMMARY: (2-3 sentences describing the attack)
TACTICS: (comma-separated list of attack tactics observed)
INTENT: (attacker's likely goal)
RISK_LEVEL: (low/medium/high/critical)
RECOMMENDATION: (1-2 sentences for the defender)`

	analysis, analyzeErr := h.callAnalysisLLM(ctx, analyzeSystemPrompt, userPrompt)
	if analyzeErr != nil {
		c.JSON(http.StatusOK, gin.H{
			"summary":        "LLM analysis unavailable. Manual review recommended.",
			"tactics":        sess.AttackerProfile.TechniquesUsed,
			"intent":         sess.AttackerProfile.IntentCategory,
			"risk_level":     riskLevel(sess.AttackerProfile.RiskScore),
			"recommendation": "Review session transcript manually.",
			"session_id":     sess.ID,
			"generated_at":   time.Now().UTC(),
		})
		return
	}

	result := parseAnalysis(analysis)
	result["session_id"] = sess.ID
	result["generated_at"] = time.Now().UTC()
	result["raw"] = analysis
	c.JSON(http.StatusOK, result)
}

func (h *Handlers) callAnalysisLLM(ctx context.Context, system, user string) (string, error) {
	// Use OpenAI's dedicated AnalyzeText when available — errors propagate
	// so AnalyzeSession can fall back to its structured stub response instead
	// of silently parsing a random decoy fallback string.
	if h.openai != nil {
		return h.openai.AnalyzeText(ctx, system, user)
	}
	// Gemini-only deployment: use GenerateDecoyResponse with the analysis
	// system prompt as the persona briefing.
	if h.generator != nil {
		persona := &model.Persona{SystemPrompt: system}
		return h.generator.GenerateDecoyResponse(ctx, persona, user)
	}
	return "", fmt.Errorf("no LLM available for analysis")
}

func parseAnalysis(raw string) gin.H {
	result := gin.H{
		"summary":        "",
		"tactics":        []string{},
		"intent":         "",
		"risk_level":     "medium",
		"recommendation": "",
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "SUMMARY:"):
			result["summary"] = strings.TrimSpace(strings.TrimPrefix(line, "SUMMARY:"))
		case strings.HasPrefix(line, "TACTICS:"):
			raw := strings.TrimSpace(strings.TrimPrefix(line, "TACTICS:"))
			tactics := strings.Split(raw, ",")
			cleaned := make([]string, 0, len(tactics))
			for _, t := range tactics {
				if t = strings.TrimSpace(t); t != "" {
					cleaned = append(cleaned, t)
				}
			}
			result["tactics"] = cleaned
		case strings.HasPrefix(line, "INTENT:"):
			result["intent"] = strings.TrimSpace(strings.TrimPrefix(line, "INTENT:"))
		case strings.HasPrefix(line, "RISK_LEVEL:"):
			result["risk_level"] = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "RISK_LEVEL:")))
		case strings.HasPrefix(line, "RECOMMENDATION:"):
			result["recommendation"] = strings.TrimSpace(strings.TrimPrefix(line, "RECOMMENDATION:"))
		}
	}
	return result
}

func riskLevel(score float64) string {
	switch {
	case score >= 0.85:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.5:
		return "medium"
	default:
		return "low"
	}
}
