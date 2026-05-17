package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/model"
	"github.com/BrightGir/AI-Honeypot/backend/internal/store"
	"github.com/BrightGir/AI-Honeypot/backend/internal/ws"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newChatHandlers creates a minimal Handlers for Chat() tests.
// lobster is nil — Chat() falls back to localInspect automatically.
// switcher is nil — tests that reach the honeypot path will need one seeded.
func newChatHandlers(t *testing.T) (*Handlers, *store.Store) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st := store.New(rdb)
	hub := ws.NewHub()
	h := &Handlers{
		store:      st,
		hub:        hub,
		threshold:  0.6,
		promptsDir: "../../prompts",
		// lobster nil → localInspect fallback
		// switcher nil → only safe for benign messages (risk < threshold)
	}
	return h, st
}

func chatRequest(t *testing.T, h *Handlers, body ChatRequest) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/chat", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	h.Chat(c)
	return w
}

// --- Session ownership tests ---

// Valid UUIDs for test sessions (must be proper UUIDs to pass UUID validation).
const (
	sessUUID1 = "11111111-1111-1111-1111-111111111111"
	sessUUID2 = "22222222-2222-2222-2222-222222222222"
	sessUUID3 = "33333333-3333-3333-3333-333333333333"
)

func TestChat_SessionOwnership_SameAgent_Allowed(t *testing.T) {
	h, st := newChatHandlers(t)
	ctx := context.Background()

	// Pre-create a session owned by agent-A.
	sess := &model.Session{
		ID:        sessUUID1,
		AgentID:   "agent-A",
		Status:    model.StatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = st.SaveSession(ctx, sess)

	// Same agent sends a benign message — should be allowed (200).
	w := chatRequest(t, h, ChatRequest{
		SessionID: sessUUID1,
		AgentID:   "agent-A",
		Message:   "help me write a report",
	})

	if w.Code == http.StatusForbidden {
		t.Errorf("same agent should not get 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChat_SessionOwnership_DifferentAgent_Forbidden(t *testing.T) {
	h, st := newChatHandlers(t)
	ctx := context.Background()

	// Pre-create a session owned by agent-A.
	sess := &model.Session{
		ID:        sessUUID2,
		AgentID:   "agent-A",
		Status:    model.StatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = st.SaveSession(ctx, sess)

	// Different agent tries to use the same session_id — must be rejected.
	w := chatRequest(t, h, ChatRequest{
		SessionID: sessUUID2,
		AgentID:   "agent-B",
		Message:   "hello",
	})

	if w.Code != http.StatusForbidden {
		t.Errorf("different agent should get 403, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "SESSION_FORBIDDEN" {
		t.Errorf("error code = %q, want SESSION_FORBIDDEN", resp["code"])
	}
}

func TestChat_SessionOwnership_NonexistentSession_CreatesNew(t *testing.T) {
	h, _ := newChatHandlers(t)

	// session_id provided but doesn't exist in store → should create a new session.
	w := chatRequest(t, h, ChatRequest{
		SessionID: sessUUID3,
		AgentID:   "agent-A",
		Message:   "help me write a report", // benign — won't trigger honeypot
	})

	// Should succeed (200) and create a new session with the given ID.
	if w.Code != http.StatusOK {
		t.Errorf("nonexistent session should create new, got %d: %s", w.Code, w.Body.String())
	}

	var resp ChatResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.SessionID != sessUUID3 {
		t.Errorf("SessionID = %q, want %q", resp.SessionID, sessUUID3)
	}
}

func TestChat_SessionOwnership_InvalidUUID_BadRequest(t *testing.T) {
	h, _ := newChatHandlers(t)

	w := chatRequest(t, h, ChatRequest{
		SessionID: "not-a-uuid",
		AgentID:   "agent-A",
		Message:   "hello",
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid UUID should return 400, got %d", w.Code)
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "INVALID_SESSION_ID" {
		t.Errorf("error code = %q, want INVALID_SESSION_ID", resp["code"])
	}
}

func TestChat_NoSessionID_CreatesNewSession(t *testing.T) {
	h, st := newChatHandlers(t)

	w := chatRequest(t, h, ChatRequest{
		AgentID: "agent-A",
		Message: "help me write a report", // benign
	})

	if w.Code != http.StatusOK {
		t.Errorf("no session_id should create new session, got %d: %s", w.Code, w.Body.String())
	}

	var resp ChatResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.SessionID == "" {
		t.Error("response should contain a new session_id")
	}

	// Verify the session was persisted.
	saved, err := st.GetSession(context.Background(), resp.SessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if saved.AgentID != "agent-A" {
		t.Errorf("AgentID = %q, want %q", saved.AgentID, "agent-A")
	}
}

func TestChat_MessageTooLong_BadRequest(t *testing.T) {
	h, _ := newChatHandlers(t)

	longMsg := make([]byte, maxMessageLen+1)
	for i := range longMsg {
		longMsg[i] = 'a'
	}

	w := chatRequest(t, h, ChatRequest{
		AgentID: "agent-A",
		Message: string(longMsg),
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("too-long message should return 400, got %d", w.Code)
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "MESSAGE_TOO_LONG" {
		t.Errorf("error code = %q, want MESSAGE_TOO_LONG", resp["code"])
	}
}

func TestChat_EmptyMessage_BadRequest(t *testing.T) {
	h, _ := newChatHandlers(t)

	w := chatRequest(t, h, ChatRequest{
		AgentID: "agent-A",
		Message: "", // binding:"required" should reject this
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("empty message should return 400, got %d", w.Code)
	}
}

func TestChat_DefaultAgentID(t *testing.T) {
	h, st := newChatHandlers(t)

	w := chatRequest(t, h, ChatRequest{
		// No AgentID — should generate a unique "agent-XXXXXXXX" ID.
		Message: "help me write a report",
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp ChatResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)

	// Verify a non-empty, unique agent ID was generated for the session.
	sess, err := st.GetSession(context.Background(), resp.SessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.AgentID == "" {
		t.Error("AgentID must not be empty when not provided by the caller")
	}
	if sess.AgentID == "enterprise-bot-001" {
		t.Error("AgentID must not be the old hardcoded default; a unique ID should be generated")
	}
}

// --- Rate limiter middleware tests ---

func TestRateLimitMiddleware_AllowsUnderLimit(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st := store.New(rdb)
	h := &Handlers{store: st}

	router := gin.New()
	router.GET("/test", h.RateLimitMiddleware(context.Background(), 5, time.Minute), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimitMiddleware_BlocksOverLimit(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st := store.New(rdb)
	h := &Handlers{store: st}

	router := gin.New()
	router.GET("/test", h.RateLimitMiddleware(context.Background(), 3, time.Minute), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Exhaust the limit.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "5.6.7.8:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}

	// 4th request must be blocked.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "5.6.7.8:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "RATE_LIMIT_EXCEEDED" {
		t.Errorf("error code = %q, want RATE_LIMIT_EXCEEDED", resp["code"])
	}
}

func TestRateLimitMiddleware_HeadersPresent(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st := store.New(rdb)
	h := &Handlers{store: st}

	router := gin.New()
	router.GET("/test", h.RateLimitMiddleware(context.Background(), 10, time.Minute), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("X-RateLimit-Limit header should be set")
	}
	if w.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("X-RateLimit-Remaining header should be set")
	}
}

// --- APIKeyMiddleware tests ---

func TestAPIKeyMiddleware_ValidKey(t *testing.T) {
	router := gin.New()
	router.GET("/protected", APIKeyMiddleware("secret-key"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-API-Key", "secret-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("valid key should return 200, got %d", w.Code)
	}
}

func TestAPIKeyMiddleware_InvalidKey(t *testing.T) {
	router := gin.New()
	router.GET("/protected", APIKeyMiddleware("secret-key"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("invalid key should return 401, got %d", w.Code)
	}
}

func TestAPIKeyMiddleware_MissingKey(t *testing.T) {
	router := gin.New()
	router.GET("/protected", APIKeyMiddleware("secret-key"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	// No X-API-Key header.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing key should return 401, got %d", w.Code)
	}
}

func TestAPIKeyMiddleware_EmptyKey_Rejected(t *testing.T) {
	router := gin.New()
	router.GET("/protected", APIKeyMiddleware("secret-key"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-API-Key", "")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("empty key should return 401, got %d", w.Code)
	}
}

// --- strconv.Itoa sanity tests ---
// These tests verify the behaviour we rely on from strconv.Itoa after
// removing the hand-rolled itoa() helper.

func TestItoa(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{-5, "-5"},
		{999, "999"},
	}
	for _, tc := range cases {
		got := strconv.Itoa(tc.n)
		if got != tc.want {
			t.Errorf("strconv.Itoa(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
