package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/store"
	"github.com/BrightGir/AI-Honeypot/backend/internal/ws"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
)

const wsTestAPIKey = "test-secret-key-for-ws"

// newWSTestHandlers creates a minimal Handlers instance for WebSocket tests.
// Named differently from newTestHandlers in rules_engine_test.go to avoid collision.
func newWSTestHandlers(t *testing.T) *Handlers {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	st := store.New(rdb)
	hub := ws.NewHub()
	return &Handlers{
		store:       st,
		hub:         hub,
		corsOrigins: []string{"*"},
		apiKey:      wsTestAPIKey,
	}
}

func newWSTestRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ws/live", h.WebSocketLive)
	return r
}

// dialAndAuth connects via WebSocket and sends the auth message.
// Returns the connection and the first server message (auth_ok or close).
func dialAndAuth(t *testing.T, srvURL, token string, header http.Header) (*websocket.Conn, map[string]string, error) {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(srvURL, "http") + "/ws/live"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		return nil, nil, err
	}
	if token != "" {
		msg, _ := json.Marshal(map[string]string{"token": token})
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			conn.Close()
			return nil, nil, err
		}
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, reply, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	var result map[string]string
	json.Unmarshal(reply, &result)
	return conn, result, nil
}

// TestWebSocketLive_NoToken verifies that connecting without sending an auth
// message causes the server to close the connection (abnormal closure / timeout).
func TestWebSocketLive_NoToken(t *testing.T) {
	h := newWSTestHandlers(t)
	srv := httptest.NewServer(newWSTestRouter(h))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/live"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		// Connection refused before upgrade — acceptable rejection.
		return
	}
	defer conn.Close()

	// Send no auth message; server should close with code 4001 or drop connection.
	conn.SetReadDeadline(time.Now().Add(wsAuthDeadline + time.Second))
	_, _, readErr := conn.ReadMessage()
	if readErr == nil {
		t.Error("expected server to close connection after auth timeout, but read succeeded")
	}
}

// TestWebSocketLive_WrongToken verifies that a wrong token causes the server
// to close the connection with close code 4001.
func TestWebSocketLive_WrongToken(t *testing.T) {
	h := newWSTestHandlers(t)
	srv := httptest.NewServer(newWSTestRouter(h))
	defer srv.Close()

	conn, result, err := dialAndAuth(t, srv.URL, "wrong-token", nil)
	if err == nil {
		defer conn.Close()
		// If we got a reply, it must NOT be auth_ok.
		if result["type"] == "auth_ok" {
			t.Error("wrong token should not receive auth_ok")
		}
	}
	// err != nil means server closed the connection — that's the expected path.
}

// TestWebSocketLive_ValidToken verifies that a correct token sent as the first
// message results in an auth_ok response.
func TestWebSocketLive_ValidToken(t *testing.T) {
	h := newWSTestHandlers(t)
	srv := httptest.NewServer(newWSTestRouter(h))
	defer srv.Close()

	conn, result, err := dialAndAuth(t, srv.URL, wsTestAPIKey, nil)
	if err != nil {
		t.Fatalf("WebSocket auth: %v", err)
	}
	defer conn.Close()
	if result["type"] != "auth_ok" {
		t.Errorf("expected auth_ok, got %v", result)
	}
}

// TestWebSocketLive_ValidToken_Header verifies that the X-API-Key header is
// accepted as an alternative to the first-message token.
func TestWebSocketLive_ValidToken_Header(t *testing.T) {
	h := newWSTestHandlers(t)
	srv := httptest.NewServer(newWSTestRouter(h))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/live"
	header := http.Header{"X-Api-Key": []string{wsTestAPIKey}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("WebSocket dial with header: %v", err)
	}
	defer conn.Close()

	// Header auth skips the first-message flow; server sends auth_ok directly.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, reply, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read auth_ok: %v", err)
	}
	var result map[string]string
	json.Unmarshal(reply, &result)
	if result["type"] != "auth_ok" {
		t.Errorf("expected auth_ok, got %v", result)
	}
}

// TestSecurityHeadersMiddleware verifies that security headers are present on
// responses when the middleware is applied.
func TestSecurityHeadersMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecurityHeadersMiddleware())
	r.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	headers := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
		"Content-Security-Policy":   "default-src",
		"Strict-Transport-Security": "max-age=",
	}
	for header, wantPrefix := range headers {
		got := w.Header().Get(header)
		if got == "" {
			t.Errorf("missing header %q", header)
			continue
		}
		if !strings.Contains(got, wantPrefix) {
			t.Errorf("header %q = %q, want to contain %q", header, got, wantPrefix)
		}
	}
}
