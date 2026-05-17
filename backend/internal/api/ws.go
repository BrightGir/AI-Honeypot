package api

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const wsAuthDeadline = 10 * time.Second // max time to receive the auth message

// wsCloseUnauthorized is the application-level WebSocket close code sent when
// authentication fails. 4000-4999 are reserved for application use per RFC 6455.
const wsCloseUnauthorized = 4001

func buildUpgrader(corsOrigins []string) websocket.Upgrader {
	if len(corsOrigins) == 1 && corsOrigins[0] == "*" {
		return websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	}
	allowed := make(map[string]struct{}, len(corsOrigins))
	for _, o := range corsOrigins {
		allowed[o] = struct{}{}
	}
	return websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			if len(allowed) == 0 {
				return false
			}
			_, ok := allowed[r.Header.Get("Origin")]
			return ok
		},
	}
}

// WebSocketLive upgrades the connection to WebSocket and then authenticates
// the client via the first message it sends.
//
// Authentication flow:
//  1. Client connects (no credentials in URL — avoids token in server logs).
//  2. Client immediately sends: {"token": "<api-key>"}
//  3. Server validates with constant-time compare.
//  4. On success: server sends {"type":"auth_ok"} and starts streaming events.
//  5. On failure: server closes the connection with code 4001.
//
// Programmatic clients that can set HTTP headers may also supply the key via
// the X-API-Key header before the upgrade — this path is kept for backward
// compatibility with non-browser clients.
//
// After authentication, Hub.Register starts both writePump and readPump
// goroutines. The readPump handles ping/pong keepalive and detects client
// disconnects; the writePump sends broadcast messages and periodic pings.
// WebSocketLive blocks until the client disconnects.
func (h *Handlers) WebSocketLive(c *gin.Context) {
	// Fast path: programmatic clients that can set custom HTTP headers.
	headerToken := c.GetHeader("X-API-Key")
	headerAuthed := headerToken != "" &&
		subtle.ConstantTimeCompare([]byte(headerToken), []byte(h.apiKey)) == 1

	upgrader := buildUpgrader(h.corsOrigins)
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		slog.Warn("ws upgrade error", "err", err)
		return
	}

	// If the header auth didn't pass, require the first message to carry the token.
	if !headerAuthed {
		conn.SetReadDeadline(time.Now().Add(wsAuthDeadline))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			slog.Warn("ws: auth message not received", "err", err)
			conn.Close()
			return
		}
		var authMsg struct {
			Token string `json:"token"`
		}
		if jsonErr := json.Unmarshal(msg, &authMsg); jsonErr != nil ||
			subtle.ConstantTimeCompare([]byte(authMsg.Token), []byte(h.apiKey)) != 1 {
			slog.Warn("ws: invalid auth token")
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(wsCloseUnauthorized, "unauthorized"))
			conn.Close()
			return
		}
	}

	// Audit log: record every successful authentication for incident response.
	slog.Info("ws: client authenticated", "remote_addr", conn.RemoteAddr())

	// Send auth confirmation so the client knows it can start receiving events.
	if err := conn.WriteJSON(map[string]string{"type": "auth_ok"}); err != nil {
		slog.Warn("ws: failed to send auth_ok", "err", err)
		conn.Close()
		return
	}

	// Register starts writePump + readPump goroutines.
	client := h.hub.Register(conn)
	<-client.Done()
}
