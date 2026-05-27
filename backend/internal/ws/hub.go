package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// writeWait is the time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// pongWait is the time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// pingPeriod is how often to send pings. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// maxMessageSize is the maximum message size allowed from the peer (bytes).
	// Dashboard clients only send auth tokens and pong frames — 512 bytes is plenty.
	maxMessageSize = 512

	heartbeatPeriod = 5 * time.Second
)

// Client represents a single WebSocket connection managed by the Hub.
type Client struct {
	conn      *websocket.Conn
	send      chan []byte
	done      chan struct{} // closed by writePump when the write side shuts down
	closeOnce sync.Once    // ensures conn.Close is called exactly once
}

type Hub struct {
	mu           sync.RWMutex
	clients      map[*Client]struct{}
	// eventsPerSec counts events in the last 1-second window (updated every second by evtTicker).
	// Note: the heartbeat broadcasts this value every 5 seconds (heartbeatPeriod), so the
	// dashboard sees the most-recent 1-second sample at each heartbeat tick.
	eventsPerSec atomic.Int64
	eventCounter atomic.Int64
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[*Client]struct{}),
	}
}

// Register upgrades a raw WebSocket connection to a managed Client and starts
// both the write pump and the read pump goroutines.
func (h *Hub) Register(conn *websocket.Conn) *Client {
	c := &Client{
		conn: conn,
		send: make(chan []byte, 256),
		done: make(chan struct{}),
	}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	slog.Debug("ws: client connected", "remote_addr", conn.RemoteAddr())
	go c.writePump(func() { h.Unregister(c) })
	go c.readPump(func() { h.Unregister(c) })
	return c
}

func (h *Hub) Unregister(c *Client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		// Closing the send channel signals writePump to exit and close the
		// underlying connection. Guard with ok-check to avoid double-close.
		close(c.send)
		slog.Debug("ws: client disconnected", "remote_addr", c.conn.RemoteAddr())
	}
	h.mu.Unlock()
}

func (h *Hub) Broadcast(msg any) {
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.eventCounter.Add(1)

	// Copy the client list under RLock so the lock is held only for the
	// map iteration, not for the (potentially blocking) channel sends.
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	for _, c := range clients {
		select {
		case c.send <- b:
		default:
			slog.Warn("ws: client send buffer full, dropping message")
		}
	}
}

func (h *Hub) clientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// StartHeartbeat sends a heartbeat every heartbeatPeriod as per API spec.
func (h *Hub) StartHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(heartbeatPeriod)
	evtTicker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	defer evtTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-evtTicker.C:
			// update events_per_sec counter every second
			h.eventsPerSec.Store(h.eventCounter.Swap(0))
		case <-ticker.C:
			h.Broadcast(map[string]any{
				"type": "heartbeat",
				"data": map[string]any{
					"collectors":     h.clientCount(),
					"events_per_sec": h.eventsPerSec.Load(),
					"timestamp":      time.Now().UTC(),
				},
			})
		}
	}
}

// writePump pumps messages from the send channel to the WebSocket connection.
// It also sends periodic ping frames to keep the connection alive and detect
// dead peers. A single goroutine per client owns all writes so there are no
// concurrent write races.
func (c *Client) writePump(onClose func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("ws: writePump panic recovered", "err", r)
		}
	}()

	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.closeOnce.Do(func() { _ = c.conn.Close() })
		close(c.done)
		onClose()
	}()

	for {
		select {
		case msg, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Hub closed the channel — send a clean close frame.
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				slog.Debug("ws: write error", "err", err)
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				slog.Debug("ws: ping error", "err", err)
				return
			}
		}
	}
}

// readPump pumps messages from the WebSocket connection.
// It handles pong frames (resetting the read deadline) and detects client
// disconnects. All reads must happen in a single goroutine per the gorilla/websocket
// documentation.
func (c *Client) readPump(onClose func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("ws: readPump panic recovered", "err", r)
		}
	}()

	defer func() {
		c.closeOnce.Do(func() { _ = c.conn.Close() })
		onClose()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		// Reset the read deadline each time we receive a pong.
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	c.conn.SetCloseHandler(func(code int, text string) error {
		slog.Debug("ws: client sent close frame", "code", code, "text", text)
		// Send a close frame back and let the read loop exit naturally.
		msg := websocket.FormatCloseMessage(code, "")
		if err := c.conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(writeWait)); err != nil {
			slog.Debug("ws: WriteControl close error", "err", err)
		}
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseGoingAway,
				websocket.CloseNormalClosure,
				websocket.CloseNoStatusReceived,
			) {
				slog.Debug("ws: unexpected close", "err", err)
			}
			return
		}
		// Dashboard clients don't send application messages after auth —
		// any incoming data is silently discarded (pong frames are handled
		// by the PongHandler above and never reach here).
	}
}

// Done returns a channel that is closed when the write pump has shut down.
func (c *Client) Done() <-chan struct{} {
	return c.done
}
