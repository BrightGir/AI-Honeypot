import { MIRAGE_CONFIG } from "./config";
/**
 * MIRAGE API client
 *
 * Configuration is read from window.MIRAGE_CONFIG (injected by the server or
 * a config.js file loaded before this script). Falls back to localhost defaults
 * so the dashboard works out-of-the-box in development without any extra setup.
 *
 * To configure for production, create a config.js that sets:
 *
 *   window.MIRAGE_CONFIG = {
 *     apiBase:  'https://mirage.example.com/api/v1',
 *     wsUrl:    'wss://mirage.example.com/ws/live',
 *     apiKey:   '<dashboard-api-key>',   // only needed for non-browser clients
 *   };
 *
 * Browser clients authenticate the WebSocket via the first message
 * ({"token": "<api-key>"}) so the key never appears in the URL or server logs.
 * The REST API key is read from the same config object.
 *
 * SECURITY NOTE: Embedding an API key in a static JS file is acceptable for
 * internal/self-hosted dashboards where the frontend is served behind
 * authentication. For public deployments, use a session-cookie-based auth
 * layer in front of the dashboard instead.
 */
export const MIRAGE_API = (function () {
  const cfg = MIRAGE_CONFIG || {};
  const BASE   = cfg.apiBase || 'http://localhost:8081/api/v1';
  const WS_URL = cfg.wsUrl   || 'ws://localhost:8081/ws/live';
  // API key: prefer explicit config, then fall back to empty string.
  // An empty key will cause the server to reject the WS auth message with
  // close code 4001 — the UI will show "connecting…" indefinitely, which is
  // the correct behaviour when no key is configured.
  const KEY = cfg.apiKey || '';

  async function get(path) {
    const headers = {};
    if (KEY) headers['X-API-Key'] = KEY;
    const r = await fetch(BASE + path, { headers });
    if (!r.ok) throw new Error('API ' + r.status);
    return r.json();
  }

  async function post(path, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (KEY) headers['X-API-Key'] = KEY;
    const r = await fetch(BASE + path, { method: 'POST', headers, body: JSON.stringify(body) });
    if (!r.ok) throw new Error('API ' + r.status);
    return r.json();
  }

  async function put(path, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (KEY) headers['X-API-Key'] = KEY;
    const r = await fetch(BASE + path, { method: 'PUT', headers, body: JSON.stringify(body) });
    if (!r.ok) throw new Error('API ' + r.status);
    return r.json();
  }

  function relativeTime(iso) {
    const sec = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (sec < 60) return sec + 's ago';
    if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
    return Math.floor(sec / 86400) + 'd ago';
  }

  function mapSession(s) {
    return {
      id: s.id,
      _fullId: s.id,
      user: s.agent_id,
      status: s.status === 'active' ? 'normal' : s.status,
      risk: Math.round((s.attacker_profile?.risk_score || 0) * 100),
      msgs: s.telemetry?.request_count || 0,
      country: '??',
      agent: s.agent_id,
      technique: s.attacker_profile?.techniques_used?.[0] || null,
      startedAt: Math.max(0, Math.floor((Date.now() - new Date(s.created_at).getTime()) / 1000)),
    };
  }

  function mapAttack(a) {
    return {
      id: a.id,
      session: a.session_id,
      technique: a.technique_id,
      severity: a.severity,
      ts: relativeTime(a.timestamp),
      fakeServed: a.decoy_response
        ? a.decoy_response.slice(0, 80) + (a.decoy_response.length > 80 ? '…' : '')
        : 'Decoy response served',
      signature: a.payload
        ? a.payload.slice(0, 80) + (a.payload.length > 80 ? '…' : '')
        : '—',
      blocked: true,
    };
  }

  /**
   * createWebSocket — starts a self-reconnecting WebSocket that:
   *  1. Connects to WS_URL.
   *  2. Sends {"token": "<api-key>"} as the first message for authentication.
   *  3. Waits for {"type": "auth_ok"} from the server.
   *  4. Dispatches all subsequent messages as window 'mirage-ws' CustomEvents.
   *  5. Reconnects with exponential back-off on disconnect.
   *
   * Returns a cleanup function that stops reconnection and closes the socket.
   */
  function createWebSocket() {
    let ws;
    let timer;
    let stopped = false;
    let retryDelay = 2000;
    const MAX_DELAY = 30000;

    function connect() {
      if (stopped) return;
      ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        retryDelay = 2000; // reset back-off on successful connect
        // Authenticate: send the API key as the first message.
        // The server expects {"token": "<key>"} before streaming events.
        if (KEY) {
          ws.send(JSON.stringify({ token: KEY }));
        }
        // Dispatch a 'connecting' event — the UI will update to 'live' once
        // auth_ok is received.
        window.dispatchEvent(new CustomEvent('mirage-ws', { detail: { type: 'connecting' } }));
      };

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'auth_ok') {
            // Authentication succeeded — signal the UI.
            window.dispatchEvent(new CustomEvent('mirage-ws', { detail: { type: 'connected' } }));
            return;
          }
          window.dispatchEvent(new CustomEvent('mirage-ws', { detail: msg }));
        } catch (e) { console.warn('mirage-ws: parse error', e); }
      };

      ws.onclose = (ev) => {
        window.dispatchEvent(new CustomEvent('mirage-ws', { detail: { type: 'disconnected', code: ev.code } }));
        if (!stopped) {
          // Exponential back-off: 2s → 4s → 8s … capped at 30s.
          timer = setTimeout(() => {
            retryDelay = Math.min(retryDelay * 2, MAX_DELAY);
            connect();
          }, retryDelay);
        }
      };

      ws.onerror = () => ws.close();
    }

    connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      ws && ws.close();
    };
  }

  return { get, post, put, relativeTime, mapSession, mapAttack, createWebSocket };
})();
