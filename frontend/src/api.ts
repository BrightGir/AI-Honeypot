import { MIRAGE_CONFIG } from "./config";

/**
 * MIRAGE API client
 */
export class MirageAPIClient {
  private base: string;
  private wsUrl: string;
  private key: string;

  constructor() {
    const cfg = MIRAGE_CONFIG || {};
    this.base = cfg.apiBase || '/api/v1';
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.wsUrl = cfg.wsUrl || `${proto}//${window.location.host}/ws/live`;
    this.key = cfg.apiKey || '';
  }

  async get<T = any>(path: string): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.key) headers['X-API-Key'] = this.key;
    const r = await fetch(this.base + path, { headers });
    if (!r.ok) throw new Error('API ' + r.status);
    return r.json() as Promise<T>;
  }

  async post<T = any>(path: string, body: any): Promise<T> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.key) headers['X-API-Key'] = this.key;
    const r = await fetch(this.base + path, { method: 'POST', headers, body: JSON.stringify(body) });
    if (!r.ok) throw new Error('API ' + r.status);
    return r.json() as Promise<T>;
  }

  async put<T = any>(path: string, body: any): Promise<T> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.key) headers['X-API-Key'] = this.key;
    const r = await fetch(this.base + path, { method: 'PUT', headers, body: JSON.stringify(body) });
    if (!r.ok) throw new Error('API ' + r.status);
    return r.json() as Promise<T>;
  }

  relativeTime(iso: string) {
    const sec = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (sec < 60) return sec + 's ago';
    if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
    return Math.floor(sec / 86400) + 'd ago';
  }

  mapSession(s: any) {
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

  mapAttack(a: any) {
    return {
      id: a.id,
      session: a.session_id,
      technique: a.technique_id,
      severity: a.severity,
      ts: this.relativeTime(a.timestamp),
      fakeServed: a.decoy_response
        ? a.decoy_response.slice(0, 80) + (a.decoy_response.length > 80 ? '…' : '')
        : 'Decoy response served',
      signature: a.payload
        ? a.payload.slice(0, 80) + (a.payload.length > 80 ? '…' : '')
        : '—',
      blocked: true,
    };
  }

  createWebSocket() {
    let ws: WebSocket | undefined;
    let timer: number | undefined;
    let stopped = false;
    let retryDelay = 2000;
    const MAX_DELAY = 30000;
    const wsUrl = this.wsUrl;
    const key = this.key;

    function connect() {
      if (stopped) return;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        retryDelay = 2000;
        if (key) {
          ws!.send(JSON.stringify({ token: key }));
        }
        window.dispatchEvent(new CustomEvent('mirage-ws', { detail: { type: 'connecting' } }));
      };

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'auth_ok') {
            window.dispatchEvent(new CustomEvent('mirage-ws', { detail: { type: 'connected' } }));
            return;
          }
          window.dispatchEvent(new CustomEvent('mirage-ws', { detail: msg }));
        } catch (err) { console.warn('mirage-ws: parse error', err); }
      };

      ws.onclose = (ev) => {
        window.dispatchEvent(new CustomEvent('mirage-ws', { detail: { type: 'disconnected', code: ev.code } }));
        if (!stopped) {
          timer = window.setTimeout(() => {
            retryDelay = Math.min(retryDelay * 2, MAX_DELAY);
            connect();
          }, retryDelay);
        }
      };

      ws.onerror = () => ws!.close();
    }

    connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      ws && ws.close();
    };
  }
}

export const MIRAGE_API = new MirageAPIClient();
