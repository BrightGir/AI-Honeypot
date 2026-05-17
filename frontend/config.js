/**
 * MIRAGE Dashboard — runtime configuration
 *
 * Copy this file to config.local.js (gitignored) and fill in your values,
 * OR set window.MIRAGE_CONFIG before api.js loads (e.g. via a server-side
 * template that injects the values at request time).
 *
 * All fields are optional — api.js falls back to localhost defaults so the
 * dashboard works out-of-the-box in development without any configuration.
 *
 * Fields:
 *   apiBase  — Base URL for the REST API, e.g. 'https://mirage.example.com/api/v1'
 *   wsUrl    — WebSocket URL,             e.g. 'wss://mirage.example.com/ws/live'
 *   apiKey   — Dashboard API key (value of API_KEY env var on the backend).
 *              Used to authenticate the WebSocket connection and REST requests.
 *              SECURITY: Only embed this key in deployments where the dashboard
 *              is served behind its own authentication layer (VPN, SSO, etc.).
 *              For public-facing deployments, use a server-side session proxy
 *              instead of embedding the key in a static file.
 */
window.MIRAGE_CONFIG = {
  apiBase: window.location.protocol + '//' + window.location.host + '/api/v1',
  wsUrl:   (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host + '/ws/live',
  apiKey:  '',
};
