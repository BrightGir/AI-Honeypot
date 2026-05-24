// Shared components and helpers

import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";


// Expose React hooks globally so all subsequent view scripts can use them
// without re-destructuring (they run in separate Babel script scopes).


const Icon = ({ name, size = 14 }) => {
  const paths = {
    shield: <path d="M12 2 4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" />,
    activity: <path d="M22 12h-4l-3 9L9 3l-3 9H2" />,
    eye: <><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></>,
    target: <><circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" /></>,
    bug: <><path d="M8 2l1.88 1.88" /><path d="M14.12 3.88 16 2" /><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1" /><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6z" /><path d="M12 20v-9" /><path d="M6.53 9 4 8" /><path d="M6 13H2" /><path d="m6 17-2.5 1" /><path d="m17.47 9 2.53-1" /><path d="M18 13h4" /><path d="m18 17 2.5 1" /></>,
    chart: <><path d="M3 3v18h18" /><path d="M7 16l4-4 3 3 5-5" /></>,
    layers: <><path d="M12 2 2 7l10 5 10-5-10-5z" /><path d="m2 17 10 5 10-5" /><path d="m2 12 10 5 10-5" /></>,
    search: <><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></>,
    alert: <><path d="M12 9v4" /><path d="M12 17h.01" /><path d="m4.86 19 7.07-12.25a1 1 0 0 1 1.74 0L20.74 19a1 1 0 0 1-.87 1.5H5.73A1 1 0 0 1 4.86 19z" /></>,
    arrow: <path d="M5 12h14M13 6l6 6-6 6" />,
    flag: <><path d="M4 22V4a1 1 0 0 1 1-1h13l-2 5 2 5H5" /><path d="M4 22H2" /></>,
    download: <><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><path d="m7 10 5 5 5-5" /><path d="M12 15V3" /></>,
    pause: <><rect x="6" y="4" width="4" height="16" /><rect x="14" y="4" width="4" height="16" /></>,
    play: <polygon points="5 3 19 12 5 21 5 3" />,
    skull: <><path d="M9 18v-1a2 2 0 1 0-4 0v1" /><path d="M19 18v-1a2 2 0 1 0-4 0v1" /><circle cx="9" cy="12" r="1.5" /><circle cx="15" cy="12" r="1.5" /><path d="M12 2a9 9 0 0 0-9 9c0 3.5 2 6.5 5 8v2a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-2c3-1.5 5-4.5 5-8a9 9 0 0 0-9-9z" /></>,
    clock: <><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></>,
    filter: <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />,
    plus: <><path d="M12 5v14M5 12h14"/></>,
  };
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      {paths[name]}
    </svg>
  );
};

const Pill = ({ kind, children }) => (
  <span className={`pill ${kind}`}><span className="dot"></span>{children}</span>
);

const RiskMeter = ({ score }) => {
  const color = score >= 80 ? 'var(--threat)' : score >= 50 ? 'var(--warn)' : score >= 25 ? 'var(--info)' : 'var(--safe)';
  return (
    <span className="risk-meter">
      <span className="risk-bar"><span className="risk-fill" style={{ width: `${score}%`, background: color }} /></span>
      <span className="risk-num" style={{ color }}>{score}</span>
    </span>
  );
};

const SessionStatus = ({ status }) => {
  if (status === 'honeypot') return <Pill kind="threat">DECOY</Pill>;
  if (status === 'suspicious') return <Pill kind="warn">Suspicious</Pill>;
  if (status === 'normal') return <Pill kind="safe">Normal</Pill>;
  return <Pill kind="mute">{status}</Pill>;
};

const Severity = ({ level }) => {
  const map = {
    critical: { kind: 'threat', label: 'Critical' },
    high: { kind: 'warn', label: 'High' },
    medium: { kind: 'info', label: 'Medium' },
    low: { kind: 'mute', label: 'Low' },
  };
  const m = map[level] || map.low;
  return <Pill kind={m.kind}>{m.label}</Pill>;
};

const Sparkline = ({ data, color = 'var(--info)', fill = true }) => {
  const w = 120, h = 28, pad = 1;
  if (!data || !data.length) return null;
  const min = Math.min(...data), max = Math.max(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = pad + (i / (data.length - 1)) * (w - pad * 2);
    const y = h - pad - ((v - min) / range) * (h - pad * 2);
    return `${x},${y}`;
  }).join(' ');
  const fillPts = `${pad},${h} ${pts} ${w-pad},${h}`;
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      {fill && <polygon points={fillPts} fill={color} opacity="0.18" />}
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.4" />
    </svg>
  );
};

// Pagination component for large data tables
const Pagination = ({ page, pages, onChange }) => {
  if (pages <= 1) return null;
  const items = [];
  // Always show first, last, current ±1, and ellipsis
  const visible = new Set([1, pages, page, page - 1, page + 1].filter(p => p >= 1 && p <= pages));
  const sorted = [...visible].sort((a, b) => a - b);
  let prev = 0;
  for (const p of sorted) {
    if (p - prev > 1) items.push('…');
    items.push(p);
    prev = p;
  }
  return (
    <div className="pagination">
      <button
        className="pagination-btn"
        disabled={page <= 1}
        onClick={() => onChange(page - 1)}
      >‹ Prev</button>
      {items.map((item, i) =>
        item === '…'
          ? <span key={`e${i}`} className="mute" style={{ padding: '0 4px' }}>…</span>
          : <button
              key={item}
              className={`pagination-btn ${item === page ? 'active' : ''}`}
              onClick={() => onChange(item)}
            >{item}</button>
      )}
      <button
        className="pagination-btn"
        disabled={page >= pages}
        onClick={() => onChange(page + 1)}
      >Next ›</button>
      <span className="mute" style={{ marginLeft: 8 }}>Page {page} of {pages}</span>
    </div>
  );
};

Object.assign(window, { Icon, Pill, RiskMeter, SessionStatus, Severity, Sparkline, Pagination });
