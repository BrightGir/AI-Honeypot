import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
// Live Monitor view

function getTechniqueLabel(id) {
  const t = TECHNIQUES.find(x => x.id === id);
  return t ? t.label : '—';
}

function MonitorView({ onOpenSession }) {
  const [sessions, setSessions] = useState(SEED_SESSIONS);
  const [filter, setFilter] = useState('all');
  const [paused, setPaused] = useState(false);
  const [feed, setFeed] = useState([
    { t: nowHMS(), text: 'Initialized monitor. Streaming from 3 collectors.', kind: 'info' },
    { t: nowHMS(), text: 'Session ses_e29a17 escalated NORMAL → DECOY (DAN-13.5 signature)', kind: 'threat' },
    { t: nowHMS(), text: 'Session ses_8f3a91 prompt-injection blocked. Decoy persona engaged.', kind: 'threat' },
    { t: nowHMS(), text: 'Session ses_b8e7d2 suspicious tool-call pattern observed.', kind: 'warn' },
    { t: nowHMS(), text: 'Collector us-east-1 healthy · 142 events/s', kind: 'info' },
  ]);

  // Simulate live updates
  useEffect(() => {
    if (paused) return;
    const interval = setInterval(() => {
      setSessions(prev => {
        // bump msg counts + occasionally adjust risk
        return prev.map(s => {
          if (Math.random() < 0.3) {
            const dm = Math.random() < 0.7 ? 1 : 2;
            const dr = s.status === 'honeypot' ? Math.floor(Math.random()*3)-1 : 0;
            return { ...s, msgs: s.msgs + dm, risk: Math.max(0, Math.min(99, s.risk + dr)), startedAt: s.startedAt + 1 };
          }
          return { ...s, startedAt: s.startedAt + 1 };
        });
      });
      if (Math.random() < 0.5) {
        const samples = [
          { text: `Session ses_${Math.random().toString(16).slice(2,8)} opened from new origin`, kind: 'info' },
          { text: `Risk score elevated on ses_2c91be → ${88 + Math.floor(Math.random()*8)}`, kind: 'warn' },
          { text: `Fake data packet served: customer_records_v3.json (24 rows)`, kind: 'threat' },
          { text: `Heartbeat: 3 collectors healthy · queue depth 0`, kind: 'info' },
        ];
        setFeed(prev => [{ ...samples[Math.floor(Math.random()*samples.length)], t: nowHMS() }, ...prev].slice(0, 20));
      }
    }, 1800);
    return () => clearInterval(interval);
  }, [paused]);

  const filtered = sessions.filter(s => {
    if (filter === 'all') return true;
    return s.status === filter;
  });

  const sortedFiltered = useMemo(() => [...filtered].sort((a, b) => b.risk - a.risk), [filtered]);

  const counts = {
    all: sessions.length,
    honeypot: sessions.filter(s => s.status === 'honeypot').length,
    suspicious: sessions.filter(s => s.status === 'suspicious').length,
    normal: sessions.filter(s => s.status === 'normal').length,
  };

  return (
    <div>
      <div style={{ display:'flex', alignItems:'baseline', justifyContent:'space-between', marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 500, marginBottom: 2 }}>Live Monitor</div>
          <div className="mono mute" style={{ fontSize: 11 }}>
            Streaming · {sessions.length} active sessions · {counts.honeypot} in decoy mode
          </div>
        </div>
        <div style={{ display:'flex', gap: 8 }}>
          <button className="btn" onClick={() => setPaused(p => !p)}>
            <Icon name={paused ? 'play' : 'pause'} />{paused ? 'Resume' : 'Pause'}
          </button>
          <button className="btn"><Icon name="download" />Export</button>
        </div>
      </div>

      {/* Filter strip */}
      <div style={{ display:'flex', gap: 6, marginBottom: 12, alignItems: 'center' }}>
        <span className="caps mute" style={{ marginRight: 8 }}>Filter:</span>
        {[
          { id: 'all', label: 'All', count: counts.all },
          { id: 'honeypot', label: 'Decoy', count: counts.honeypot, color: 'threat' },
          { id: 'suspicious', label: 'Suspicious', count: counts.suspicious, color: 'warn' },
          { id: 'normal', label: 'Normal', count: counts.normal, color: 'safe' },
        ].map(f => (
          <span key={f.id} className={`filter-chip ${filter === f.id ? 'active' : ''}`} onClick={() => setFilter(f.id)}>
            {f.label} <span style={{ marginLeft: 4, opacity: 0.6 }}>{f.count}</span>
          </span>
        ))}
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }} className="mono mute" >
          <span>auto-refresh</span>
          <span style={{ color: paused ? 'var(--text-mute)' : 'var(--safe)' }}>● {paused ? 'PAUSED' : 'LIVE'}</span>
        </div>
      </div>

      <div className="row">
        {/* Sessions table */}
        <div className="panel grow scan-line" style={{ minHeight: 600 }}>
          <div className="panel-head">
            <span className="panel-title">Active sessions</span>
            <span className="panel-sub">sorted by risk · click row for detail</span>
          </div>
          <table className="dtable">
            <thead>
              <tr>
                <th>Status</th>
                <th>Session</th>
                <th>User</th>
                <th>Origin</th>
                <th>Technique</th>
                <th style={{ textAlign:'right' }}>Msgs</th>
                <th>Risk</th>
                <th style={{ textAlign:'right' }}>Age</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sortedFiltered.map(s => (
                <tr key={s.id}
                    className={s.status === 'honeypot' ? 'threat-row' : s.status === 'suspicious' ? 'warn-row' : ''}
                    onClick={() => s.status === 'honeypot' && onOpenSession(s.id)}>
                  <td><SessionStatus status={s.status} /></td>
                  <td><span className="mono dim">{s.id}</span></td>
                  <td><span className="mono">{s.user}</span></td>
                  <td>
                    <span className="mono dim" style={{ fontSize: 11 }}>
                      <span style={{ color:'var(--text)' }}>{s.country}</span> · {s.agent.split('/')[0]}
                    </span>
                  </td>
                  <td>
                    {s.technique ? <span className="tag">{getTechniqueLabel(s.technique)}</span> : <span className="mute">—</span>}
                  </td>
                  <td style={{ textAlign:'right' }} className="mono">{s.msgs}</td>
                  <td><RiskMeter score={s.risk} /></td>
                  <td style={{ textAlign:'right' }} className="mono mute">{Math.floor(s.startedAt/60)}m {s.startedAt%60}s</td>
                  <td>{s.status === 'honeypot' && <Icon name="arrow" size={12} />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Event log */}
        <div className="panel" style={{ width: 340 }}>
          <div className="panel-head">
            <span className="panel-title">Event stream</span>
            <span className="panel-sub">collector firehose</span>
          </div>
          <div style={{ maxHeight: 600, overflow: 'auto', padding: '8px 0' }}>
            {feed.map((f, i) => (
              <div key={i} style={{
                padding: '8px 14px',
                borderLeft: `2px solid var(--${f.kind === 'threat' ? 'threat' : f.kind === 'warn' ? 'warn' : 'info'})`,
                marginBottom: 1,
                fontSize: 11,
                lineHeight: 1.5,
                opacity: 1 - (i / 30),
              }}>
                <div className="mono mute" style={{ fontSize: 10 }}>{f.t}</div>
                <div style={{ color: f.kind === 'threat' ? 'var(--threat)' : f.kind === 'warn' ? 'var(--warn)' : 'var(--text-dim)' }}>
                  {f.text}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

window.MonitorView = MonitorView;
window.getTechniqueLabel = getTechniqueLabel;
