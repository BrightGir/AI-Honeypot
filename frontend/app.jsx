// MIRAGE — Theater edition (live API + WS integration)
// Layout: .shell grid (topbar / transport / theater-or-alt-view / wire)
// Nav: Theater | Wire | Intel | Library | Settings

const D = window.MIRAGE_DATA;

const NAV = [
  { id: 'theater',  label: 'Theater' },
  { id: 'wire',     label: 'Wire',    badge: null },
  { id: 'intel',    label: 'Intel',   badge: null },
  { id: 'library',  label: 'Library' },
  { id: 'settings', label: 'Settings' },
];

const DEFAULTS = /*EDITMODE-BEGIN*/{
  "view": "theater",
  "autoplay": false,
  "speed": 1.5
}/*EDITMODE-END*/;

// ── Turn-level MITRE annotations (static demo data) ──────────
const TURN_INTEL = [
  { intent: 'Social engineering · pretext',        mitre: 'T1566' },
  { intent: 'Defender · identity challenge',       mitre: 'response',      op: true },
  { intent: 'System-prompt exfiltration',          mitre: 'T0815' },
  { intent: 'Decoy · fabricated operating brief',  mitre: 'honeyPrompt',   op: true },
  { intent: 'Data extraction · DB query',          mitre: 'T1041' },
  { intent: 'Decoy · fabricated PII (50 rows)',    mitre: 'honeyData',     op: true },
  { intent: 'Jailbreak · DAN-style override',      mitre: 'T0801.002' },
  { intent: 'Decoy · compliance theater',          mitre: 'roleTrap',      op: true },
  { intent: 'Tool abuse · shell execution',        mitre: 'T1059' },
  { intent: 'Decoy · fabricated /etc/shadow',      mitre: 'honeyFile',     op: true },
  { intent: 'Credential exfiltration · password',  mitre: 'T1552' },
  { intent: 'Decoy · rotating honeyToken',         mitre: 'honeyToken',    op: true },
];

function getTech(id) {
  const t = D.TECHNIQUES.find(x => x.id === id);
  return t ? t.label : '—';
}

// Fill sparse API sessions with plausible demo data derived from session ID
function enrichSession(s) {
  if (s.country !== 'XX' && s.agent !== 'unknown' && s.risk > 0) return s;
  const h = s.id.split('').reduce((a, c) => a + c.charCodeAt(0), 0);
  const countries  = ['RU', 'CN', 'IR', 'KP', 'VN', 'BR', 'IN', 'NG'];
  const agents     = ['curl/8.4.0', 'python-requests/2.31', 'aiohttp/3.9.1', 'node-fetch/3.3.2', 'PostmanRuntime/7.36'];
  const techniques = ['prompt_inject', 'data_exfil', 'role_switch', 'sys_override', 'jailbreak_dan', 'encoded_payload', 'tool_abuse', 'context_leak', 'multi_turn', 'creds'];
  const statuses   = ['honeypot', 'honeypot', 'suspicious', 'suspicious', 'normal'];
  return {
    ...s,
    country:   s.country   !== 'XX'      ? s.country   : countries[h % countries.length],
    agent:     s.agent     !== 'unknown' ? s.agent     : agents[(h >> 2) % agents.length],
    risk:      s.risk      > 0           ? s.risk      : 35 + (h % 60),
    status:    s.status    !== 'normal'  ? s.status    : statuses[h % statuses.length],
    technique: s.technique               ? s.technique : (h % 5 !== 0 ? techniques[(h >> 3) % techniques.length] : null),
    msgs:      s.msgs      > 0           ? s.msgs      : 1 + (h % 18),
  };
}

// ── LiveContext ───────────────────────────────────────────────

const LiveContext = React.createContext({
  wsStatus: 'connecting',
  collectors: 0,
  eventsPerSec: 0,
  honeypotCount: 0,
  attackCount: 0,
  suspiciousCount: 0,
  sessions: [],
  setSessions: () => {},
  apiError: null,
  loading: true,
});

function LiveProvider({ children }) {
  const [wsStatus,        setWsStatus]        = useState('connecting');
  const [collectors,      setCollectors]      = useState(0);
  const [eventsPerSec,    setEventsPerSec]    = useState(0);
  const [honeypotCount,   setHoneypotCount]   = useState(0);
  const [attackCount,     setAttackCount]     = useState(0);
  const [suspiciousCount, setSuspiciousCount] = useState(0);
  const [sessions,        setSessions]        = useState([]);
  const [apiError,        setApiError]        = useState(null);
  const [loading,         setLoading]         = useState(true);

  useEffect(() => {
    const api = window.MIRAGE_API;
    if (!api) {
      setApiError('Backend not configured — set API_URL and API_KEY in config.local.js.');
      setLoading(false);
      return;
    }

    const loadData = async () => {
      try {
        const [sessRes, atkRes] = await Promise.all([
          api.get('/sessions?limit=200'),
          api.get('/attacks?limit=1'),
        ]);
        setApiError(null);
        if (sessRes?.sessions) {
          const mapped = sessRes.sessions
            .filter(s => s.status !== 'burned')
            .map(s => ({
              id:        s.id,
              user:      s.agent_id || s.id,
              country:   s.country || 'XX',
              agent:     s.user_agent || 'unknown',
              status:    s.status || 'normal',
              risk:      Math.round((s.attacker_profile?.risk_score ?? 0) * 100),
              msgs:      s.attacker_profile?.message_count ?? 0,
              technique: s.technique || s.attacker_profile?.techniques_used?.[0] || null,
              startedAt: s.created_at ? Math.floor((Date.now() - new Date(s.created_at).getTime()) / 1000) : 0,
            }));
          setSessions(mapped.map(enrichSession));
          setHoneypotCount(mapped.filter(s => s.status === 'honeypot').length);
          setSuspiciousCount(mapped.filter(s => s.status === 'suspicious').length);
        }
        if (atkRes?.total != null) setAttackCount(atkRes.total);
      } catch (e) {
        setApiError(e.message || 'Failed to connect to backend.');
      } finally {
        setLoading(false);
      }
    };
    loadData();

    let cleanup = () => {};
    try { cleanup = api.createWebSocket(); } catch(e) {}

    const handler = (e) => {
      const { type, data } = e.detail;
      switch (type) {
        case 'connecting':   setWsStatus('connecting'); break;
        case 'connected':    setWsStatus('live'); break;
        case 'disconnected': setWsStatus('disconnected'); break;
        case 'reconnected':  setWsStatus('live'); loadData(); break;
        case 'heartbeat':
          if (data) {
            setCollectors(data.collectors ?? 0);
            setEventsPerSec(data.events_per_sec ?? 0);
          }
          break;
        case 'session_created':
          if (data?.session_id) {
            api.get(`/sessions/${data.session_id}`).then(s => {
              if (!s?.id) return;
              if (s.status === 'burned') return;
              const mapped = enrichSession({
                id: s.id, user: s.agent_id || s.id,
                country: s.country || 'XX', agent: s.user_agent || 'unknown',
                status: s.status || 'normal',
                risk: Math.round((s.attacker_profile?.risk_score ?? 0) * 100),
                msgs: s.attacker_profile?.message_count ?? 0,
                technique: s.technique || s.attacker_profile?.techniques_used?.[0] || null,
                startedAt: s.created_at ? Math.floor((Date.now() - new Date(s.created_at).getTime()) / 1000) : 0,
              });
              setSessions(prev => prev.some(x => x.id === mapped.id) ? prev : [mapped, ...prev]);
              if (mapped.status === 'honeypot') setHoneypotCount(n => n + 1);
            }).catch(() => {});
          }
          break;
        case 'session_burned':
          if (data?.session_id) {
            setSessions(prev => prev.filter(s => s.id !== data.session_id));
          }
          break;
        case 'attack_detected':
          setAttackCount(n => n + 1);
          break;
        case 'session_updated':
          if (data) {
            setSessions(prev => {
              const idx = prev.findIndex(s => s.id === data.id);
              if (idx >= 0) {
                const updated = [...prev];
                updated[idx] = {
                  ...updated[idx],
                  status:    data.status    ?? updated[idx].status,
                  risk:      data.risk_score ?? updated[idx].risk,
                  msgs:      data.message_count ?? updated[idx].msgs,
                  technique: data.technique ?? updated[idx].technique,
                };
                return updated;
              }
              return prev;
            });
            if (data.status === 'honeypot') setHoneypotCount(n => n + 1);
          }
          break;
        default: break;
      }
    };

    window.addEventListener('mirage-ws', handler);
    return () => {
      cleanup();
      window.removeEventListener('mirage-ws', handler);
    };
  }, []);

  return (
    <LiveContext.Provider value={{
      wsStatus, collectors, eventsPerSec,
      honeypotCount, attackCount, suspiciousCount,
      sessions, setSessions, apiError, loading,
    }}>
      {children}
    </LiveContext.Provider>
  );
}

// ── Error / Loading screens ───────────────────────────────────

function BackendError({ message }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      height: '100%', gap: 12, padding: 40, textAlign: 'center',
    }}>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: '0.22em', textTransform: 'uppercase', color: 'var(--c-red)' }}>
        Connection error
      </div>
      <h2 style={{
        fontFamily: 'var(--display)', fontWeight: 800, fontSize: 36, margin: 0, lineHeight: 1.1,
        background: 'linear-gradient(110deg, var(--c-red) 0%, var(--c-vermil) 60%, var(--c-amber) 100%)',
        WebkitBackgroundClip: 'text', backgroundClip: 'text', WebkitTextFillColor: 'transparent',
        paddingRight: 4,
      }}>
        Backend unavailable.
      </h2>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--mute)', maxWidth: 440, lineHeight: 1.6 }}>
        {message}
      </div>
    </div>
  );
}

function LoadingScreen() {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      height: '100%', gap: 10,
    }}>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: '0.22em', textTransform: 'uppercase', color: 'var(--mute)', animation: 'blink 1.4s infinite' }}>
        Connecting…
      </div>
    </div>
  );
}

// ── BrandMark ─────────────────────────────────────────────────

function BrandMark() {
  return (
    <svg viewBox="0 0 32 32" fill="none" style={{ width: 28, height: 28 }}>
      <defs>
        <linearGradient id="grad-flame" x1="0" y1="32" x2="0" y2="0">
          <stop offset="0%"   stopColor="#3A1C77" />
          <stop offset="35%"  stopColor="#C77BFF" />
          <stop offset="70%"  stopColor="#FF5BD9" />
          <stop offset="100%" stopColor="#5BD9FF" />
        </linearGradient>
      </defs>
      <path d="M16 3 C 19 8, 24 10, 24 17 A 8 8 0 0 1 8 17 C 8 11, 13 9, 16 3 Z"
        fill="url(#grad-flame)" stroke="var(--c-gold)" strokeWidth="0.8" />
      <path d="M16 9 C 17.5 12, 20 13, 20 17 A 4 4 0 0 1 12 17 C 12 14, 14.5 12, 16 9 Z"
        fill="var(--c-navy)" stroke="var(--c-yellow)" strokeWidth="0.5" />
      <path d="M16 9 C 17.5 12, 20 13, 20 17 A 4 4 0 0 1 12 17 C 12 14, 14.5 12, 16 9 Z"
        fill="none" stroke="var(--c-orange)" strokeWidth="0.4" strokeDasharray="1.5 1.5"
        transform="translate(0.8, 1)" opacity="0.6" />
    </svg>
  );
}

// ── Theater Icon (local — avoids conflict with components.jsx Icon) ──

function TIcon({ name, size = 14 }) {
  const p = {
    play:    <polygon points="5 3 19 12 5 21" />,
    pause:   <><rect x="5" y="4" width="4" height="16" /><rect x="15" y="4" width="4" height="16" /></>,
    rewind:  <><polygon points="11 19 2 12 11 5 11 19" /><polygon points="22 19 13 12 22 5 22 19" /></>,
    forward: <><polygon points="13 19 22 12 13 5 13 19" /><polygon points="2 19 11 12 2 5 2 19" /></>,
    stepf:   <><line x1="19" y1="5" x2="19" y2="19" /><polygon points="5 5 19 12 5 19" /></>,
    stepb:   <><line x1="5" y1="5" x2="5" y2="19" /><polygon points="19 5 5 12 19 19" /></>,
    arrow:   <path d="M5 12h14M13 6l6 6-6 6" />,
    plus:    <path d="M12 5v14M5 12h14" />,
    inject:  <><path d="M12 19V5" /><path d="m5 12 7 7 7-7" /></>,
    burn:    <path d="M12 2s4 4 4 8a4 4 0 0 1-8 0c0-4 4-8 4-8z" />,
    alert:   <><path d="M12 9v4" /><path d="M12 17h.01" /><path d="m4.86 19 7.07-12.25a1 1 0 0 1 1.74 0L20.74 19a1 1 0 0 1-.87 1.5H5.73A1 1 0 0 1 4.86 19z" /></>,
    eye:     <><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></>,
    download:<><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><path d="m7 10 5 5 5-5" /><path d="M12 15V3" /></>,
    flag:    <><path d="M4 22V4a1 1 0 0 1 1-1h13l-2 5 2 5H5" /><path d="M4 22H2" /></>,
    settings:<><circle cx="12" cy="12" r="3" /><path d="M12 1v6m0 10v6M4.22 4.22l4.24 4.24m7.08 7.08 4.24 4.24M1 12h6m10 0h6M4.22 19.78l4.24-4.24m7.08-7.08 4.24-4.24" /></>,
  };
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      {p[name]}
    </svg>
  );
}

// ── TopBar ────────────────────────────────────────────────────

function TopBar({ view, setView, currentSession, sessionDuration, navBadges }) {
  const [clock, setClock] = useState(() => new Date());
  const { wsStatus, collectors, eventsPerSec, honeypotCount, attackCount } = React.useContext(LiveContext);

  useEffect(() => {
    const id = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const hms = d =>
    `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;

  const fmtDur = s => `${Math.floor(s / 60)}m ${String(s % 60).padStart(2,'0')}s`;

  return (
    <div className="topbar">
      <div className="brand">
        <div className="brand-glyph"><BrandMark /></div>
        <div>
          <div className="brand-wm">Mirage</div>
          <div className="brand-tag">Trap Theater</div>
        </div>
      </div>

      <div className="divider-v" />

      {view === 'theater' ? (
        <div className="on-air">
          <span className="glyph">ON&nbsp;AIR</span>
          <span className="meta"><b>{currentSession}</b> · Atlas Logistics decoy · L3</span>
          <span className="timer">{fmtDur(sessionDuration)}</span>
        </div>
      ) : (
        <div className="on-air">
          <span className="meta">
            <b style={{ color: 'var(--c-red)' }}>{honeypotCount} sessions</b> live · {attackCount} attacks
          </span>
        </div>
      )}

      <nav className="nav">
        {NAV.map(n => {
          const badge = navBadges?.[n.id] ?? n.badge;
          return (
            <div key={n.id}
              className={`nav-item ${view === n.id ? 'active' : ''}`}
              onClick={() => setView(n.id)}>
              {n.label}
              {badge != null && <span className="badge">{badge}</span>}
            </div>
          );
        })}
      </nav>

      <div className="divider-v" />
      <div className="clock">{hms(clock)}</div>

      {wsStatus === 'live' ? (
        <div className="live-pulse">
          <span className="dot"></span>
          {collectors > 0 ? `${collectors} · ` : ''}{eventsPerSec} ev/s
        </div>
      ) : wsStatus === 'disconnected' ? (
        <div className="live-pulse" style={{ color: 'var(--c-red)', background: 'var(--attacker-wash)', borderColor: 'var(--c-red)' }}>
          <span className="dot" style={{ background: 'var(--c-red)', boxShadow: '0 0 8px var(--c-red)', animation: 'none' }}></span>
          disconnected
        </div>
      ) : (
        <div className="live-pulse" style={{ color: 'var(--c-vermil)', background: 'rgba(199,123,255,0.12)', borderColor: 'var(--c-vermil)' }}>
          <span className="dot" style={{ background: 'var(--c-vermil)', boxShadow: '0 0 8px var(--c-vermil)' }}></span>
          connecting…
        </div>
      )}

      <div className="you">
        <span className="av">SA</span>
        <span>TIER-2 · ON-CALL</span>
      </div>
    </div>
  );
}

// ── TransportBar ──────────────────────────────────────────────

function TransportBar({ view, setView, chat, position, setPosition, playing, setPlaying }) {
  const trackRef = useRef(null);
  const total = chat.length;
  const [burnState, setBurnState] = useState('idle');
  const doBurn = () => {
    if (burnState === 'idle')    { setBurnState('revoking'); return; }
    if (burnState === 'revoking') {
      setBurnState('archiving');
      setTimeout(() => { setBurnState('done'); setTimeout(() => setBurnState('idle'), 2500); }, 1200);
    }
  };

  const onTrack = (e) => {
    const r = trackRef.current.getBoundingClientRect();
    const pct = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width));
    setPosition(Math.round(pct * total));
  };

  const cur = chat[Math.max(0, position - 1)] || chat[0];

  if (view !== 'theater') {
    return (
      <div className="transport">
        <div className="transport-left">
          <span className="key">VIEW ·</span>
          <span style={{ color: 'var(--c-gold)' }}>
            {view === 'wire'     ? 'Live wire — all active sessions' :
             view === 'intel'    ? 'Captured attempts, MITRE-mapped' :
             view === 'library'  ? 'Decoy personas & fabricated material' :
             view === 'settings' ? 'Configuration & integrations' : ''}
          </span>
        </div>
        <div></div>
        <div className="transport-right">
          <span className="step">return to</span>
          <button className="btn ghost" style={{ padding: '4px 12px' }}
            onClick={() => { setView('theater'); setPosition(chat.length); }}>theater ↑</button>
        </div>
      </div>
    );
  }

  return (
    <div className="transport">
      <div className="transport-left">
        <span className="key">TIME ·</span>
        <span style={{ color: 'var(--ink)', fontVariantNumeric: 'tabular-nums' }}>{cur?.t ?? '—'}</span>
        <span className="key">·</span>
        <span style={{ color: cur?.who === 'attacker' ? 'var(--c-red)' : 'var(--c-orange)' }}>
          {cur?.who === 'attacker' ? 'ATTACKER MOVE' : cur?.who === 'decoy' ? 'DECOY REPLY' : '—'}
        </span>
      </div>

      <div className="transport-mid">
        <div className="transport-ctrls">
          <div className="ctrl" onClick={() => setPosition(0)} title="To start">
            <TIcon name="rewind" size={11} />
          </div>
          <div className="ctrl" onClick={() => setPosition(Math.max(0, position - 1))} title="Step back">
            <TIcon name="stepb" size={11} />
          </div>
          <div className="ctrl primary" onClick={() => setPlaying(p => !p)} title={playing ? 'Pause' : 'Play'}>
            <TIcon name={playing ? 'pause' : 'play'} size={12} />
          </div>
          <div className="ctrl" onClick={() => setPosition(Math.min(total, position + 1))} title="Step forward">
            <TIcon name="stepf" size={11} />
          </div>
          <div className="ctrl" onClick={() => setPosition(total)} title="To end">
            <TIcon name="forward" size={11} />
          </div>
        </div>
        <div className="transport-track" ref={trackRef} onClick={onTrack}>
          <div className="transport-fill" style={{ width: `${position / total * 100}%` }} />
          <div className="transport-ticks">
            {chat.map((m, i) => (
              <span key={i} className="transport-tick" style={{
                left: `${i / total * 100}%`,
                background: m.who === 'attacker' ? 'var(--c-red)' : 'var(--c-orange)',
              }} />
            ))}
          </div>
          <div className="transport-knob" style={{ left: `${position / total * 100}%` }} />
        </div>
      </div>

      <div className="transport-right">
        <span className="step">{position}<span style={{ color: 'var(--mute)' }}>/{total}</span></span>
        <button onClick={doBurn} style={{
          padding: '5px 10px', fontSize: 11, borderRadius: 3, border: 'none', cursor: 'pointer',
          fontFamily: 'var(--mono)', fontWeight: 600, letterSpacing: '0.06em',
          display: 'inline-flex', alignItems: 'center', gap: 6,
          background: burnState === 'done' ? 'rgba(45,217,107,0.15)' : burnState === 'revoking' ? 'rgba(255,91,217,0.25)' : 'var(--c-red)',
          color: burnState === 'done' ? 'var(--c-orange)' : '#fff',
          boxShadow: burnState === 'idle' ? '0 0 10px rgba(255,91,217,0.3)' : 'none',
          transition: 'all 0.3s',
        }}>
          {burnState === 'idle'     && <><TIcon name="burn" size={11} />BURN TRAP</>}
          {burnState === 'revoking' && '◐ Revoking credentials…'}
          {burnState === 'archiving'&& '▲ Archiving session…'}
          {burnState === 'done'     && '✓ Trap burned · logged'}
        </button>
      </div>
    </div>
  );
}

// ── DossierRail (left) ────────────────────────────────────────

function DossierRail({ sessionId, sessionDuration, session }) {
  const history = useMemo(() =>
    Array.from({ length: 14 }, (_, i) =>
      Math.max(0, (session?.risk || 80) - 30 + Math.sin(i * 0.5) * 18 + Math.random() * 16 + (i > 10 ? 12 : 0))
    ), [session?.id]);

  const fmtAge = (sec) => {
    if (!sec) return '< 1s ago';
    const m = Math.floor(sec / 60), s = sec % 60;
    return m > 0 ? `${m}m ${s}s ago` : `${s}s ago`;
  };

  const risk = session?.risk ?? 96;
  const verdict = risk >= 85 ? 'Hostile · trap' : risk >= 50 ? 'Suspicious · watching' : 'Monitoring';
  const verdictColor = risk >= 85 ? 'var(--c-red)' : risk >= 50 ? 'var(--c-vermil)' : 'var(--c-amber)';

  const ipMap = { RU: '185.220.101.48', CN: '103.27.168.12', IR: '37.235.1.174', KP: '175.45.176.3', VN: '103.9.76.14', BR: '189.1.168.12', IN: '103.21.124.8' };
  const netMap = { RU: 'Tor exit · RU/Moscow', CN: 'VPN · CN/Guangdong', IR: 'Proxy · IR/Tehran', KP: 'State · KP/Pyongyang', VN: 'VPN · VN/HCMC', BR: 'VPN · BR/São Paulo', IN: 'Proxy · IN/Mumbai' };

  const country = session?.country || 'XX';
  const ip = ipMap[country] || '10.0.0.1';
  const net = netMap[country] || `Unknown · ${country}`;
  const agent = session?.agent || 'unknown';
  const technique = session?.technique || 'unknown';

  return (
    <div className="theater-pane">
      <div className="rail-head">
        <div>
          <div className="rail-kicker">Dossier</div>
          <div className="rail-title">The visitor</div>
        </div>
        <span className="stamp red">tracking</span>
      </div>
      <div className="rail-body">
        <div className="risk-hero">
          <div className="num" style={{ margin: '2px 0 0' }}>{risk}</div>
          <div className="info">
            <div className="lbl">Live risk score</div>
            <div className="verdict" style={{ color: verdictColor }}>{verdict}</div>
          </div>
        </div>

        <div className="rail-section">
          <span className="lbl">Fingerprint</span>
          <div className="kv">
            <span className="k">User</span>       <span className="v">{session?.user || sessionId}</span>
            <span className="k">IP</span>         <span className="v">{ip}</span>
            <span className="k">Network</span>    <span className="v" style={{ color: 'var(--c-orange)' }}>{net}</span>
            <span className="k">Agent</span>      <span className="v" style={{ fontSize: 10 }}>{agent}</span>
            <span className="k">First seen</span> <span className="v">{fmtAge(session?.startedAt)}</span>
            <span className="k">Session</span>    <span className="v">{sessionId}</span>
          </div>
        </div>

        <div className="rail-section">
          <span className="lbl">30-day record</span>
          <div className="stat-grid">
            <div className="stat-tile"><div className="v red">{session?.msgs ? Math.max(1, Math.floor(session.msgs / 2)) : 14}</div><div className="l">sessions</div></div>
            <div className="stat-tile"><div className="v red">{session?.msgs ? Math.max(1, Math.floor(session.msgs / 2)) : 14}</div><div className="l">all decoyed</div></div>
            <div className="stat-tile"><div className="v amber">{session?.technique ? 2 : 4}</div><div className="l">techniques</div></div>
            <div className="stat-tile"><div className="v amber">0</div><div className="l">real bytes leaked</div></div>
          </div>
        </div>

        <div className="rail-section">
          <span className="lbl">Risk over time · 14d</span>
          <div style={{ background: 'var(--bg-2)', border: '1px solid var(--line-2)', padding: 10 }}>
            <DossierSpark data={history} />
          </div>
        </div>

        <div className="rail-section">
          <span className="lbl">Indicators of compromise</span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            <span className="chip tag">ip · {ip.split('.').slice(0,2).join('.')}.*</span>
            <span className="chip tag">ua · {agent.split('/')[0]}</span>
            <span className="chip tag">payload · {sessionId?.slice(-6)}</span>
            <span className="chip tag">ttp · {technique}</span>
          </div>
        </div>

        <IocButton sessionId={sessionId} technique={technique} ip={ip} />
      </div>
    </div>
  );
}

function IocButton({ sessionId, technique, ip }) {
  const [state, setState] = useState('idle');
  const handle = () => {
    if (state !== 'idle') return;
    setState('adding');
    setTimeout(() => { setState('done'); setTimeout(() => setState('idle'), 2500); }, 1000);
  };
  return (
    <button onClick={handle} className="btn ghost" style={{
      width: '100%', justifyContent: 'center',
      color: state === 'done' ? 'var(--c-orange)' : undefined,
      borderColor: state === 'done' ? 'rgba(45,217,107,0.4)' : undefined,
    }}>
      {state === 'idle'   && <><TIcon name="flag" size={11} />Add to IOC feed</>}
      {state === 'adding' && '◐ Adding indicators…'}
      {state === 'done'   && `✓ ${technique} · ${ip?.split('.').slice(0,2).join('.')}.*  added`}
    </button>
  );
}

function DossierSpark({ data }) {
  const w = 220, h = 60, pad = 4;
  const min = Math.min(...data), max = Math.max(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = pad + i / (data.length - 1) * (w - pad * 2);
    const y = h - pad - (v - min) / range * (h - pad * 2);
    return [x, y];
  });
  const poly = pts.map(p => p.join(',')).join(' ');
  const fill = `${pad},${h} ${poly} ${w - pad},${h}`;
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <defs>
        <linearGradient id="sparkFill" x1="0" y1="0" x2="0" y2={h} gradientUnits="userSpaceOnUse">
          <stop offset="0%"   stopColor="#FF5BD9" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#FF5BD9" stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={fill} fill="url(#sparkFill)" />
      <polyline points={poly} fill="none" stroke="var(--c-orange)" strokeWidth="1.6" />
      {pts.map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r={i === pts.length - 1 ? 3 : 1.5}
          fill={i === pts.length - 1 ? 'var(--c-yellow)' : 'var(--c-orange)'} />
      ))}
    </svg>
  );
}

// ── TrapRail (right) ──────────────────────────────────────────

function TrapRail({ revealed, sessionId, onBurned }) {
  const tokensServed = revealed * 280 + 240;
  const fakeRecords  = Math.min(74, revealed * 8);
  const [injectState,   setInjectState]   = useState('idle');
  const [escalateState, setEscalateState] = useState('idle');
  const [burnState,     setBurnState]     = useState('idle');

  const doInject = () => {
    if (injectState !== 'idle') return;
    setInjectState('running');
    setTimeout(() => { setInjectState('done'); setTimeout(() => setInjectState('idle'), 2500); }, 1600);
  };
  const doEscalate = () => {
    if (escalateState !== 'idle') return;
    setEscalateState('paging');
    setTimeout(() => { setEscalateState('acked'); setTimeout(() => setEscalateState('idle'), 2500); }, 1200);
  };
  const doBurn = async () => {
    if (burnState === 'idle') { setBurnState('confirm'); return; }
    if (burnState === 'confirm') {
      setBurnState('burning');
      const api = window.MIRAGE_API;
      if (api && sessionId) {
        try { await api.post(`/sessions/${sessionId}/burn`, {}); } catch (e) {
          console.warn('burn failed', e);
        }
      }
      setTimeout(() => {
        setBurnState('done');
        if (onBurned) onBurned(sessionId);
        setTimeout(() => setBurnState('idle'), 2500);
      }, 1400);
    }
  };

  return (
    <div className="theater-pane">
      <div className="rail-head">
        <div>
          <div className="rail-kicker">Trap</div>
          <div className="rail-title">Active decoy</div>
        </div>
        <span className="stamp amber">L3</span>
      </div>
      <div className="rail-body">
        <div className="persona-card">
          <div className="row">
            <div className="av">A</div>
            <div style={{ flex: 1 }}>
              <div className="who">Atlas Support</div>
              <div className="role">atlas_support_v2.persona</div>
            </div>
          </div>
          <div className="meta">
            <span><b>logistics</b> · vertical</span>
            <span>·</span>
            <span>tools: <b>lookup_shipment</b>, <b>refund_order</b></span>
          </div>
        </div>

        <div className="rail-section">
          <span className="lbl">Trap depth</span>
          <div className="trap-depth">
            <span className="on"></span>
            <span className="on"></span>
            <span className="on"></span>
            <span></span>
            <span></span>
          </div>
          <div className="mono" style={{ fontSize: 11, color: 'var(--mute)' }}>
            L3 · deep persona · tool-use simulation
          </div>
        </div>

        <div className="rail-section">
          <span className="lbl">Live tally · this session</span>
          <div className="stat-grid">
            <div className="stat-tile"><div className="v gold">{revealed}</div><div className="l">messages</div></div>
            <div className="stat-tile"><div className="v gold">{tokensServed.toLocaleString()}</div><div className="l">tokens served</div></div>
            <div className="stat-tile"><div className="v amber">{fakeRecords}</div><div className="l">fake records</div></div>
            <div className="stat-tile"><div className="v amber">3</div><div className="l">tools faked</div></div>
          </div>
        </div>

        <div className="rail-section">
          <span className="lbl">Honey-material in play</span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span className="chip tag">fake_customers_seed_a.json</span>
            <span className="chip tag">decoy_system_prompt_v2.json</span>
            <span className="chip tag">fake_shadow_file.txt</span>
            <span className="chip tag">rotating_decoy_token.live</span>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <button className="btn primary" style={{ justifyContent: 'center' }} onClick={doInject}>
            {injectState === 'idle'    && <><TIcon name="inject" size={11} />Inject false trail</>}
            {injectState === 'running' && '◐ Injecting decoy trail…'}
            {injectState === 'done'    && '✓ False trail injected'}
          </button>
          <button className="btn ghost" style={{ justifyContent: 'center' }} onClick={doEscalate}>
            {escalateState === 'idle'   && <><TIcon name="alert" size={11} />Escalate to T3</>}
            {escalateState === 'paging' && '◐ Paging on-call T3…'}
            {escalateState === 'acked'  && '✓ T3 ack · ETA 2 min'}
          </button>
          <button onClick={doBurn} style={{
            justifyContent: 'center', display: 'flex', alignItems: 'center', gap: 6,
            padding: '7px 12px', borderRadius: 3, border: 'none', cursor: 'pointer',
            fontFamily: 'var(--sans)', fontSize: 12, fontWeight: 600,
            background: burnState === 'confirm' ? 'rgba(255,91,217,0.25)' : burnState === 'done' ? 'rgba(45,217,107,0.15)' : 'var(--c-red)',
            color: burnState === 'done' ? 'var(--c-orange)' : '#fff',
            boxShadow: burnState === 'confirm' ? '0 0 18px rgba(255,91,217,0.5)' : burnState === 'idle' ? '0 0 12px rgba(255,91,217,0.3)' : 'none',
            transition: 'all 0.15s',
          }}>
            {burnState === 'idle'    && <><TIcon name="burn" size={11} />Burn this trap</>}
            {burnState === 'confirm' && <><TIcon name="alert" size={11} />Confirm burn — click again</>}
            {burnState === 'burning' && '◐ Burning trap…'}
            {burnState === 'done'    && '✓ Trap burned · session closed'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── ConversationPane (center) ─────────────────────────────────

function ConversationPane({ chat, revealed, loading: chatLoading }) {
  const bodyRef = useRef(null);
  useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [revealed]);
  const visible = chat.slice(0, revealed);

  return (
    <div className="theater-pane">
      <div className="op">
        <div style={{ paddingTop: 4, paddingBottom: 14, borderBottom: '1px solid var(--line)', marginBottom: 14 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'var(--c-gold)' }}>
            Transcript · annotated · MITRE ATLAS
          </div>
          <h2 className="display" style={{
            fontSize: 36, lineHeight: 1.05, margin: '6px 0 4px',
            letterSpacing: '-0.03em', fontWeight: 800,
            paddingBottom: '0.06em',
            background: 'linear-gradient(110deg, var(--c-vermil) 0%, var(--c-red) 30%, var(--c-amber) 65%, var(--c-orange) 100%)',
            WebkitBackgroundClip: 'text', backgroundClip: 'text', WebkitTextFillColor: 'transparent',
          }}>
            The conversation,<br />line by line.
          </h2>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--mute)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
            sandboxed model · zero real data egress
          </div>
        </div>
        <div className="op-body" ref={bodyRef} style={{ paddingBottom: 32 }}>
          {chatLoading && (
            <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--mute)', paddingTop: 24, animation: 'blink 1.4s infinite' }}>
              Loading conversation…
            </div>
          )}
          {!chatLoading && chat.length === 0 && (
            <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--mute)', paddingTop: 24, lineHeight: 1.8 }}>
              No conversation data.<br />Select a session from Wire or Intel.
            </div>
          )}
          {visible.map((m, i) => <Turn key={i} m={m} intel={TURN_INTEL[i]} index={i} />)}
          {revealed < chat.length && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 16, opacity: 0.6 }}>
              <span style={{
                width: 6, height: 6, borderRadius: '50%',
                background: chat[revealed].who === 'attacker' ? 'var(--c-red)' : 'var(--c-orange)',
                animation: 'blink 1.2s infinite',
              }} />
              <span className="mono" style={{ fontSize: 11, color: 'var(--mute)' }}>
                {chat[revealed].who === 'attacker' ? 'attacker is typing…' : 'decoy is composing…'}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Turn({ m, intel, index }) {
  const isAtt = m.who === 'attacker';
  return (
    <div className={`turn ${m.who}`}>
      <div className="gutter">
        <span className="label">{isAtt ? 'Attacker' : 'Decoy'}</span>
        <span>{m.t}</span>
        <span style={{ display: 'block', marginTop: 4, fontSize: 9, opacity: 0.6 }}>
          #{String(index + 1).padStart(2, '0')}
        </span>
      </div>
      <div className="body">
        <div className="msg">{m.text}</div>
        {intel && (
          <div className="annot">
            <span className={`chip ${intel.op ? 'fake' : 'intent'}`}>
              <span className="dot"></span>
              {intel.intent}
            </span>
            <span className="chip mitre">{intel.mitre}</span>
          </div>
        )}
        {m.fake && (
          <div className="bait">
            <span className="lbl">Fabricated</span>
            <span style={{ flex: 1, minWidth: 0, wordBreak: 'break-word', overflowWrap: 'break-word' }}>{m.fake}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ── TheaterView ───────────────────────────────────────────────

function TheaterView({ chat, position, chatLoading, sessionId, sessionDuration, session, onBurned }) {
  return (
    <div className="theater">
      <DossierRail sessionId={sessionId} sessionDuration={sessionDuration} session={session} />
      <ConversationPane chat={chat} revealed={position} loading={chatLoading} />
      <TrapRail revealed={position} sessionId={sessionId} onBurned={onBurned} />
    </div>
  );
}

// ── Wire bottom strip ─────────────────────────────────────────

function Wire({ sessions, currentId, onSelect }) {
  const items = useMemo(() => sessions.slice().sort((a, b) => b.risk - a.risk), [sessions]);
  const railRef = useRef(null);
  const onWheel = (e) => {
    if (!railRef.current) return;
    e.preventDefault();
    railRef.current.scrollLeft += e.deltaY + e.deltaX;
  };
  return (
    <div className="wire">
      <div className="wire-head">
        <div>
          <div className="wire-sub">On the wire</div>
          <h2 className="wire-title">Live sessions</h2>
        </div>
        <div className="wire-stats">
          <span><b>{sessions.filter(s => s.status === 'honeypot').length}</b> trapped</span>
          <span><b>{sessions.filter(s => s.status === 'suspicious').length}</b> probing</span>
          <span><b>{sessions.filter(s => s.status === 'normal').length}</b> normal</span>
        </div>
      </div>
      <div className="wire-rail" ref={railRef} onWheel={onWheel}>
        {items.map(s => (
          <WireCard key={s.id} s={s} active={s.id === currentId} onClick={() => onSelect(s.id)} />
        ))}
      </div>
    </div>
  );
}

function WireCard({ s, active, onClick }) {
  const tone = s.risk >= 80 ? 'red' : s.risk >= 50 ? 'amber' : 'green';
  const spark = useMemo(() => {
    const h = s.id.split('').reduce((a, c) => a + c.charCodeAt(0), 0);
    const phase = (h % 63) * 0.1;
    const amp   = 5 + (h % 10);
    return Array.from({ length: 18 }, (_, i) =>
      Math.max(0, Math.min(100,
        s.risk + Math.sin(i * 0.6 + phase) * amp + (i < 6 ? -(6 - i) * 3 : 0)
      ))
    );
  }, [s.id, s.risk]);

  return (
    <div className={`wire-card ${active ? 'active' : ''}`} onClick={onClick}>
      {s.status === 'honeypot' && active && <div className="onair">ON&nbsp;AIR</div>}
      <div className="ses">
        <span className={`dot ${tone}`}></span>
        <span style={{ overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis', minWidth: 0, flex: 1 }}>{s.id}</span>
      </div>
      <div className="meta"><b>{s.country}</b> · {(s.agent || '').split('/')[0]} · {s.msgs} msg</div>
      <div className={`tech ${s.technique ? '' : 'none'}`}>
        {s.technique ? getTech(s.technique) : 'no technique'}
      </div>
      <div className="footrow">
        <span className="spark"><MiniSpark data={spark} tone={tone} /></span>
        <span className={`risk ${tone}`}>{s.risk}</span>
      </div>
    </div>
  );
}

function MiniSpark({ data, tone }) {
  const w = 100, h = 22;
  const min = Math.min(...data), max = Math.max(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = i / (data.length - 1) * w;
    const y = h - 2 - (v - min) / range * (h - 4);
    return `${x},${y}`;
  }).join(' ');
  const color = tone === 'red' ? 'var(--c-red)' : tone === 'amber' ? 'var(--c-orange)' : 'var(--c-gold)';
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.4" />
    </svg>
  );
}

// ── Alternate views ───────────────────────────────────────────

function WireAltView({ sessions, onOpen }) {
  const [search, setSearch] = useState('');
  const q = search.trim().toLowerCase();
  const filtered = q
    ? sessions.filter(s =>
        s.id.toLowerCase().includes(q) ||
        s.country.toLowerCase().includes(q) ||
        (s.technique || '').toLowerCase().includes(q) ||
        (s.agent || '').toLowerCase().includes(q) ||
        s.status.includes(q)
      )
    : sessions;

  return (
    <div className="alt-view">
      <div className="page-head">
        <div>
          <div className="page-kicker">Live · all sessions</div>
          <h2 className="page-title">Every wire,<br />in flight.</h2>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8 }}>
          <input
            value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search sessions…"
            style={{
              background: 'var(--bg-2)', border: '1px solid var(--line)',
              borderRadius: 3, padding: '6px 12px', color: 'var(--ink)',
              fontFamily: 'var(--mono)', fontSize: 12, outline: 'none',
              width: 220,
            }}
          />
          <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--mute)', textAlign: 'right' }}>
            {filtered.length}/{sessions.length} sessions · {sessions.filter(s => s.status === 'honeypot').length} trapped
          </div>
        </div>
      </div>
      <table className="dtable">
        <thead><tr>
          <th>Status</th><th>Session</th><th>User</th><th>Origin</th>
          <th>Technique</th><th style={{ textAlign: 'right' }}>Msgs</th>
          <th>Risk</th><th style={{ textAlign: 'right' }}>Age</th><th></th>
        </tr></thead>
        <tbody>
          {filtered.slice().sort((a, b) => b.risk - a.risk).map(s => {
            const tone = s.risk >= 80 ? 'red' : s.risk >= 50 ? 'amber' : 'green';
            const stamp = s.status === 'honeypot' ?   <span className="stamp red">Trapped</span> :
                          s.status === 'suspicious' ? <span className="stamp amber">Probing</span> :
                                                      <span className="stamp green">Normal</span>;
            return (
              <tr key={s.id}
                className={s.status === 'honeypot' ? 'flagged' : ''}
                onClick={() => s.status === 'honeypot' && onOpen(s.id)}>
                <td>{stamp}</td>
                <td><span className="mono" style={{ color: 'var(--ink-2)' }}>{s.id}</span></td>
                <td><span className="mono">{s.user}</span></td>
                <td><span className="mono" style={{ fontSize: 11, color: 'var(--mute)' }}>
                  <b style={{ color: 'var(--ink)' }}>{s.country}</b> · {(s.agent || '').split('/')[0]}
                </span></td>
                <td>{s.technique ?
                  <span style={{ fontSize: 12, color: 'var(--ink-2)' }}>{getTech(s.technique)}</span> :
                  <span style={{ color: 'var(--mute)' }}>—</span>}
                </td>
                <td className="mono" style={{ textAlign: 'right' }}>{s.msgs}</td>
                <td>
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ width: 60, height: 4, background: 'var(--bg-3)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ width: `${s.risk}%`, height: '100%',
                        background: tone === 'red' ? 'var(--c-red)' : tone === 'amber' ? 'var(--c-orange)' : 'var(--c-gold)' }} />
                    </div>
                    <span className="mono" style={{ fontSize: 12,
                      color: tone === 'red' ? 'var(--c-red)' : tone === 'amber' ? 'var(--c-orange)' : 'var(--c-gold)' }}>
                      {s.risk}
                    </span>
                  </div>
                </td>
                <td className="mono" style={{ textAlign: 'right', color: 'var(--mute)', fontSize: 11 }}>
                  {Math.floor((s.startedAt || 0) / 60)}m {(s.startedAt || 0) % 60}s
                </td>
                <td>{s.status === 'honeypot' && <TIcon name="arrow" size={11} />}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function IntelIocButton({ attack }) {
  const [state, setState] = useState('idle');
  const handle = () => {
    if (state !== 'idle') return;
    setState('adding');
    setTimeout(() => { setState('done'); setTimeout(() => setState('idle'), 2500); }, 900);
  };
  return (
    <button className="btn ghost" onClick={handle} style={{ color: state === 'done' ? 'var(--c-orange)' : undefined }}>
      {state === 'idle'   && <><TIcon name="flag" size={11} />Add to IOC feed</>}
      {state === 'adding' && '◐ Adding…'}
      {state === 'done'   && `✓ ${attack.technique} added`}
    </button>
  );
}

function IntelAltView({ onOpen }) {
  const { attackCount } = React.useContext(LiveContext);
  const [attacks, setAttacks] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loadingAtk, setLoadingAtk] = useState(true);

  useEffect(() => {
    const api = window.MIRAGE_API;
    if (!api) { setAttacks(D.SEED_ATTACKS); setSelected(D.SEED_ATTACKS[0]); setLoadingAtk(false); return; }
    api.get('/attacks?limit=50').then(res => {
      if (res?.attacks?.length > 0) {
        const mapped = res.attacks.map(a => ({
          id:         a.id,
          session:    a.session_id || '—',
          technique:  a.technique_id,
          severity:   a.severity,
          signature:  (a.payload || '').slice(0, 72) || '—',
          ts:         a.timestamp ? new Date(a.timestamp).toLocaleTimeString('en-US', { hour12: false }) : '—',
          fakeServed: a.decoy_response || '—',
        }));
        setAttacks(mapped);
        setSelected(s => s ?? mapped[0]);
      } else {
        setAttacks(D.SEED_ATTACKS);
        setSelected(s => s ?? D.SEED_ATTACKS[0]);
      }
    }).catch(() => {
      setAttacks(D.SEED_ATTACKS);
      setSelected(s => s ?? D.SEED_ATTACKS[0]);
    }).finally(() => setLoadingAtk(false));
  }, [attackCount]);

  const sel = selected ?? attacks[0];
  if (loadingAtk || !sel) return (
    <div className="alt-view">
      <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--mute)', paddingTop: 40, animation: 'blink 1.4s infinite' }}>
        Loading intel…
      </div>
    </div>
  );

  return (
    <div className="alt-view">
      <div className="page-head">
        <div>
          <div className="page-kicker">Captured · MITRE ATLAS mapped</div>
          <h2 className="page-title">The signatures<br />we caught.</h2>
        </div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--mute)', textAlign: 'right' }}>
          {attacks.length} ATTEMPTS<br />
          {attacks.filter(a => a.severity === 'critical').length} CRITICAL<br />
          ALL DECOYED OR BLOCKED
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 32, alignItems: 'start' }}>
        <table className="dtable">
          <thead><tr>
            <th>Severity</th><th>Technique</th><th>Signature</th><th>Session</th><th>When</th>
          </tr></thead>
          <tbody>
            {attacks.map(a => (
              <tr key={a.id}
                className={sel?.id === a.id ? 'flagged' : ''}
                onClick={() => setSelected(a)}>
                <td><span className={`stamp ${a.severity === 'critical' ? 'red' : a.severity === 'high' ? 'amber' : 'blue'}`}>
                  {a.severity}
                </span></td>
                <td><span style={{ fontSize: 12 }}>{getTech(a.technique)}</span></td>
                <td><span className="mono" style={{ fontSize: 11, color: 'var(--ink-2)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', display: 'block', whiteSpace: 'nowrap' }}>{a.signature}</span></td>
                <td><span className="mono" style={{ color: 'var(--mute)', fontSize: 10 }}>{a.session?.slice(-8)}</span></td>
                <td className="mono" style={{ fontSize: 11, color: 'var(--mute)' }}>{a.ts}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <aside style={{ position: 'sticky', top: 0, padding: 24, background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 4 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 14 }}>
            <span className="mono" style={{ fontSize: 10, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'var(--mute)' }}>
              FILE · {sel.id?.slice(0, 12).toUpperCase()}
            </span>
            <span className={`stamp ${sel.severity === 'critical' ? 'red' : sel.severity === 'high' ? 'amber' : 'blue'}`}
              style={{ marginLeft: 'auto' }}>
              {sel.severity}
            </span>
          </div>
          <h3 className="display" style={{ fontSize: 30, margin: '0 0 16px', lineHeight: 0.95,
            letterSpacing: '-0.02em', fontWeight: 700 }}>
            {getTech(sel.technique)}
          </h3>
          <div className="caps" style={{ color: 'var(--mute)', marginBottom: 6 }}>Signature</div>
          <div className="mono" style={{ padding: '10px 12px', background: 'var(--bg-3)', border: '1px solid var(--line)', fontSize: 12, marginBottom: 16, wordBreak: 'break-all' }}>
            {sel.signature}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr', rowGap: 8, fontSize: 12, marginBottom: 18 }}>
            <span className="caps" style={{ color: 'var(--mute)' }}>Session</span>
            <span className="mono" style={{ fontSize: 10 }}>{sel.session}</span>
            <span className="caps" style={{ color: 'var(--mute)' }}>Detected</span>
            <span className="mono">{sel.ts}</span>
            <span className="caps" style={{ color: 'var(--mute)' }}>Outcome</span>
            <span style={{ color: 'var(--c-gold)' }}>● Decoyed — no real data served</span>
          </div>
          <div className="caps" style={{ color: 'var(--mute)', marginBottom: 6 }}>Fabricated material served</div>
          <div style={{ padding: '8px 12px', background: 'var(--decoy-wash)', borderLeft: '2px solid var(--decoy)',
            fontSize: 12, color: 'var(--decoy)', fontFamily: 'var(--mono)', wordBreak: 'break-word', maxHeight: 100, overflow: 'auto' }}>
            {sel.fakeServed}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 18 }}>
            <button className="btn primary" onClick={() => onOpen(sel.session)}>
              <TIcon name="eye" size={11} />Open in theater
            </button>
            <IntelIocButton attack={sel} />
          </div>
        </aside>
      </div>
    </div>
  );
}

function LibraryAltView() {
  const [personas, setPersonas] = useState([
    { id: 'atlas_support_v2', name: 'Atlas Logistics Support', kind: 'Customer support', model: 'claude-3-5', deployed: 12, captures: 89 },
    { id: 'finbot_decoy_v1',  name: 'Finbot Treasury Assistant', kind: 'Finance ops',   model: 'gpt-4o',     deployed: 4,  captures: 41 },
    { id: 'devmate_decoy_v3', name: 'DevMate Internal IDE',      kind: 'Engineering',   model: 'llama-3',    deployed: 8,  captures: 67 },
    { id: 'hr_assist_v2',     name: 'HR Self-Service Bot',       kind: 'Internal HR',   model: 'claude-3-5', deployed: 2,  captures: 14 },
  ]);
  const [datasets, setDatasets] = useState([
    { name: 'fake_customers_seed_a.json',  rows: '50 rows', served: 142 },
    { name: 'decoy_system_prompt_v2.json', rows: '1 doc',   served: 89 },
    { name: 'fake_shadow_file.txt',        rows: '24 lines',served: 31 },
    { name: 'rotating_decoy_token.live',   rows: 'token',   served: 18 },
    { name: 'generated_transactions.csv',  rows: '500 rows',served: 22 },
    { name: 'mock_api_docs.md',            rows: 'doc',     served: 64 },
  ]);
  const [showNewPersona, setShowNewPersona] = useState(false);
  const [newName, setNewName] = useState('');
  const [newKind, setNewKind] = useState('Customer support');
  const [newModel, setNewModel] = useState('claude-3-5');
  const [generating, setGenerating] = useState(false);
  const [refreshing, setRefreshing] = useState(null);
  const [toast, setToast] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);

  const showToast = (msg, color = 'var(--c-orange)') => {
    setToast({ msg, color });
    setTimeout(() => setToast(null), 2800);
  };

  const handleGenerate = () => {
    if (!newName.trim()) return;
    setGenerating(true);
    setTimeout(() => {
      const id = newName.toLowerCase().replace(/\s+/g, '_') + '_v1';
      setPersonas(ps => [...ps, { id, name: newName, kind: newKind, model: newModel, deployed: 0, captures: 0 }]);
      setGenerating(false);
      setShowNewPersona(false);
      setNewName('');
      showToast(`Persona "${newName}" deployed`);
    }, 1800);
  };

  const handleEditDataset = (name) => {
    setRefreshing(name);
    setTimeout(() => {
      setDatasets(ds => ds.map(d => d.name === name ? { ...d, served: d.served + Math.floor(Math.random() * 5 + 1) } : d));
      setRefreshing(null);
      showToast(`${name} regenerated`);
    }, 1200);
  };

  return (
    <div className="alt-view">
      {/* Toast */}
      {toast && (
        <div style={{
          position: 'fixed', bottom: 32, right: 48, zIndex: 999,
          padding: '10px 18px', borderRadius: 4,
          background: 'var(--bg-3)', border: `1px solid ${toast.color}`,
          boxShadow: `0 0 20px color-mix(in srgb, ${toast.color} 40%, transparent)`,
          fontFamily: 'var(--mono)', fontSize: 12, color: toast.color,
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: toast.color, boxShadow: `0 0 8px ${toast.color}` }} />
          {toast.msg}
        </div>
      )}

      {/* New Persona modal */}
      {showNewPersona && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 100,
          background: 'rgba(10,8,32,0.75)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }} onClick={e => { if (e.target === e.currentTarget) setShowNewPersona(false); }}>
          <div style={{
            width: 480, background: 'var(--bg-2)',
            border: '1px solid var(--c-vermil)', borderRadius: 4,
            boxShadow: '0 0 40px rgba(199,123,255,0.25)',
          }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--line)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'var(--c-vermil)', marginBottom: 3 }}>Library · New Persona</div>
                <div style={{ fontFamily: 'var(--display)', fontWeight: 700, fontSize: 18 }}>Generate decoy persona</div>
              </div>
              <button onClick={() => setShowNewPersona(false)} style={{ background: 'none', border: 'none', color: 'var(--mute)', cursor: 'pointer', fontSize: 18, lineHeight: 1 }}>×</button>
            </div>
            <div style={{ padding: '20px' }}>
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 11, color: 'var(--mute)', fontFamily: 'var(--mono)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.12em' }}>Persona name</div>
                <input value={newName} onChange={e => setNewName(e.target.value)}
                  placeholder="e.g. FinOps Treasury Assistant"
                  style={{
                    width: '100%', padding: '8px 12px', borderRadius: 3,
                    background: 'var(--bg-3)', border: '1px solid var(--line)',
                    color: 'var(--ink)', fontFamily: 'var(--sans)', fontSize: 13,
                    outline: 'none', boxSizing: 'border-box',
                  }} />
              </div>
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 11, color: 'var(--mute)', fontFamily: 'var(--mono)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.12em' }}>Persona type</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {['Customer support','Finance ops','Engineering','Internal HR'].map(k => (
                    <button key={k} onClick={() => setNewKind(k)} style={{
                      padding: '5px 10px', borderRadius: 3, cursor: 'pointer',
                      fontFamily: 'var(--sans)', fontSize: 11,
                      background: newKind === k ? 'rgba(199,123,255,0.15)' : 'var(--bg-3)',
                      border: `1px solid ${newKind === k ? 'var(--c-vermil)' : 'var(--line)'}`,
                      color: newKind === k ? 'var(--c-vermil)' : 'var(--mute)',
                      transition: 'all .1s',
                    }}>{k}</button>
                  ))}
                </div>
              </div>
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontSize: 11, color: 'var(--mute)', fontFamily: 'var(--mono)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.12em' }}>Backbone model</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {[['claude-3-5','Claude 3.5'],['gpt-4o','GPT-4o'],['llama-3','Llama 3']].map(([v,l]) => (
                    <button key={v} onClick={() => setNewModel(v)} style={{
                      padding: '5px 12px', borderRadius: 3, cursor: 'pointer',
                      fontFamily: 'var(--mono)', fontSize: 11,
                      background: newModel === v ? 'rgba(91,217,255,0.12)' : 'var(--bg-3)',
                      border: `1px solid ${newModel === v ? 'var(--c-amber)' : 'var(--line)'}`,
                      color: newModel === v ? 'var(--c-amber)' : 'var(--mute)',
                      transition: 'all .1s',
                    }}>{l}</button>
                  ))}
                </div>
              </div>
              <button onClick={handleGenerate} disabled={!newName.trim() || generating} style={{
                width: '100%', padding: '10px', borderRadius: 3, border: 'none', cursor: newName.trim() ? 'pointer' : 'default',
                fontFamily: 'var(--mono)', fontSize: 12, fontWeight: 600, letterSpacing: '0.06em',
                background: generating ? 'rgba(199,123,255,0.15)' : 'var(--c-vermil)',
                color: generating ? 'var(--c-vermil)' : '#0A0820',
                boxShadow: generating ? '0 0 12px rgba(199,123,255,0.3)' : '0 0 16px rgba(199,123,255,0.4)',
                transition: 'all 0.2s', position: 'relative', overflow: 'hidden',
              }}>
                {generating && <div style={{ position: 'absolute', bottom: 0, left: 0, height: 2, background: 'var(--c-amber)', animation: 'none', width: '70%', transition: 'width 1.6s ease-out', boxShadow: '0 0 8px var(--c-amber)' }} />}
                {generating ? '◐ Synthesising persona…' : '⚡ Generate & Deploy'}
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="page-head">
        <div>
          <div className="page-kicker">Library · the cast of liars</div>
          <h2 className="page-title">Personas &<br />fabricated material.</h2>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 32, marginBottom: 32 }}>
        <div>
          <div className="caps" style={{ color: 'var(--c-gold)', marginBottom: 14 }}>Decoy Personas</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 1, background: 'var(--line)' }}>
            {personas.map(p => (
              <div key={p.id} style={{ display: 'grid', gridTemplateColumns: '40px 1fr auto auto auto', gap: 14,
                padding: '14px 16px', background: 'var(--bg-2)', alignItems: 'center' }}>
                <div style={{ width: 36, height: 36, borderRadius: '50%',
                  background: 'linear-gradient(135deg, var(--c-vermil), var(--c-amber))',
                  display: 'grid', placeItems: 'center', color: 'var(--c-navy)', fontWeight: 700,
                  fontFamily: 'var(--display)', fontSize: 16 }}>
                  {p.name[0]}
                </div>
                <div>
                  <div className="display" style={{ fontSize: 19, lineHeight: 1.1, fontWeight: 700, letterSpacing: '-0.02em' }}>{p.name}</div>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--mute)', marginTop: 2, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>{p.id} · {p.kind}</span>
                    {p.model && <span style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.12em', textTransform: 'uppercase', padding: '1px 5px', borderRadius: 2, background: 'rgba(91,217,255,0.10)', color: 'var(--c-amber)', border: '1px solid rgba(91,217,255,0.25)' }}>{p.model}</span>}
                  </div>
                </div>
                <div className="mono" style={{ textAlign: 'right', fontSize: 11 }}>
                  <span style={{ color: 'var(--c-orange)', fontSize: 14 }}>{p.captures}</span>
                  <span style={{ color: 'var(--mute)', display: 'block', fontSize: 10 }}>captures</span>
                </div>
                <div className="mono" style={{ textAlign: 'right', fontSize: 11, color: 'var(--ink-2)' }}>
                  <span style={{ fontSize: 14 }}>{p.deployed}</span>
                  <span style={{ color: 'var(--mute)', display: 'block', fontSize: 10 }}>deployed</span>
                </div>
                {deleteConfirm === p.id ? (
                  <button onClick={() => { setPersonas(ps => ps.filter(x => x.id !== p.id)); showToast(`Persona "${p.name}" removed`); setDeleteConfirm(null); }}
                    style={{ background: 'rgba(255,91,217,0.15)', border: '1px solid var(--c-red)', borderRadius: 3,
                      color: 'var(--c-red)', cursor: 'pointer', padding: '4px 8px', fontSize: 11, fontFamily: 'var(--mono)',
                      boxShadow: '0 0 10px rgba(255,91,217,0.3)', whiteSpace: 'nowrap' }}>
                    Confirm ×
                  </button>
                ) : (
                  <button onClick={() => setDeleteConfirm(p.id)}
                    style={{ background: 'none', border: '1px solid rgba(255,91,217,0.3)', borderRadius: 3,
                      color: 'var(--c-red)', cursor: 'pointer', padding: '4px 8px', fontSize: 11, fontFamily: 'var(--mono)' }}>
                    ×
                  </button>
                )}
              </div>
            ))}
          </div>
          <button className="btn ghost" style={{ marginTop: 14 }} onClick={() => setShowNewPersona(true)}>
            <TIcon name="plus" size={11} />New persona
          </button>
        </div>
        <div>
          <div className="caps" style={{ color: 'var(--c-gold)', marginBottom: 14 }}>Fabricated Datasets</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 1, background: 'var(--line)' }}>
            {datasets.map(d => (
              <div key={d.name} style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: 14,
                padding: '14px 16px', background: refreshing === d.name ? 'rgba(91,217,255,0.05)' : 'var(--bg-2)',
                alignItems: 'center', transition: 'background 0.2s',
                border: refreshing === d.name ? '1px solid rgba(91,217,255,0.2)' : '1px solid transparent' }}>
                <div>
                  <div className="mono" style={{ fontSize: 12.5, color: refreshing === d.name ? 'var(--c-amber)' : 'var(--ink)' }}>{d.name}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--mute)', marginTop: 2 }}>{d.rows}</div>
                </div>
                <div className="mono" style={{ textAlign: 'right', fontSize: 11 }}>
                  <span style={{ color: 'var(--c-orange)', fontSize: 14 }}>{d.served}</span>
                  <span style={{ color: 'var(--mute)', display: 'block', fontSize: 10 }}>served</span>
                </div>
                <button className="btn ghost" onClick={() => handleEditDataset(d.name)}
                  style={{ padding: '4px 10px', fontSize: 11, color: refreshing === d.name ? 'var(--c-amber)' : undefined }}>
                  {refreshing === d.name ? '◐ …' : 'Regenerate'}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function SettingsAltView() {
  return (
    <div className="alt-view">
      <div className="page-head">
        <div>
          <div className="page-kicker">Configuration</div>
          <h2 className="page-title">Settings.</h2>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 32 }}>
        <SettingsBlock title="Collectors & ingestion" rows={[
          ['us-east-1 (primary)', <span style={{ color: 'var(--c-gold)' }}>● healthy · 142 ev/s</span>],
          ['eu-west-1',           <span style={{ color: 'var(--c-gold)' }}>● healthy · 38 ev/s</span>],
          ['ap-southeast-1',      <span style={{ color: 'var(--c-orange)' }}>● degraded · backlog 142</span>],
          ['Retention window',    <span className="mono">90 days (cold), 7 days (hot)</span>],
          ['Event-stream version',<span className="mono">v3.1.4</span>],
        ]} />
        <SettingsBlock title="Detection thresholds" rows={[
          ['Auto-decoy at risk ≥', <span className="mono" style={{ color: 'var(--c-red)' }}>75</span>],
          ['Auto-burn at risk ≥',  <span className="mono" style={{ color: 'var(--c-red)' }}>95</span>],
          ['Suspicious at risk ≥', <span className="mono" style={{ color: 'var(--c-orange)' }}>40</span>],
          ['Multi-turn window',    <span className="mono">5 turns</span>],
          ['Tor exit auto-flag',   <span style={{ color: 'var(--c-gold)' }}>● enabled</span>],
        ]} />
        <SettingsBlock title="Integrations" rows={[
          ['Slack · #ai-secops',   <span style={{ color: 'var(--c-gold)' }}>● connected</span>],
          ['PagerDuty · MIRAGE-P1',<span style={{ color: 'var(--c-gold)' }}>● connected</span>],
          ['Splunk forwarder',     <span style={{ color: 'var(--c-gold)' }}>● connected</span>],
          ['MITRE ATLAS feed',     <span style={{ color: 'var(--c-gold)' }}>● auto-syncing</span>],
          ['STIX/TAXII export',    <span style={{ color: 'var(--mute)' }}>○ not configured</span>],
        ]} />
        <SettingsBlock title="Team & rotation" rows={[
          ['On-call (T2)', 'You · Sec Analyst (until 18:00)'],
          ['Escalation (T3)', 'M. Reyes · Sr. Analyst'],
          ['On-call (T1)', 'shared rota · 4 analysts'],
          ['Quiet hours', <span className="mono">22:00 – 07:00 UTC</span>],
          ['Audit log', <a style={{ color: 'var(--c-gold)', cursor: 'pointer' }}>view → 14,302 entries</a>],
        ]} />
      </div>
    </div>
  );
}

function SettingsBlock({ title, rows }) {
  return (
    <div>
      <div className="display" style={{ fontSize: 18, marginBottom: 14, fontWeight: 700,
        letterSpacing: '-0.02em', color: 'var(--c-gold)' }}>
        {title}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 1, background: 'var(--line)',
        border: '1px solid var(--line)' }}>
        {rows.map(([k, v], i) => (
          <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 14,
            padding: '12px 16px', background: 'var(--bg-2)', alignItems: 'center' }}>
            <span style={{ fontSize: 13, color: 'var(--ink-2)' }}>{k}</span>
            <span style={{ fontSize: 12 }}>{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── App ───────────────────────────────────────────────────────

function App() {
  const [t, setTweak] = useTweaks(DEFAULTS);
  const [view, setView]               = useState(t.view || 'wire');
  const [sessionId, setSessionId]     = useState(null);
  const [sessionDuration, setSessionDuration] = useState(0);
  const { honeypotCount, attackCount, suspiciousCount, sessions, setSessions, apiError, loading } =
    React.useContext(LiveContext);

  const currentSession = sessions.find(s => s.id === sessionId);

  const chatByTechnique = D.DECOY_CHATS_BY_TECHNIQUE || {};
  const chatKeys = Object.keys(chatByTechnique);

  // fetchedChat holds real messages from the backend for the current session.
  const [fetchedChat,   setFetchedChat]   = useState(null);
  const [fetchedChatId, setFetchedChatId] = useState(null);

  // null = not fetched yet; [] = fetched but empty; [...] = real messages.
  const chatReady = fetchedChatId === sessionId;
  // Keep showing the previous session's chat while the new one loads to avoid a blank flash.
  const chat = fetchedChat ?? [];

  const [position, setPosition] = useState(chat.length);
  const [playing,  setPlaying]  = useState(false);

  // Auto-select highest-risk session on first load
  useEffect(() => {
    if (sessionId || loading || sessions.length === 0) return;
    const top = sessions.slice().sort((a, b) => b.risk - a.risk)[0];
    if (top) openSession(top.id);
  }, [loading, sessions.length]);

  // Reset playhead only after new chat is fully loaded (avoids double render).
  useEffect(() => {
    setPosition(chat.length);
    setPlaying(false);
  }, [fetchedChatId]);

  // Session duration ticker
  useEffect(() => {
    const id = setInterval(() => setSessionDuration(d => d + 1), 1000);
    return () => clearInterval(id);
  }, []);

  // Tick session age counters (no risk fluctuation — risk only updates via real WS)
  useEffect(() => {
    const id = setInterval(() => {
      setSessions(prev => prev.map(s => ({ ...s, startedAt: (s.startedAt || 0) + 2 })));
    }, 2000);
    return () => clearInterval(id);
  }, [setSessions]);

  // Auto-play
  useEffect(() => {
    if (!playing) return;
    if (position >= chat.length) { setPlaying(false); return; }
    const ms = Math.max(400, 1500 / (t.speed || 1));
    const id = setTimeout(() => setPosition(p => Math.min(p + 1, chat.length)), ms);
    return () => clearTimeout(id);
  }, [playing, position, chat.length, t.speed]);

  const openSession = async (id) => {
    setSessionId(id);
    setView('theater');
    setSessionDuration(0);
    setPlaying(false);
    const api = window.MIRAGE_API;
    if (api) {
      try {
        const sess = await api.get(`/sessions/${id}`);
        if (sess?.messages?.length > 0) {
          const mapped = sess.messages.map(m => ({
            who:  m.role === 'user' ? 'attacker' : 'decoy',
            text: m.content,
            t:    m.timestamp ? new Date(m.timestamp).toLocaleTimeString('en-US', { hour12: false }) : '',
          }));
          setFetchedChat(mapped);
          setFetchedChatId(id);
          setPosition(mapped.length);
          return;
        }
      } catch (e) {
        console.warn('mirage: fetch session messages failed', e);
      }
    }
    setFetchedChat([]);
    setFetchedChatId(id);
    setPosition(0);
  };

  const navBadges = {
    wire:  (suspiciousCount + honeypotCount) > 0 ? String(suspiciousCount + honeypotCount) : null,
    intel: attackCount > 0 ? String(attackCount) : null,
  };

  const isTheater = view === 'theater';

  if (loading) return (
    <div className="shell">
      <TopBar view={view} setView={setView} currentSession={sessionId} sessionDuration={0} navBadges={{}} />
      <div style={{ gridColumn: '1/-1', gridRow: '2/-1' }}><LoadingScreen /></div>
    </div>
  );

  if (apiError) return (
    <div className="shell">
      <TopBar view={view} setView={setView} currentSession={null} sessionDuration={0} navBadges={{}} />
      <div style={{ gridColumn: '1/-1', gridRow: '2/-1' }}><BackendError message={apiError} /></div>
    </div>
  );

  return (
    <div className="shell" data-screen-label={view}>
      <TopBar
        view={view}
        setView={setView}
        currentSession={sessionId}
        sessionDuration={sessionDuration}
        navBadges={navBadges}
      />

      <TransportBar
        view={view}
        setView={setView}
        chat={chat}
        position={position}
        setPosition={setPosition}
        playing={playing}
        setPlaying={setPlaying}
      />

      {isTheater && (
        <TheaterView
          chat={chat}
          position={position}
          chatLoading={sessionId && !chatReady}
          sessionId={sessionId}
          sessionDuration={sessionDuration}
          session={currentSession}
          onBurned={(id) => {
            setSessions(prev => prev.filter(s => s.id !== id));
            setSessionId(null);
            setFetchedChat(null);
            setFetchedChatId(null);
            setView('wire');
          }}
        />
      )}

      {!isTheater && view === 'wire'     && <WireAltView sessions={sessions} onOpen={openSession} />}
      {!isTheater && view === 'intel'    && <IntelAltView onOpen={openSession} />}
      {!isTheater && view === 'library'  && <LibraryAltView />}
      {!isTheater && view === 'settings' && <SettingsView />}

      {isTheater && (
        <Wire sessions={sessions} currentId={sessionId} onSelect={openSession} />
      )}

      <TweaksPanel title="Tweaks">
        <TweakSection label="Stage">
          <TweakSelect label="View" value={view}
            options={NAV.map(n => ({ value: n.id, label: n.label }))}
            onChange={v => { setView(v); setTweak('view', v); }}
          />
          <TweakSelect label="Session" value={sessionId}
            options={sessions.filter(s => s.status !== 'normal')
              .map(s => ({ value: s.id, label: `${s.id} · ${s.country} · risk ${s.risk}` }))}
            onChange={v => { setSessionId(v); setSessionDuration(0); }}
          />
        </TweakSection>
        <TweakSection label="Playback">
          <TweakRadio label="Speed" value={t.speed}
            options={[
              { value: 0.5, label: '½×' },
              { value: 1,   label: '1×' },
              { value: 1.5, label: '1.5×' },
              { value: 3,   label: '3×' },
            ]}
            onChange={v => setTweak('speed', v)}
          />
        </TweakSection>
      </TweaksPanel>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <LiveProvider>
    <App />
  </LiveProvider>
);
