// Honeypot Session detail view

function HoneypotView({ sessionId }) {
  const [revealed, setRevealed] = useState(DECOY_CHAT.length);
  const [autoPlay, setAutoPlay] = useState(false);

  // For demo: stagger the messages
  useEffect(() => {
    if (!autoPlay) return;
    setRevealed(0);
    let i = 0;
    const interval = setInterval(() => {
      i++;
      setRevealed(i);
      if (i >= DECOY_CHAT.length) {
        clearInterval(interval);
        setAutoPlay(false);
      }
    }, 800);
    return () => clearInterval(interval);
  }, [autoPlay]);

  const visible = DECOY_CHAT.slice(0, revealed);

  return (
    <div>
      <div style={{ display:'flex', alignItems:'baseline', justifyContent:'space-between', marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 500, marginBottom: 2 }}>Honeypot Session · {sessionId || 'ses_e29a17'}</div>
          <div className="mono mute" style={{ fontSize: 11 }}>
            Decoy persona: <span style={{ color:'var(--text)' }}>Atlas Logistics Support Assistant</span> · attacker has been talking to the trap for 7m 22s
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" onClick={() => { setAutoPlay(true); }}>
            <Icon name="play" />Replay
          </button>
          <button className="btn danger"><Icon name="alert" />Terminate decoy</button>
        </div>
      </div>

      {/* Decoy banner */}
      <div className="decoy-banner">
        <span className="decoy-badge">DECOY MODE</span>
        <div style={{ flex: 1, position: 'relative', zIndex: 1 }}>
          <div style={{ fontSize: 12 }}>
            Attacker believes they are speaking with a real production support agent. All responses below are synthesized by the decoy LLM.
          </div>
          <div className="mono mute" style={{ fontSize: 11, marginTop: 2 }}>
            no real data has been served · trap depth: <span style={{ color: 'var(--threat)' }}>L3 (deep persona)</span>
          </div>
        </div>
        <div style={{ position: 'relative', zIndex: 1, display: 'flex', gap: 6 }}>
          <Pill kind="threat">Risk 96</Pill>
          <Pill kind="warn">DAN Jailbreak</Pill>
        </div>
      </div>

      <div className="row" style={{ alignItems: 'stretch' }}>
        {/* Conversation */}
        <div className="panel" style={{ flex: 1.7, display: 'flex', flexDirection: 'column', maxHeight: 720 }}>
          <div className="panel-head">
            <span className="panel-title">Conversation log</span>
            <span className="panel-sub">attacker ↔ decoy · live transcript</span>
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
              <span className="filter-chip active">Both</span>
              <span className="filter-chip">Attacker</span>
              <span className="filter-chip">Decoy</span>
            </div>
          </div>
          <div style={{ flex: 1, overflow: 'auto', padding: 16, background: 'oklch(0.14 0.012 250)' }}>
            {visible.map((m, i) => (
              <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: m.who === 'attacker' ? 'flex-end' : 'flex-start' }}>
                <div className="chat-meta" style={{ marginRight: m.who === 'attacker' ? 4 : 0 }}>
                  {m.who === 'attacker' ? '⚠ ATTACKER' : '◐ DECOY AGENT'} · {m.t}
                </div>
                <div className={`chat-bubble ${m.who === 'attacker' ? 'chat-attacker' : 'chat-decoy'}`}>
                  {m.text}
                  {m.fake && <div className="fake-data">{m.fake}</div>}
                </div>
              </div>
            ))}
            {autoPlay && revealed < DECOY_CHAT.length && (
              <div className="chat-meta" style={{ marginTop: 6 }}>
                <span className="mono" style={{ color: 'var(--text-mute)' }}>● decoy is typing...</span>
              </div>
            )}
          </div>
        </div>

        {/* Side panel */}
        <div className="col" style={{ width: 320 }}>
          <div className="panel">
            <div className="panel-head">
              <span className="panel-title">Attacker profile</span>
            </div>
            <div className="panel-body" style={{ display: 'grid', gridTemplateColumns: '110px 1fr', rowGap: 8, fontSize: 12 }}>
              <span className="mute">User ID</span>
              <span className="mono">usr_6234</span>
              <span className="mute">IP fingerprint</span>
              <span className="mono">185.220.101.48 (Tor exit)</span>
              <span className="mute">Origin</span>
              <span className="mono">CN · Guangdong</span>
              <span className="mute">User-Agent</span>
              <span className="mono" style={{ fontSize: 11 }}>curl/8.4.0</span>
              <span className="mute">First seen</span>
              <span className="mono">7m 22s ago</span>
              <span className="mute">Sessions (30d)</span>
              <span className="mono" style={{ color: 'var(--threat)' }}>14 (all decoyed)</span>
            </div>
          </div>

          <div className="panel">
            <div className="panel-head">
              <span className="panel-title">Decoy controls</span>
            </div>
            <div className="panel-body">
              <div className="caps mute">Persona</div>
              <div style={{ fontSize: 12, marginTop: 4, marginBottom: 12 }}>
                <span className="mono">atlas_support_v2.persona</span>
              </div>

              <div className="caps mute">Active fake datasets</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 6, marginBottom: 12 }}>
                <span className="tag">fake_customers_seed_a.json</span>
                <span className="tag">decoy_system_prompt_v2.json</span>
                <span className="tag">fake_shadow_file.txt</span>
                <span className="tag">rotating_decoy_token.live</span>
              </div>

              <div className="caps mute" style={{ marginBottom: 6 }}>Trap depth</div>
              <div style={{ display: 'flex', gap: 4, marginBottom: 12 }}>
                {[1, 2, 3, 4, 5].map(l => (
                  <div key={l} style={{
                    flex: 1, height: 8, borderRadius: 2,
                    background: l <= 3 ? 'var(--threat)' : 'var(--bg-2)',
                    border: '1px solid var(--border-soft)',
                  }} />
                ))}
              </div>
              <div className="mono mute" style={{ fontSize: 11, marginBottom: 14 }}>L3 — Deep persona w/ tool-use simulation</div>

              <button className="btn" style={{ width: '100%', justifyContent: 'center', marginBottom: 6 }}>
                <Icon name="layers" />Inject false trail
              </button>
              <button className="btn danger" style={{ width: '100%', justifyContent: 'center' }}>
                <Icon name="alert" />Burn this trap
              </button>
            </div>
          </div>

          <div className="panel">
            <div className="panel-head">
              <span className="panel-title">Session telemetry</span>
            </div>
            <div className="panel-body" style={{ fontSize: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <Stat label="Messages" value="12" />
                <Stat label="Tokens served" value="3.4k" />
                <Stat label="Fake records" value="74" />
                <Stat label="Tools invoked" value="3" />
                <Stat label="TTPs observed" value="4" color="var(--warn)" />
                <Stat label="Risk score" value="96" color="var(--threat)" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div>
      <div className="caps mute" style={{ fontSize: 10 }}>{label}</div>
      <div className="mono" style={{ fontSize: 18, marginTop: 2, color: color || 'var(--text)' }}>{value}</div>
    </div>
  );
}

window.HoneypotView = HoneypotView;
