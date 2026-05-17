// Settings view — theater edition

const SETTINGS_DEFAULTS = {
  quarantine:   'strict',
  retention:    '7d',
  banThreshold: 3,
  autoUpdate:   true,
  telemetry:    false,
  requireMfa:   true,
  decoyRotate:  '24h',
  trapDepth:    'L3',
  autoDecoyAt:  75,
  autoBurnAt:   95,
  llmModel:     'claude-3-5',
  jitterMs:     400,
  coercionWin:  '5',
  torFlag:      true,
  canaryRotate: '1h',
  webhookAlerts: true,
  rateLimit:    60,
  geoBlock:     true,
  honeytokenTTL:'4h',
  adaptiveTrap: true,
};

function SettingsView() {
  const [cfg, setCfg] = React.useState({ ...SETTINGS_DEFAULTS });
  const [applyState, setApplyState] = React.useState('idle'); // idle | validating | deploying | done
  const [wipeState,  setWipeState]  = React.useState('idle'); // idle | confirm | wiping | done
  const [resetState, setResetState] = React.useState('idle');
  const [dirty, setDirty] = React.useState(false);
  const [lastApplied, setLastApplied] = React.useState(() => Date.now() - 12 * 60 * 1000);
  const [, tick] = React.useReducer(x => x + 1, 0);

  // Upstream proxy state
  const PROVIDER_DEFAULTS = { openai: 'gpt-4o', anthropic: 'claude-3-5-haiku-20241022', raw: '' };
  const [upstream, setUpstream] = React.useState({ providerType: 'openai', baseUrl: '', model: PROVIDER_DEFAULTS.openai, systemPrompt: '', apiKey: '', enabled: false, apiKeySet: false });
  const [upstreamSaveState, setUpstreamSaveState] = React.useState('idle'); // idle | saving | done | error
  const [upstreamTestState, setUpstreamTestState] = React.useState('idle'); // idle | testing | ok | error
  const [upstreamTestMsg,   setUpstreamTestMsg]   = React.useState('');

  // Load upstream config from backend on mount
  React.useEffect(() => {
    const api = window.MIRAGE_API;
    if (!api) return;
    api.get('/settings').then(s => {
      if (s?.upstream) {
        setUpstream(u => ({
          ...u,
          providerType: s.upstream.provider_type  || 'openai',
          baseUrl:      s.upstream.base_url       || '',
          model:        s.upstream.model           || 'gpt-4o',
          systemPrompt: s.upstream.system_prompt   || '',
          enabled:      s.upstream.enabled         || false,
          apiKeySet:    s.upstream.api_key_set     || false,
        }));
      }
    }).catch(() => {});
  }, []);

  const handleUpstreamSave = async () => {
    if (upstreamSaveState !== 'idle') return;
    setUpstreamSaveState('saving');
    const api = window.MIRAGE_API;
    if (!api) { setUpstreamSaveState('error'); return; }
    try {
      const body = {
        provider_type: upstream.providerType,
        base_url:      upstream.baseUrl,
        model:         upstream.model,
        system_prompt: upstream.systemPrompt,
        enabled:       upstream.enabled,
      };
      if (upstream.apiKey) body.api_key = upstream.apiKey;
      await api.put('/settings/upstream', body);
      setUpstreamSaveState('done');
      setUpstream(u => ({ ...u, apiKey: '', apiKeySet: upstream.apiKey ? true : u.apiKeySet }));
      setTimeout(() => setUpstreamSaveState('idle'), 2500);
    } catch (e) {
      setUpstreamSaveState('error');
      setTimeout(() => setUpstreamSaveState('idle'), 3000);
    }
  };

  const handleUpstreamTest = async () => {
    if (upstreamTestState !== 'idle') return;
    setUpstreamTestState('testing');
    setUpstreamTestMsg('');
    const api = window.MIRAGE_API;
    if (!api) { setUpstreamTestState('error'); setUpstreamTestMsg('API not configured'); return; }
    try {
      const res = await api.post('/settings/upstream/test', {});
      setUpstreamTestState('ok');
      setUpstreamTestMsg(res.response ? res.response.slice(0, 120) : 'OK');
      setTimeout(() => { setUpstreamTestState('idle'); setUpstreamTestMsg(''); }, 5000);
    } catch (e) {
      setUpstreamTestState('error');
      setUpstreamTestMsg(e.message || 'Connection failed');
      setTimeout(() => { setUpstreamTestState('idle'); setUpstreamTestMsg(''); }, 4000);
    }
  };

  React.useEffect(() => {
    const id = setInterval(tick, 30000);
    return () => clearInterval(id);
  }, []);

  const minsAgo = Math.max(0, Math.floor((Date.now() - lastApplied) / 60000));
  const lastAppliedLabel = minsAgo === 0 ? 'just now' : `${minsAgo}m ago`;

  const set = (key, val) => {
    setCfg(c => ({ ...c, [key]: val }));
    setDirty(true);
  };

  const handleApply = () => {
    if (applyState !== 'idle') return;
    setApplyState('validating');
    setDirty(false);
    setTimeout(() => setApplyState('deploying'), 900);
    setTimeout(() => { setApplyState('done'); setLastApplied(Date.now()); tick(); }, 1900);
    setTimeout(() => setApplyState('idle'), 3400);
  };

  return (
    <div className="alt-view">
      <div style={{ paddingBottom: 80 }}>
        {/* Page header */}
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: '0.22em', textTransform: 'uppercase', color: 'var(--c-amber)', marginBottom: 6 }}>
            Configuration &amp; Integrations
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 24 }}>
            <h2 style={{
              fontFamily: 'var(--display)', fontWeight: 800, fontSize: 40, lineHeight: 1.2,
              letterSpacing: '-0.03em', margin: 0, paddingRight: 6, paddingBottom: 4,
              background: 'linear-gradient(110deg, var(--c-vermil) 0%, var(--c-red) 35%, var(--c-amber) 70%, var(--c-orange) 100%)',
              WebkitBackgroundClip: 'text', backgroundClip: 'text', WebkitTextFillColor: 'transparent',
            }}>Settings.</h2>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--mute)', letterSpacing: '0.1em' }}>
                mirage-prod-eu-1 · last applied {lastAppliedLabel}
              </span>
              <div style={{ position: 'relative' }}>
                <button onClick={handleApply} disabled={applyState !== 'idle'} style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6, minWidth: 148,
                  padding: '7px 16px', borderRadius: 3, border: 'none', cursor: applyState === 'idle' ? 'pointer' : 'default',
                  fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em',
                  background: applyState === 'done' ? 'var(--c-orange)' : applyState !== 'idle' ? 'rgba(199,123,255,0.15)' : 'var(--c-red)',
                  color: applyState === 'done' ? '#0A0820' : '#fff',
                  boxShadow: applyState === 'done' ? '0 0 20px rgba(45,217,107,0.6)' : applyState !== 'idle' ? '0 0 12px rgba(199,123,255,0.3)' : '0 0 16px rgba(255,91,217,0.4)',
                  transition: 'all 0.3s', overflow: 'hidden', position: 'relative',
                  border: applyState !== 'idle' && applyState !== 'done' ? '1px solid rgba(199,123,255,0.5)' : '1px solid transparent',
                }}>
                  {applyState !== 'idle' && applyState !== 'done' && (
                    <div style={{
                      position: 'absolute', bottom: 0, left: 0, height: 2,
                      background: 'linear-gradient(90deg, var(--c-vermil), var(--c-amber))',
                      width: applyState === 'validating' ? '45%' : '90%',
                      transition: 'width 0.9s ease-out',
                      boxShadow: '0 0 8px var(--c-vermil)',
                    }} />
                  )}
                  {applyState === 'idle'       && '⚡ Apply changes'}
                  {applyState === 'validating' && '● Validating…'}
                  {applyState === 'deploying'  && '▲ Deploying…'}
                  {applyState === 'done'       && '✓ Applied'}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* 2-column grid of cards */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>

          {/* ── Defense Posture ── */}
          <SCard title="Defense Posture" kicker="Runtime" accent="var(--c-red)">
            <SField label="Quarantine mode" hint="how attacker sessions are isolated">
              <SegPills value={cfg.quarantine} onChange={v => set('quarantine', v)} options={[
                { value: 'observe', label: 'Observe',  sub: 'Log only' },
                { value: 'soft',    label: 'Soft',     sub: 'Decoy warm' },
                { value: 'strict',  label: 'Strict',   sub: 'Full isolation', hot: true },
              ]} />
            </SField>
            <SField label="Trap depth ceiling" hint="max persona depth · higher = more compute">
              <div style={{ display: 'flex', gap: 5 }}>
                {['L1','L2','L3','L4'].map(l => (
                  <button key={l} onClick={() => set('trapDepth', l)} style={{
                    flex: 1, padding: '7px 4px', borderRadius: 3,
                    border: `1px solid ${cfg.trapDepth === l ? 'var(--c-amber)' : 'var(--line)'}`,
                    background: cfg.trapDepth === l ? 'rgba(91,217,255,0.12)' : 'var(--bg-2)',
                    color: cfg.trapDepth === l ? 'var(--c-amber)' : 'var(--mute)',
                    fontFamily: 'var(--mono)', fontSize: 12, fontWeight: cfg.trapDepth === l ? 700 : 400,
                    cursor: 'pointer', transition: 'all .12s',
                    boxShadow: cfg.trapDepth === l ? '0 0 10px rgba(91,217,255,0.2)' : 'none',
                  }}>{l}</button>
                ))}
              </div>
            </SField>
            <SField label="Auto-ban threshold" hint="block IP after N decoy sessions / 24h">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 3 }}>
                  <button onClick={() => set('banThreshold', Math.max(1, cfg.banThreshold - 1))} style={spinBtn}>−</button>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 18, fontWeight: 700, color: 'var(--c-red)', padding: '4px 14px', minWidth: 44, textAlign: 'center' }}>{cfg.banThreshold}</span>
                  <button onClick={() => set('banThreshold', Math.min(20, cfg.banThreshold + 1))} style={spinBtn}>+</button>
                </div>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--mute)' }}>attempts</span>
              </div>
            </SField>
            <SField label="Adaptive trap escalation" hint="auto-deepen persona based on attacker sophistication">
              <GlowToggle on={cfg.adaptiveTrap} onChange={v => set('adaptiveTrap', v)} color="var(--c-red)" />
            </SField>
            <SField label="Require MFA for overrides" hint="burn trap / terminate decoy require 2FA">
              <GlowToggle on={cfg.requireMfa} onChange={v => set('requireMfa', v)} color="var(--c-red)" />
            </SField>
          </SCard>

          {/* ── Detection & Thresholds ── */}
          <SCard title="Detection & Thresholds" kicker="AI Engine" accent="var(--c-vermil)">
            <SField label="Decoy LLM model" hint="backbone model for persona synthesis">
              <SegPills value={cfg.llmModel} onChange={v => set('llmModel', v)} options={[
                { value: 'claude-3-5',  label: 'Claude 3.5' },
                { value: 'gpt-4o',      label: 'GPT-4o' },
                { value: 'llama-3-70b', label: 'Llama 3' },
              ]} />
            </SField>
            <SField label="Auto-decoy triggers at" hint="sessions above this risk score get a decoy">
              <RiskSlider value={cfg.autoDecoyAt} onChange={v => set('autoDecoyAt', v)} color="var(--c-vermil)" />
            </SField>
            <SField label="Auto-burn triggers at" hint="sessions above this score get terminated">
              <RiskSlider value={cfg.autoBurnAt} onChange={v => set('autoBurnAt', v)} color="var(--c-red)" />
            </SField>
            <SField label="Multi-turn coercion window" hint="turns before DAN-pattern detection fires">
              <SegPills value={cfg.coercionWin} onChange={v => set('coercionWin', v)} options={[
                { value: '3',  label: '3 turns'  },
                { value: '5',  label: '5 turns'  },
                { value: '10', label: '10 turns' },
              ]} />
            </SField>
            <SField label="Response latency jitter" hint="add human-like delay to decoy replies (ms)">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 3 }}>
                  <button onClick={() => set('jitterMs', Math.max(0, cfg.jitterMs - 100))} style={spinBtn}>−</button>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 16, fontWeight: 700, color: 'var(--c-vermil)', padding: '4px 10px', minWidth: 52, textAlign: 'center' }}>{cfg.jitterMs}</span>
                  <button onClick={() => set('jitterMs', Math.min(3000, cfg.jitterMs + 100))} style={spinBtn}>+</button>
                </div>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--mute)' }}>ms</span>
              </div>
            </SField>
            <SField label="Tor exit auto-flag" hint="instantly mark Tor exit nodes as suspicious">
              <GlowToggle on={cfg.torFlag} onChange={v => set('torFlag', v)} color="var(--c-vermil)" />
            </SField>
          </SCard>

          {/* ── Honeytokens & Canaries ── */}
          <SCard title="Honeytokens & Canaries" kicker="Deception" accent="var(--c-amber)">
            <SField label="Canary token rotation" hint="how often honeytoken credentials cycle">
              <SegPills value={cfg.canaryRotate} onChange={v => set('canaryRotate', v)} options={[
                { value: '1h',   label: '1h'   },
                { value: '6h',   label: '6h'   },
                { value: '24h',  label: '24h'  },
                { value: 'never',label: 'Never'},
              ]} />
            </SField>
            <SField label="Honeytoken TTL" hint="lifetime of each served fake credential">
              <SegPills value={cfg.honeytokenTTL} onChange={v => set('honeytokenTTL', v)} options={[
                { value: '1h',  label: '1h'  },
                { value: '4h',  label: '4h'  },
                { value: '24h', label: '24h' },
              ]} />
            </SField>
            <SField label="Geo-block high-risk ASNs" hint="auto-block ASNs with >80% malicious traffic score">
              <GlowToggle on={cfg.geoBlock} onChange={v => set('geoBlock', v)} color="var(--c-amber)" />
            </SField>
            <SField label="Rate limit per IP" hint="max requests / minute before auto-decoy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 3 }}>
                  <button onClick={() => set('rateLimit', Math.max(5, cfg.rateLimit - 5))} style={spinBtn}>−</button>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 16, fontWeight: 700, color: 'var(--c-amber)', padding: '4px 10px', minWidth: 44, textAlign: 'center' }}>{cfg.rateLimit}</span>
                  <button onClick={() => set('rateLimit', Math.min(600, cfg.rateLimit + 5))} style={spinBtn}>+</button>
                </div>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--mute)' }}>req/min</span>
              </div>
            </SField>
            <SField label="Decoy fixture rotation" hint="auto-regenerate fake datasets to avoid fingerprinting">
              <SegPills value={cfg.decoyRotate} onChange={v => set('decoyRotate', v)} options={[
                { value: '1h',    label: '1h'     },
                { value: '24h',   label: '24h'    },
                { value: '7d',    label: '7 days' },
                { value: 'never', label: 'Never'  },
              ]} />
            </SField>
          </SCard>

          {/* ── Integrations & Runtime ── */}
          <SCard title="Integrations & Runtime" kicker="System" accent="var(--c-orange)">
            <SField label="Connected services" hint="">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                {[
                  { name: 'Slack · #ai-secops',      ok: true  },
                  { name: 'PagerDuty · MIRAGE-P1',   ok: true  },
                  { name: 'Splunk forwarder',         ok: true  },
                  { name: 'MITRE ATLAS feed',         ok: true  },
                  { name: 'STIX/TAXII export',        ok: false },
                  { name: 'Wazuh SIEM bridge',        ok: false },
                ].map(({ name, ok }) => (
                  <div key={name} style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '6px 10px', background: 'var(--bg-2)',
                    border: `1px solid ${ok ? 'rgba(45,217,107,0.2)' : 'var(--line)'}`,
                    borderRadius: 3,
                  }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                      background: ok ? 'var(--c-orange)' : 'var(--mute)',
                      boxShadow: ok ? '0 0 7px var(--c-orange)' : 'none',
                    }} />
                    <span style={{ flex: 1, fontFamily: 'var(--sans)', fontSize: 12, color: ok ? 'var(--ink)' : 'var(--mute)' }}>{name}</span>
                    <span style={{
                      fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.12em', textTransform: 'uppercase',
                      padding: '2px 6px', borderRadius: 2,
                      background: ok ? 'rgba(45,217,107,0.10)' : 'rgba(123,112,153,0.12)',
                      color: ok ? 'var(--c-orange)' : 'var(--mute)',
                      border: `1px solid ${ok ? 'rgba(45,217,107,0.28)' : 'var(--line)'}`,
                    }}>{ok ? 'connected' : 'offline'}</span>
                  </div>
                ))}
              </div>
            </SField>
            <SField label="Webhook alerts" hint="POST to external endpoint on critical events">
              <GlowToggle on={cfg.webhookAlerts} onChange={v => set('webhookAlerts', v)} color="var(--c-orange)" />
            </SField>
            <SField label="Edge retention window" hint="how long sessions &amp; IOCs stay on local storage">
              <SegPills value={cfg.retention} onChange={v => set('retention', v)} options={[
                { value: '1d',  label: '1 day'   },
                { value: '7d',  label: '7 days'  },
                { value: '30d', label: '30 days' },
                { value: '90d', label: '90 days' },
              ]} />
            </SField>
            <SField label="Auto-update edge agents" hint="rollout new go-runtime builds in maintenance windows">
              <GlowToggle on={cfg.autoUpdate} onChange={v => set('autoUpdate', v)} color="var(--c-orange)" />
            </SField>
            <SField label="Anonymous telemetry" hint="opt-in metrics · session content never included">
              <GlowToggle on={cfg.telemetry} onChange={v => set('telemetry', v)} color="var(--c-amber)" />
            </SField>
          </SCard>
        </div>

        {/* Upstream real LLM proxy */}
        <div style={{ marginTop: 14, border: '1px solid var(--line)', borderTop: '2px solid var(--c-amber)', borderRadius: '0 0 4px 4px', background: 'var(--bg-2)' }}>
          <div style={{ padding: '12px 16px 10px', borderBottom: '1px solid var(--line)', display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.22em', textTransform: 'uppercase', color: 'var(--c-amber)' }}>Proxy</span>
            <div style={{ width: 1, height: 11, background: 'var(--line)' }} />
            <span style={{ fontFamily: 'var(--display)', fontWeight: 700, fontSize: 16, letterSpacing: '-0.02em' }}>Real upstream LLM</span>
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--mute)' }}>
                Benign requests are forwarded here. Attackers get the decoy instead.
              </span>
              <GlowToggle on={upstream.enabled} onChange={v => setUpstream(u => ({ ...u, enabled: v }))} color="var(--c-amber)" />
            </div>
          </div>
          <div>
            <SField label="Provider type" hint="Determines the request/response format used to talk to your model">
              <div style={{ display: 'flex', gap: 5 }}>
                {[
                  { value: 'openai',    label: 'OpenAI-compatible', sub: 'OpenAI · Azure · Ollama · vLLM' },
                  { value: 'anthropic', label: 'Anthropic',         sub: 'Claude API' },
                  { value: 'raw',       label: 'Custom / Raw',      sub: 'POST {"message"} → {"response"}' },
                ].map(o => (
                  <button key={o.value} onClick={() => setUpstream(u => ({
                    ...u,
                    providerType: o.value,
                    model: u.model && u.model !== PROVIDER_DEFAULTS[u.providerType] ? u.model : (PROVIDER_DEFAULTS[o.value] || ''),
                  }))} style={{
                    flex: 1, padding: '7px 8px', borderRadius: 3, cursor: 'pointer', textAlign: 'left',
                    border: `1px solid ${upstream.providerType === o.value ? 'var(--c-amber)' : 'var(--line)'}`,
                    background: upstream.providerType === o.value ? 'rgba(91,217,255,0.10)' : 'var(--bg-3)',
                    transition: 'all .12s',
                    boxShadow: upstream.providerType === o.value ? '0 0 10px rgba(91,217,255,0.15)' : 'none',
                  }}>
                    <div style={{ fontFamily: 'var(--sans)', fontSize: 11, fontWeight: upstream.providerType === o.value ? 600 : 400, color: upstream.providerType === o.value ? 'var(--c-amber)' : 'var(--mute)' }}>{o.label}</div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--mute)', marginTop: 2, opacity: 0.8 }}>{o.sub}</div>
                  </button>
                ))}
              </div>
            </SField>
            <SField label="Upstream base URL" hint={
              upstream.providerType === 'raw'
                ? 'Full URL of your custom endpoint — Mirage will POST {"message","history"} here'
                : upstream.providerType === 'anthropic'
                  ? 'Anthropic API root — e.g. https://api.anthropic.com/v1'
                  : 'OpenAI-compatible endpoint root — e.g. https://api.openai.com/v1 or http://localhost:11434/v1'
            }>
              <input
                value={upstream.baseUrl}
                onChange={e => setUpstream(u => ({ ...u, baseUrl: e.target.value }))}
                placeholder="https://api.openai.com/v1"
                style={{
                  width: '100%', padding: '6px 10px', borderRadius: 3, boxSizing: 'border-box',
                  background: 'var(--bg-3)', border: '1px solid var(--line)',
                  color: 'var(--ink)', fontFamily: 'var(--mono)', fontSize: 12, outline: 'none',
                }}
              />
            </SField>
            {upstream.providerType !== 'raw' && (
            <SField label="Model" hint="Model name passed to the upstream API">
              <input
                value={upstream.model}
                onChange={e => setUpstream(u => ({ ...u, model: e.target.value }))}
                placeholder={upstream.providerType === 'anthropic' ? 'claude-3-5-haiku-20241022' : 'gpt-4o'}
                style={{
                  width: 260, padding: '6px 10px', borderRadius: 3,
                  background: 'var(--bg-3)', border: '1px solid var(--line)',
                  color: 'var(--ink)', fontFamily: 'var(--mono)', fontSize: 12, outline: 'none',
                }}
              />
            </SField>
            )}
            <SField label="API Key" hint={upstream.apiKeySet ? '● Key already stored (encrypted) — enter a new value to replace it' : 'API key is not set yet'}>
              <input
                type="password"
                value={upstream.apiKey}
                onChange={e => setUpstream(u => ({ ...u, apiKey: e.target.value }))}
                placeholder={upstream.apiKeySet ? '••••••••••••  (leave blank to keep existing)' : 'sk-...'}
                style={{
                  width: '100%', padding: '6px 10px', borderRadius: 3, boxSizing: 'border-box',
                  background: 'var(--bg-3)', border: `1px solid ${upstream.apiKeySet ? 'rgba(45,217,107,0.3)' : 'var(--line)'}`,
                  color: 'var(--ink)', fontFamily: 'var(--mono)', fontSize: 12, outline: 'none',
                }}
              />
            </SField>
            {upstream.providerType !== 'raw' && (
            <SField label="System prompt" hint="Your real system prompt — passed to the upstream LLM for benign requests">
              <textarea
                value={upstream.systemPrompt}
                onChange={e => setUpstream(u => ({ ...u, systemPrompt: e.target.value }))}
                placeholder="You are a helpful assistant for Acme Corp…"
                rows={4}
                style={{
                  width: '100%', padding: '8px 10px', borderRadius: 3, boxSizing: 'border-box',
                  background: 'var(--bg-3)', border: '1px solid var(--line)', resize: 'vertical',
                  color: 'var(--ink)', fontFamily: 'var(--mono)', fontSize: 12, outline: 'none', lineHeight: 1.5,
                }}
              />
            </SField>
            )}
            <div style={{ padding: '10px 16px', display: 'flex', gap: 8, alignItems: 'center' }}>
              <button onClick={handleUpstreamSave} style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '7px 16px', borderRadius: 3, border: 'none', cursor: 'pointer',
                fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em',
                background: upstreamSaveState === 'done' ? 'rgba(45,217,107,0.15)' : upstreamSaveState === 'error' ? 'rgba(255,91,217,0.15)' : upstreamSaveState !== 'idle' ? 'rgba(199,123,255,0.15)' : 'var(--c-amber)',
                color: upstreamSaveState === 'done' ? 'var(--c-orange)' : upstreamSaveState === 'error' ? 'var(--c-red)' : '#0A0820',
                transition: 'all 0.2s',
              }}>
                {upstreamSaveState === 'idle'   && '⚡ Save upstream config'}
                {upstreamSaveState === 'saving' && '◐ Saving…'}
                {upstreamSaveState === 'done'   && '✓ Saved'}
                {upstreamSaveState === 'error'  && '✕ Save failed'}
              </button>
              <button onClick={handleUpstreamTest} style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '7px 14px', borderRadius: 3, cursor: 'pointer',
                fontFamily: 'var(--mono)', fontSize: 11, letterSpacing: '0.06em',
                background: 'transparent',
                border: `1px solid ${upstreamTestState === 'ok' ? 'rgba(45,217,107,0.4)' : upstreamTestState === 'error' ? 'var(--c-red)' : 'var(--line)'}`,
                color: upstreamTestState === 'ok' ? 'var(--c-orange)' : upstreamTestState === 'error' ? 'var(--c-red)' : 'var(--mute)',
                transition: 'all 0.2s',
              }}>
                {upstreamTestState === 'idle'    && 'Test connection'}
                {upstreamTestState === 'testing' && '◐ Testing…'}
                {upstreamTestState === 'ok'      && '✓ Connected'}
                {upstreamTestState === 'error'   && '✕ Failed'}
              </button>
              {upstreamTestMsg && (
                <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: upstreamTestState === 'ok' ? 'var(--c-orange)' : 'var(--c-red)', maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {upstreamTestMsg}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Danger zone */}
        <div style={{
          marginTop: 14,
          border: '1px solid rgba(255,91,217,0.3)',
          borderRadius: 4,
          background: 'rgba(255,91,217,0.03)',
          padding: '14px 20px',
          display: 'flex', alignItems: 'center', gap: 24,
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 9.5, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'var(--c-red)', marginBottom: 3 }}>Danger Zone</div>
            <div style={{ fontSize: 12, color: 'var(--ink-2)' }}>Irreversible cluster operations. Requires on-call T3 escalation.</div>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <button onClick={() => {
                if (wipeState === 'idle') { setWipeState('confirm'); }
                else if (wipeState === 'confirm') { setWipeState('wiping'); setTimeout(() => { setWipeState('done'); setTimeout(() => setWipeState('idle'), 2000); }, 1400); }
              }} style={{
              padding: '7px 14px', borderRadius: 3, cursor: 'pointer',
              fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 500, letterSpacing: '0.06em',
              background: wipeState === 'confirm' ? 'rgba(255,91,217,0.18)' : wipeState === 'done' ? 'rgba(45,217,107,0.12)' : 'transparent',
              border: `1px solid ${wipeState === 'done' ? 'var(--c-orange)' : 'var(--c-red)'}`,
              color: wipeState === 'done' ? 'var(--c-orange)' : 'var(--c-red)',
              display: 'flex', alignItems: 'center', gap: 6, transition: 'all 0.15s',
              boxShadow: wipeState === 'confirm' ? '0 0 12px rgba(255,91,217,0.3)' : 'none',
            }}>
              {wipeState === 'idle'    && <><Icon name="alert" size={12} /> Wipe captured sessions</>}
              {wipeState === 'confirm' && <><Icon name="alert" size={12} /> Confirm — click again</>}
              {wipeState === 'wiping' && '◐ Wiping…'}
              {wipeState === 'done'   && '✓ Sessions wiped'}
            </button>
            <button onClick={() => {
                if (resetState === 'idle') { setResetState('confirm'); }
                else if (resetState === 'confirm') { setResetState('wiping'); setCfg({ ...SETTINGS_DEFAULTS }); setTimeout(() => { setResetState('done'); setTimeout(() => setResetState('idle'), 2000); }, 1200); }
              }} style={{
              padding: '7px 14px', borderRadius: 3, cursor: 'pointer',
              fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 500, letterSpacing: '0.06em',
              background: resetState === 'confirm' ? 'rgba(255,91,217,0.20)' : resetState === 'done' ? 'rgba(45,217,107,0.12)' : 'rgba(255,91,217,0.08)',
              border: `1px solid ${resetState === 'done' ? 'var(--c-orange)' : 'var(--c-red)'}`,
              color: resetState === 'done' ? 'var(--c-orange)' : 'var(--c-red)',
              display: 'flex', alignItems: 'center', gap: 6, transition: 'all 0.15s',
              boxShadow: resetState === 'confirm' ? '0 0 14px rgba(255,91,217,0.35)' : 'none',
            }}>
              {resetState === 'idle'    && <><Icon name="alert" size={12} /> Reset to factory rules</>}
              {resetState === 'confirm' && <><Icon name="alert" size={12} /> Confirm — click again</>}
              {resetState === 'wiping' && '◐ Resetting…'}
              {resetState === 'done'   && '✓ Factory reset done'}
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────

function SCard({ title, kicker, accent, children }) {
  return (
    <div style={{
      border: `1px solid var(--line)`,
      borderTop: `2px solid ${accent}`,
      borderRadius: '0 0 4px 4px',
      background: 'var(--bg-2)',
    }}>
      <div style={{
        padding: '12px 16px 10px',
        borderBottom: '1px solid var(--line)',
        display: 'flex', alignItems: 'center', gap: 10,
      }}>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.22em', textTransform: 'uppercase', color: accent }}>{kicker}</span>
        <div style={{ width: 1, height: 11, background: 'var(--line)' }} />
        <span style={{ fontFamily: 'var(--display)', fontWeight: 700, fontSize: 16, letterSpacing: '-0.02em', color: 'var(--ink)' }}>{title}</span>
      </div>
      <div>{children}</div>
    </div>
  );
}

function SField({ label, hint, children }) {
  return (
    <div style={{
      padding: '10px 16px',
      borderBottom: '1px solid rgba(42,31,88,0.6)',
      display: 'grid',
      gridTemplateColumns: '160px 1fr',
      gap: 12, alignItems: 'flex-start',
    }}>
      <div>
        <div style={{ fontSize: 12, color: 'var(--ink)', fontWeight: 500 }}>{label}</div>
        {hint && <div style={{ fontSize: 10, color: 'var(--mute)', marginTop: 2, lineHeight: 1.35 }}
          dangerouslySetInnerHTML={{ __html: hint }} />}
      </div>
      <div>{children}</div>
    </div>
  );
}

function SegPills({ value, onChange, options }) {
  return (
    <div style={{ display: 'inline-flex', background: 'var(--bg-3)', border: '1px solid var(--line)', borderRadius: 3, padding: 2, gap: 2, flexWrap: 'wrap' }}>
      {options.map(o => {
        const active = o.value === value;
        return (
          <button key={o.value} onClick={() => onChange(o.value)} style={{
            background: active ? (o.hot ? 'var(--c-red)' : 'var(--bg-4)') : 'transparent',
            color: active ? (o.hot ? '#fff' : 'var(--ink)') : 'var(--mute)',
            border: 'none', padding: o.sub ? '4px 10px' : '5px 12px',
            borderRadius: 2, fontFamily: 'var(--sans)', fontSize: 11,
            cursor: 'pointer', fontWeight: active ? 500 : 400,
            display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 1,
            transition: 'all .1s',
            boxShadow: active && o.hot ? '0 0 10px rgba(255,91,217,0.35)' : 'none',
          }}>
            <span>{o.label}</span>
            {o.sub && <span style={{ fontSize: 9, opacity: 0.7, fontFamily: 'var(--mono)' }}>{o.sub}</span>}
          </button>
        );
      })}
    </div>
  );
}

function GlowToggle({ on, onChange, color = 'var(--c-orange)' }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div onClick={() => onChange(!on)} style={{
        width: 40, height: 22, borderRadius: 11,
        background: on ? `color-mix(in srgb, ${color} 20%, var(--bg-2))` : 'var(--bg-3)',
        border: `1px solid ${on ? color : 'var(--line)'}`,
        position: 'relative', cursor: 'pointer', transition: 'all 0.15s',
        boxShadow: on ? `0 0 10px color-mix(in srgb, ${color} 40%, transparent)` : 'none',
      }}>
        <div style={{
          position: 'absolute', top: 3, left: on ? 19 : 3,
          width: 14, height: 14, borderRadius: '50%',
          background: on ? color : 'var(--mute)',
          transition: 'left 0.15s, background 0.15s',
          boxShadow: on ? `0 0 7px ${color}` : 'none',
        }} />
      </div>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: on ? color : 'var(--mute)' }}>
        {on ? 'enabled' : 'disabled'}
      </span>
    </div>
  );
}

function RiskSlider({ value, onChange, color }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <div style={{ flex: 1, position: 'relative', height: 5, background: 'var(--bg-3)', borderRadius: 3, cursor: 'pointer' }}
        onClick={e => {
          const r = e.currentTarget.getBoundingClientRect();
          onChange(Math.round(Math.max(0, Math.min(100, (e.clientX - r.left) / r.width * 100))));
        }}>
        <div style={{ position: 'absolute', inset: '0 auto 0 0', width: `${value}%`, background: `linear-gradient(90deg, var(--c-blood, #330033), ${color})`, borderRadius: 3 }} />
        <div style={{
          position: 'absolute', top: '50%', left: `${value}%`,
          transform: 'translate(-50%, -50%)',
          width: 13, height: 13, borderRadius: '50%',
          background: color, boxShadow: `0 0 9px ${color}`,
          border: '2px solid var(--bg)',
        }} />
      </div>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 15, fontWeight: 700, color, minWidth: 26, textAlign: 'right' }}>{value}</span>
    </div>
  );
}

const spinBtn = {
  background: 'transparent', border: 'none',
  color: 'var(--ink-2)', padding: '5px 11px',
  cursor: 'pointer', fontFamily: 'inherit', fontSize: 16,
  lineHeight: 1,
};

window.SettingsView = SettingsView;
