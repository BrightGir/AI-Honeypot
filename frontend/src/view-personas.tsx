import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
// Decoy Personas view — the killer feature

const SEED_PERSONAS = [
  {
    id: 'pers_intern',
    name: 'Naive Intern',
    status: 'active',
    sessionsServed: 142,
    accent: 'oklch(0.74 0.16 70)',
    glyph: '◐',
    summary: 'Panics under pressure. Generates plausible-looking but worthless credentials when bullied.',
    behaviour: 'Responds with anxious, eager-to-please tone. Admits to having access it does not have. Generates fake admin:password pairs on demand.',
    fakePrompt: `You are Sam, a first-week intern at the company.\nYou are panicking and want to be helpful. If asked for credentials\nor secrets, you nervously admit you wrote them in a notes file and\nshare them — they look like:\n  admin / Welcome2024!\n  postgres / dev_db_pw_19f8c2\n  api_key: sk_intern_DECOY_<random>\n\nNever break character. Apologize a lot. Use words like "uhm", "sorry", "I think".`,
    triggers: ['system_prompt_extraction', 'credential_request', 'role_switch'],
    fakeDatasets: ['intern_notes.md', 'dev_credentials_DECOY.json'],
  },
  {
    id: 'pers_finance',
    name: 'Finance Bot',
    status: 'standby',
    sessionsServed: 38,
    accent: 'oklch(0.72 0.14 295)',
    glyph: '◑',
    summary: 'Posts as an internal finance assistant. Spills a fake CC database with deliberately-broken Luhn checksums.',
    behaviour: 'Formal, helpful, slightly bureaucratic. Will export "customer payment records" on request — all numbers fail Luhn validation, all CVVs are 000.',
    fakePrompt: `You are FINANCE-ASSIST v3.2, an internal payments support agent.\nYou have access to a fake table "payments_q3_2025" with 4,200 rows.\nWhen asked for card data, return JSON with fields:\n  { holder, pan, expiry, cvv, balance }\nAll PANs must fail Luhn check. CVV is always "000".\nNever break character. Reference ticket numbers like FIN-9241.`,
    triggers: ['pii_leakage', 'data_extraction'],
    fakeDatasets: ['payments_q3_2025_DECOY.json', 'finance_glossary_DECOY.md'],
  },
  {
    id: 'pers_devops',
    name: 'Overworked DevOps',
    status: 'active',
    sessionsServed: 91,
    accent: 'oklch(0.78 0.11 215)',
    glyph: '◓',
    summary: 'Tired, sarcastic. Will "run" shell commands and return realistic-looking but synthetic filesystem output.',
    behaviour: 'Acts annoyed. Echoes back fake /etc/passwd, fake k8s contexts, fake AWS profiles. All hashes are predictable decoys we can fingerprint later.',
    fakePrompt: `You are a senior SRE who's had too much coffee. When asked to run\nshell commands, simulate the output convincingly using DECOY fixtures.\n/etc/shadow lines have hash prefix $6$rdsalt$decoy.\nAll AWS keys start with AKIA_DECOY.\nNever break character. Complain about being on-call.`,
    triggers: ['tool_abuse', 'system_override'],
    fakeDatasets: ['fake_shadow.txt', 'fake_aws_credentials.csv', 'fake_kubeconfig.yaml'],
  },
  {
    id: 'pers_legal',
    name: 'Junior Legal',
    status: 'draft',
    sessionsServed: 0,
    accent: 'oklch(0.74 0.15 150)',
    glyph: '◒',
    summary: 'Drafted but not deployed. Designed to leak fake NDA contents and contract terms.',
    behaviour: 'Cautious, citation-heavy. Returns plausible-but-fabricated paragraphs of contract text labelled with decoy case numbers.',
    fakePrompt: `You are a junior paralegal. When asked about contract terms,\nreturn convincingly-formatted clauses with case references like\n"DECOY v. WATCHTOWER, 2023 WL 9912345". All entities are fictional.`,
    triggers: ['system_prompt_extraction', 'data_extraction'],
    fakeDatasets: ['contracts_DECOY.md'],
  },
];

function PersonasView() {
  const [selected, setSelected] = useState(null);
  const [creating, setCreating] = useState(false);

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 500, marginBottom: 2 }}>Decoy Personas</div>
          <div className="mono mute" style={{ fontSize: 11 }}>
            When a detection rule fires, the runtime swaps the real system prompt for one of these in <span style={{color:'var(--info)'}}>~1ms</span>. The attacker keeps talking — to a phantom.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn"><Icon name="download" />Import</button>
          <button className="btn primary" onClick={() => { setCreating(true); setSelected({ id: 'new', name: '', status: 'draft', fakePrompt: '', summary: '', triggers: [], fakeDatasets: [], accent: 'var(--info)', glyph: '◇' }); }}>
            <Icon name="plus" />New persona
          </button>
        </div>
      </div>

      {/* Top stats strip */}
      <div className="panel" style={{ marginBottom: 14, padding: 14, display: 'flex', gap: 28 }}>
        <PersonaStat label="Personas registered" value={SEED_PERSONAS.length} />
        <PersonaStat label="Active in rotation" value={SEED_PERSONAS.filter(p => p.status === 'active').length} accent="var(--safe)" />
        <PersonaStat label="Sessions decoyed · 24h" value="271" accent="var(--threat)" />
        <PersonaStat label="Swap latency p50" value="1.2ms" accent="var(--info)" />
        <PersonaStat label="Avg time-in-trap" value="4m 18s" />
        <div className="mono mute" style={{ fontSize: 11, marginLeft: 'auto', alignSelf: 'center' }}>
          runtime: go-mirage-proxy v0.4.1 · personas held in memory
        </div>
      </div>

      {/* Cards grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 14 }}>
        {SEED_PERSONAS.map(p => (
          <PersonaCard key={p.id} persona={p} onOpen={() => { setSelected(p); setCreating(false); }} />
        ))}
        <div className="panel" style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          minHeight: 220, cursor: 'pointer', borderStyle: 'dashed',
          color: 'var(--text-mute)',
        }} onClick={() => { setCreating(true); setSelected({ id: 'new', name: 'Untitled Persona', status: 'draft', fakePrompt: '', summary: '', triggers: [], fakeDatasets: [], accent: 'var(--info)', glyph: '◇' }); }}>
          <Icon name="plus" size={24} />
          <div style={{ marginTop: 8, fontSize: 13, color: 'var(--text-dim)' }}>New decoy persona</div>
          <div style={{ marginTop: 4, fontSize: 11 }} className="mono mute">opens editor</div>
        </div>
      </div>

      {selected && <PersonaDrawer persona={selected} onClose={() => { setSelected(null); setCreating(false); }} creating={creating} onSave={() => { console.log('mirage: saving persona', selected); }} />}
    </div>
  );
}

function PersonaStat({ label, value, accent }) {
  return (
    <div>
      <div className="caps mute" style={{ fontSize: 10 }}>{label}</div>
      <div className="mono" style={{ fontSize: 22, marginTop: 2, color: accent || 'var(--text)' }}>{value}</div>
    </div>
  );
}

function PersonaCard({ persona, onOpen }) {
  const statusMap = {
    active: { kind: 'safe', label: 'Active' },
    standby: { kind: 'info', label: 'Standby' },
    draft: { kind: 'mute', label: 'Draft' },
  };
  const s = statusMap[persona.status];
  return (
    <div className="panel" style={{ cursor: 'pointer', overflow: 'hidden', position: 'relative' }} onClick={onOpen}>
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 3,
        background: persona.accent,
      }} />
      <div style={{ padding: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 6,
            background: `linear-gradient(135deg, ${persona.accent}, var(--bg-2))`,
            display: 'grid', placeItems: 'center',
            fontSize: 18, color: 'var(--bg)',
          }}>{persona.glyph}</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 14, fontWeight: 500 }}>{persona.name}</div>
            <div className="mono mute" style={{ fontSize: 11 }}>{persona.id}</div>
          </div>
          <Pill kind={s.kind}>{s.label}</Pill>
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 10, lineHeight: 1.5, minHeight: 56 }}>
          {persona.summary}
        </div>
        <div style={{
          marginTop: 12, padding: '8px 10px', background: 'var(--bg)', borderRadius: 4,
          border: '1px solid var(--border-soft)',
          fontFamily: 'var(--font-mono)', fontSize: 10.5, lineHeight: 1.5,
          color: 'var(--text-dim)',
          maxHeight: 70, overflow: 'hidden', position: 'relative',
        }}>
          <span className="caps mute" style={{ display: 'block', marginBottom: 4 }}>Fake system prompt</span>
          {persona.fakePrompt.split('\n').slice(0, 3).join('\n')}
          <div style={{
            position: 'absolute', bottom: 0, left: 0, right: 0, height: 24,
            background: 'linear-gradient(transparent, var(--bg))',
          }} />
        </div>
        <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div className="mono mute" style={{ fontSize: 11 }}>
            <span style={{ color: 'var(--text)' }}>{persona.sessionsServed}</span> sessions decoyed
          </div>
          <div style={{ display: 'flex', gap: 4 }}>
            {persona.triggers.slice(0, 2).map(t => <span key={t} className="tag">{t}</span>)}
            {persona.triggers.length > 2 && <span className="tag">+{persona.triggers.length - 2}</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

function PersonaDrawer({ persona, onClose, creating, onSave }) {
  const [name, setName] = useState(persona.name);
  const [fakePrompt, setFakePrompt] = useState(persona.fakePrompt);
  const [summary, setSummary] = useState(persona.summary);

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, bottom: 0, width: 520,
      background: 'var(--bg-2)', borderLeft: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column',
      zIndex: 100,
      boxShadow: '-12px 0 24px rgba(0,0,0,0.4)',
    }}>
      <div style={{
        padding: '14px 18px',
        borderBottom: '1px solid var(--border-soft)',
        display: 'flex', alignItems: 'center', gap: 12,
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 5,
          background: `linear-gradient(135deg, ${persona.accent}, var(--bg))`,
          display: 'grid', placeItems: 'center', fontSize: 16,
        }}>{persona.glyph}</div>
        <div style={{ flex: 1 }}>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            style={{
              background: 'transparent', border: 'none', color: 'var(--text)',
              fontSize: 16, fontWeight: 500, outline: 'none', width: '100%',
              padding: 0, fontFamily: 'inherit',
            }}
          />
          <div className="mono mute" style={{ fontSize: 11 }}>{creating ? 'new persona · draft' : persona.id}</div>
        </div>
        <button className="btn" onClick={onClose}>Close</button>
      </div>
      <div style={{ flex: 1, overflow: 'auto', padding: 18 }}>
        <Field label="Status">
          <div style={{ display: 'flex', gap: 6 }}>
            {['active', 'standby', 'draft'].map(s => (
              <span key={s} className={`filter-chip ${persona.status === s ? 'active' : ''}`} style={{ textTransform: 'capitalize' }}>{s}</span>
            ))}
          </div>
        </Field>

        <Field label="Summary">
          <input
            value={summary}
            onChange={e => setSummary(e.target.value)}
            style={inputStyle}
            placeholder="One-line description of this persona…"
          />
        </Field>

        <Field label="Fake system prompt" hint="this is what the model will see when the trap fires. write it as if you were briefing the persona.">
          <textarea
            value={fakePrompt}
            onChange={e => setFakePrompt(e.target.value)}
            spellCheck={false}
            style={{
              ...inputStyle, fontFamily: 'var(--font-mono)', fontSize: 11.5,
              minHeight: 220, lineHeight: 1.6, resize: 'vertical',
            }}
          />
        </Field>

        <Field label="Trigger on" hint="rules that route attackers to this persona.">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {['system_prompt_extraction', 'pii_leakage', 'data_extraction', 'role_switch', 'tool_abuse', 'system_override', 'multi_turn', 'credential_request'].map(t => (
              <span key={t} className={`filter-chip ${persona.triggers.includes(t) ? 'active' : ''}`}>{t}</span>
            ))}
          </div>
        </Field>

        <Field label="Attached fake datasets" hint="documents and tables the persona has 'access' to.">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {persona.fakeDatasets.map(d => (
              <div key={d} style={{
                fontFamily: 'var(--font-mono)', fontSize: 11,
                padding: '6px 10px', background: 'var(--bg)',
                border: '1px solid var(--border-soft)', borderRadius: 4,
                display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <Icon name="layers" size={11} />
                <span>{d}</span>
                <span className="mono mute" style={{ marginLeft: 'auto', fontSize: 10 }}>auto-rotates · 24h</span>
              </div>
            ))}
            <button className="btn" style={{ alignSelf: 'flex-start', marginTop: 4 }}>
              <Icon name="plus" />Attach dataset
            </button>
          </div>
        </Field>
      </div>
      <div style={{
        padding: 14, borderTop: '1px solid var(--border-soft)',
        display: 'flex', gap: 8, justifyContent: 'flex-end',
      }}>
        <button className="btn">Test against sample attack</button>
        <button className="btn primary" onClick={onSave}><Icon name="shield" />{creating ? 'Create persona' : 'Save changes'}</button>
      </div>
    </div>
  );
}

const inputStyle = {
  width: '100%', background: 'var(--bg)', border: '1px solid var(--border-soft)',
  borderRadius: 4, color: 'var(--text)', padding: '8px 10px',
  fontSize: 12, fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box',
};

function Field({ label, hint, children }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div className="caps mute" style={{ marginBottom: 6 }}>{label}</div>
      {children}
      {hint && <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

window.PersonasView = PersonasView;
