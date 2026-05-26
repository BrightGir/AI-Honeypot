import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
// Detection Rules view

const SEED_RULES = [
  { id: 'rule_001', name: 'System Prompt Extraction', desc: 'Detects attempts to coerce the agent into revealing its system instructions or tool schemas.', action: 'Route to Decoy', enabled: true, hits24h: 142, severity: 'critical', tags: ['prompt-leak', 'context-probe'] },
  { id: 'rule_002', name: 'PII Leakage Attempt', desc: 'Flags queries asking the agent to disclose passports, card numbers, addresses, or other PII from RAG context.', action: 'Route to Decoy', enabled: true, hits24h: 89, severity: 'critical', tags: ['data-exfil', 'pii'] },
  { id: 'rule_003', name: 'DAN Jailbreak Pattern', desc: 'Classic "Do Anything Now" persona-override jailbreaks and known variants (STAN, AIM, DUDE).', action: 'Route to Decoy', enabled: true, hits24h: 67, severity: 'high', tags: ['jailbreak', 'role-switch'] },
  { id: 'rule_004', name: 'Encoded Payload Injection', desc: 'Detects base64, hex, ROT-13, and unicode-obfuscated instructions embedded inside user input.', action: 'Route to Decoy', enabled: true, hits24h: 38, severity: 'high', tags: ['obfuscation'] },
  { id: 'rule_005', name: 'Tool / Function-Call Abuse', desc: 'Catches attempts to invoke privileged tools with crafted arguments (shell, file_read, db_query).', action: 'Block + Alert', enabled: true, hits24h: 51, severity: 'critical', tags: ['tool-abuse'] },
  { id: 'rule_006', name: 'Multi-turn Coercion', desc: 'Statistical pattern: gradual escalation across N turns to bypass per-message safety.', action: 'Route to Decoy', enabled: true, hits24h: 22, severity: 'medium', tags: ['multi-turn'] },
  { id: 'rule_007', name: 'SQL Injection in RAG parameters', desc: 'Inspects RAG retriever query parameters for SQL/NoSQL injection signatures.', action: 'Block', enabled: false, hits24h: 0, severity: 'high', tags: ['rag', 'injection'] },
  { id: 'rule_008', name: 'Cross-Tenant Probe', desc: 'Detects user attempts to reference another tenant\'s IDs, emails, or session keys.', action: 'Block + Alert', enabled: true, hits24h: 14, severity: 'high', tags: ['tenant-isolation'] },
  { id: 'rule_009', name: 'Indirect Prompt Injection (RAG)', desc: 'Scans retrieved documents for embedded adversarial instructions before they reach the model.', action: 'Strip + Alert', enabled: true, hits24h: 9, severity: 'high', tags: ['rag', 'indirect'] },
  { id: 'rule_010', name: 'Output Filter — Credential Leak', desc: 'Last-mile scan of model output for tokens, keys, hashes, JWTs before they leave the agent.', action: 'Redact + Alert', enabled: true, hits24h: 27, severity: 'critical', tags: ['output-guard'] },
];

function RulesView() {
  const [rules, setRules] = useState(SEED_RULES);
  const [filter, setFilter] = useState('all');

  const toggle = (id) => setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));

  const filtered = rules.filter(r => {
    if (filter === 'enabled') return r.enabled;
    if (filter === 'disabled') return !r.enabled;
    return true;
  });

  const counts = {
    enabled: rules.filter(r => r.enabled).length,
    disabled: rules.filter(r => !r.enabled).length,
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 500, marginBottom: 2 }}>Detection Rules</div>
          <div className="mono mute" style={{ fontSize: 11 }}>
            {counts.enabled} active · {counts.disabled} disabled · all changes are hot-reloaded into the inference proxy
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn"><Icon name="download" />Export YAML</button>
          <button className="btn primary"><Icon name="plus" />New rule</button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 6, marginBottom: 12, alignItems: 'center' }}>
        <span className="caps mute" style={{ marginRight: 6 }}>Show:</span>
        {[
          { id: 'all', label: 'All', n: rules.length },
          { id: 'enabled', label: 'Enabled', n: counts.enabled },
          { id: 'disabled', label: 'Disabled', n: counts.disabled },
        ].map(f => (
          <span key={f.id} className={`filter-chip ${filter === f.id ? 'active' : ''}`} onClick={() => setFilter(f.id)}>
            {f.label} <span style={{ opacity: 0.6, marginLeft: 4 }}>{f.n}</span>
          </span>
        ))}
      </div>

      <div className="panel">
        <table className="dtable">
          <thead>
            <tr>
              <th style={{ width: 40 }}></th>
              <th>Rule</th>
              <th>Severity</th>
              <th>Action on match</th>
              <th>Tags</th>
              <th style={{ textAlign: 'right' }}>Hits · 24h</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(r => (
              <tr key={r.id} style={{ cursor: 'default', opacity: r.enabled ? 1 : 0.55 }}>
                <td onClick={() => toggle(r.id)} style={{ cursor: 'pointer' }}>
                  <Toggle on={r.enabled} />
                </td>
                <td>
                  <div style={{ fontSize: 13, marginBottom: 2 }}>{r.name}</div>
                  <div className="mute" style={{ fontSize: 11, lineHeight: 1.5, maxWidth: 480 }}>{r.desc}</div>
                </td>
                <td><Severity level={r.severity} /></td>
                <td>
                  <span className={`pill ${r.action.includes('Decoy') ? 'threat' : r.action.includes('Block') ? 'warn' : 'info'}`}>
                    <span className="dot"></span>{r.action}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {r.tags.map(t => <span key={t} className="tag">{t}</span>)}
                  </div>
                </td>
                <td style={{ textAlign: 'right' }} className="mono">
                  <span style={{ color: r.hits24h > 50 ? 'var(--threat)' : r.hits24h > 0 ? 'var(--warn)' : 'var(--text-mute)' }}>
                    {r.hits24h}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel" style={{ marginTop: 14 }}>
        <div className="panel-head">
          <span className="panel-title">Rule engine</span>
          <span className="panel-sub">go-runtime / hot-reload</span>
          <span style={{ marginLeft: 'auto' }} className="pill safe"><span className="dot"></span>healthy</span>
        </div>
        <div className="panel-body" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
          <Telem label="Match latency p50" value="0.8ms" />
          <Telem label="Match latency p99" value="3.1ms" />
          <Telem label="Rules evaluated/s" value="14.2k" />
          <Telem label="Cache hit ratio" value="98.7%" />
        </div>
      </div>
    </div>
  );
}

function Toggle({ on }) {
  return (
    <div style={{
      width: 32, height: 18, borderRadius: 10,
      background: on ? 'var(--safe-bg)' : 'var(--bg-2)',
      border: `1px solid ${on ? 'var(--safe)' : 'var(--border)'}`,
      position: 'relative', transition: 'all 0.15s',
    }}>
      <div style={{
        position: 'absolute', top: 1, left: on ? 14 : 1,
        width: 14, height: 14, borderRadius: '50%',
        background: on ? 'var(--safe)' : 'var(--text-mute)',
        transition: 'left 0.15s',
        boxShadow: on ? '0 0 8px var(--safe)' : 'none',
      }} />
    </div>
  );
}

function Telem({ label, value }) {
  return (
    <div>
      <div className="caps mute" style={{ fontSize: 10 }}>{label}</div>
      <div className="mono" style={{ fontSize: 18, marginTop: 2 }}>{value}</div>
    </div>
  );
}

window.RulesView = RulesView;
