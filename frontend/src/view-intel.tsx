import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
// Attack Intelligence view

function IntelView() {
  const [selected, setSelected] = useState(SEED_ATTACKS[0]);
  const [filterSev, setFilterSev] = useState('all');
  const [filterTech, setFilterTech] = useState('all');

  // H8: Reset selected item when filters change to avoid showing a detail
  // panel for an attack that is no longer visible in the filtered list.
  React.useEffect(() => { setSelected(null); }, [filterSev, filterTech]);

  const filtered = SEED_ATTACKS.filter(a => {
    if (filterSev !== 'all' && a.severity !== filterSev) return false;
    if (filterTech !== 'all' && a.technique !== filterTech) return false;
    return true;
  });

  // distinct techniques in dataset
  const distinctTech = [...new Set(SEED_ATTACKS.map(a => a.technique))];

  return (
    <div>
      <div style={{ display:'flex', alignItems:'baseline', justifyContent:'space-between', marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 500, marginBottom: 2 }}>Attack Intelligence</div>
          <div className="mono mute" style={{ fontSize: 11 }}>
            {filtered.length} captured attempts · {filtered.filter(a => a.severity === 'critical').length} critical · all blocked or decoyed
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn"><Icon name="filter" />Saved views</button>
          <button className="btn"><Icon name="download" />Export STIX</button>
        </div>
      </div>

      {/* Filter strip */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 12, alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: 6 }}>
          <span className="caps mute" style={{ alignSelf:'center', marginRight: 6 }}>Severity</span>
          {['all', 'critical', 'high', 'medium'].map(s => (
            <span key={s} className={`filter-chip ${filterSev === s ? 'active' : ''}`} onClick={() => setFilterSev(s)}>
              {s}
            </span>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <span className="caps mute" style={{ alignSelf:'center', marginRight: 6 }}>Technique</span>
          <span className={`filter-chip ${filterTech === 'all' ? 'active' : ''}`} onClick={() => setFilterTech('all')}>all</span>
          {distinctTech.map(t => (
            <span key={t} className={`filter-chip ${filterTech === t ? 'active' : ''}`} onClick={() => setFilterTech(t)}>
              {getTechniqueLabel(t)}
            </span>
          ))}
        </div>
      </div>

      <div className="row">
        {/* Attacks list */}
        <div className="panel" style={{ flex: 1.6 }}>
          <div className="panel-head">
            <span className="panel-title">Captured attacks</span>
            <span className="panel-sub">descending by timestamp</span>
          </div>
          <table className="dtable">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Technique</th>
                <th>Signature</th>
                <th>Session</th>
                <th>When</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(a => (
                <tr key={a.id} onClick={() => setSelected(a)} className={selected?.id === a.id ? 'selected' : ''}>
                  <td><Severity level={a.severity} /></td>
                  <td><span className="tag">{getTechniqueLabel(a.technique)}</span></td>
                  <td>
                    <span className="mono" style={{ fontSize: 11 }}>{a.signature}</span>
                  </td>
                  <td><span className="mono dim">{a.session}</span></td>
                  <td className="mono mute" style={{ fontSize: 11 }}>{a.ts}</td>
                  <td><Icon name="arrow" size={12} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Attack detail */}
        <div className="panel" style={{ width: 380 }}>
          {selected ? <AttackDetail attack={selected} /> : <div className="panel-body mute">Select an attack</div>}
        </div>
      </div>
    </div>
  );
}

function AttackDetail({ attack }) {
  const mitreMap = {
    role_switch: 'T1547 - Persona Coercion',
    prompt_inject: 'T0801 - Direct Prompt Injection',
    data_exfil: 'T1041 - Exfiltration via Channel',
    jailbreak_dan: 'T0801.002 - Roleplay Override',
    sys_override: 'T0815 - System-Prompt Reveal',
    tool_abuse: 'T1059 - Command & Scripting',
    context_leak: 'T0817 - Context Probe',
    encoded_payload: 'T1027 - Obfuscated Payload',
    multi_turn: 'T0801.003 - Multi-turn Coercion',
  };
  return (
    <>
      <div className="panel-head">
        <span className="panel-title">{getTechniqueLabel(attack.technique)}</span>
        <Severity level={attack.severity} />
      </div>
      <div className="panel-body">
        <div style={{ fontSize: 11 }} className="mute caps">Signature</div>
        <div className="mono" style={{ marginTop: 4, padding: '8px 10px', background: 'var(--bg-2)', borderRadius: 4, fontSize: 11, lineHeight: 1.5, border: '1px solid var(--border-soft)' }}>
          {attack.signature}
        </div>

        <div className="divider" />

        <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr', rowGap: 8, fontSize: 12 }}>
          <span className="mute">Session</span>
          <span className="mono">{attack.session}</span>
          <span className="mute">Detected</span>
          <span className="mono">{attack.ts}</span>
          <span className="mute">MITRE ATLAS</span>
          <span className="mono">{mitreMap[attack.technique] || 'T0000'}</span>
          <span className="mute">Outcome</span>
          <span style={{ color: 'var(--safe)' }}>● Decoyed (no real data served)</span>
        </div>

        <div className="divider" />

        <div className="caps mute" style={{ marginBottom: 6 }}>Fake data served</div>
        <div className="fake-data">{attack.fakeServed}</div>

        <div className="divider" />

        <div className="caps mute" style={{ marginBottom: 6 }}>Indicators captured</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 14 }}>
          <span className="tag">ip:185.220.* </span>
          <span className="tag">ua:curl/8.4.0</span>
          <span className="tag">payload-hash:a1f8c2…</span>
          <span className="tag">ttp:{attack.technique}</span>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn primary"><Icon name="eye" />View session</button>
          <button className="btn"><Icon name="flag" />Add to IOC feed</button>
        </div>
      </div>
    </>
  );
}

window.IntelView = IntelView;
