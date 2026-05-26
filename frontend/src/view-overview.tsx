import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
// Stats Overview view

function OverviewView() {
  // KPI sparkline data — static seed arrays (no Math.random so useMemo is stable)
  const sparkAttacks  = useMemo(() => [22,25,19,28,24,21,30,26,18,23,27,20,29,24,22,26,19,28,25,21,30,23,27,24], []);
  const sparkSessions = useMemo(() => [5,7,6,8,5,9,6,7,8,5,6,9,7,5,8,6,7,5,9,6,8,7,5,6], []);
  const sparkBlocked  = useMemo(() => [120,135,118,142,128,115,138,125,110,132,145,120,138,125,118,140,128,115,142,130,120,135,125,118], []);
  const sparkAgents   = useMemo(() => [340,355,338,362,348,335,358,345,330,352,365,340,358,345,338,360,348,335,362,350,340,355,345,338], []);

  const max = Math.max(...ATTACK_TIMELINE.map(d => d.attacks));

  return (
    <div>
      <div style={{ display:'flex', alignItems:'baseline', justifyContent:'space-between', marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 500, marginBottom: 2 }}>Threat Overview</div>
          <div className="mono mute" style={{ fontSize: 11 }}>Window: last 24 hours · auto-refresh 5s · region: global</div>
        </div>
        <div style={{ display:'flex', gap: 8 }}>
          <button className="btn"><Icon name="filter" />Filters</button>
          <button className="btn"><Icon name="download" />Export</button>
          <button className="btn primary"><Icon name="plus" />New rule</button>
        </div>
      </div>

      {/* KPIs */}
      <div className="kpi-grid">
        <div className="kpi">
          <div className="kpi-accent" style={{ background: 'var(--threat)' }} />
          <div className="kpi-label">Attacks caught · 24h</div>
          <div className="kpi-value">1,284<span className="kpi-delta" style={{ color: 'var(--threat)' }}>↑ 18.4%</span></div>
          <div className="kpi-spark"><Sparkline data={sparkAttacks} color="var(--threat)" /></div>
        </div>
        <div className="kpi">
          <div className="kpi-accent" style={{ background: 'var(--warn)' }} />
          <div className="kpi-label">Active honeypot sessions</div>
          <div className="kpi-value">37<span className="kpi-delta" style={{ color: 'var(--warn)' }}>↑ 4</span></div>
          <div className="kpi-spark"><Sparkline data={sparkSessions} color="var(--warn)" /></div>
        </div>
        <div className="kpi">
          <div className="kpi-accent" style={{ background: 'var(--info)' }} />
          <div className="kpi-label">Data requests blocked</div>
          <div className="kpi-value">2,901<span className="kpi-delta" style={{ color: 'var(--safe)' }}>↑ 6.1%</span></div>
          <div className="kpi-spark"><Sparkline data={sparkBlocked} color="var(--info)" /></div>
        </div>
        <div className="kpi">
          <div className="kpi-accent" style={{ background: 'var(--safe)' }} />
          <div className="kpi-label">Protected agents</div>
          <div className="kpi-value">348<span className="kpi-delta mute">≈ stable</span></div>
          <div className="kpi-spark"><Sparkline data={sparkAgents} color="var(--safe)" /></div>
        </div>
      </div>

      {/* Timeline + technique mix */}
      <div className="row" style={{ marginBottom: 12 }}>
        <div className="panel grow">
          <div className="panel-head">
            <span className="panel-title">Attack volume · 24h</span>
            <span className="panel-sub">stacked: detected / decoy / blocked</span>
            <div style={{ marginLeft:'auto', display:'flex', gap: 6 }}>
              <span className="filter-chip active">24H</span>
              <span className="filter-chip">7D</span>
              <span className="filter-chip">30D</span>
            </div>
          </div>
          <div className="panel-body">
            <TimelineChart data={ATTACK_TIMELINE} max={max} />
          </div>
        </div>
        <div className="panel" style={{ width: 340 }}>
          <div className="panel-head">
            <span className="panel-title">Technique mix</span>
            <span className="panel-sub">last 24h</span>
          </div>
          <div className="panel-body">
            <TechniqueDonut />
          </div>
        </div>
      </div>

      {/* Top agents + Geo */}
      <div className="row">
        <div className="panel" style={{ flex: 1.4 }}>
          <div className="panel-head">
            <span className="panel-title">Most-targeted agents</span>
            <span className="panel-sub">sessions / attacks / decoys served</span>
          </div>
          <div>
            <table className="dtable">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th style={{textAlign:'right'}}>Sessions</th>
                  <th style={{textAlign:'right'}}>Attacks</th>
                  <th style={{textAlign:'right'}}>Decoy %</th>
                  <th style={{width:140}}>Health</th>
                </tr>
              </thead>
              <tbody>
                {TOP_AGENTS.map(a => {
                  const pct = ((a.honeypot / a.attacks) * 100).toFixed(1);
                  const health = a.attacks / a.sessions;
                  const healthColor = health > 0.05 ? 'var(--threat)' : health > 0.02 ? 'var(--warn)' : 'var(--safe)';
                  return (
                    <tr key={a.name}>
                      <td><span className="mono">{a.name}</span></td>
                      <td style={{textAlign:'right'}} className="mono dim">{a.sessions.toLocaleString()}</td>
                      <td className="mono" style={{color:'var(--warn)', textAlign:'right'}}>{a.attacks}</td>
                      <td className="mono" style={{color:'var(--threat)', textAlign:'right'}}>{pct}%</td>
                      <td>
                        <div style={{ display:'flex', alignItems:'center', gap: 8 }}>
                          <div style={{ flex:1, height: 4, background:'var(--bg-2)', borderRadius: 2 }}>
                            <div style={{ height:'100%', width:`${Math.min(100, health*1000)}%`, background: healthColor, borderRadius: 2 }} />
                          </div>
                          <span className="mono" style={{ fontSize: 10, color: healthColor }}>{(health*100).toFixed(1)}%</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
        <div className="panel" style={{ flex: 1 }}>
          <div className="panel-head">
            <span className="panel-title">Attack origin</span>
            <span className="panel-sub">geo-fingerprinted IPs · last 24h</span>
          </div>
          <div className="panel-body">
            <GeoList />
          </div>
        </div>
      </div>
    </div>
  );
}

function TimelineChart({ data, max }) {
  const w = 720, h = 180, padL = 28, padR = 8, padT = 8, padB = 22;
  const innerW = w - padL - padR, innerH = h - padT - padB;
  const bw = innerW / data.length;
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map(t => Math.round(max * t));

  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} style={{ display:'block' }}>
      {/* gridlines */}
      {yTicks.map((t, i) => {
        const y = padT + innerH - (i/4)*innerH;
        return <g key={i}>
          <line x1={padL} y1={y} x2={w-padR} y2={y} stroke="var(--border-soft)" strokeDasharray="2 3" />
          <text x={padL-6} y={y+3} textAnchor="end" fontSize="9" fill="var(--text-mute)" fontFamily="var(--font-mono)">{t}</text>
        </g>;
      })}
      {/* bars */}
      {data.map((d, i) => {
        const x = padL + i*bw + 2;
        const totalH = (d.attacks/max)*innerH;
        const decoyH = (d.honeypot/max)*innerH;
        const blockedH = (d.blocked/max)*innerH;
        const y0 = padT + innerH;
        return <g key={i}>
          <rect x={x} y={y0-totalH} width={bw-4} height={totalH-decoyH-blockedH > 0 ? totalH-decoyH-blockedH : 0} fill="var(--info)" opacity="0.5" />
          <rect x={x} y={y0-decoyH-blockedH} width={bw-4} height={decoyH} fill="var(--threat)" />
          <rect x={x} y={y0-blockedH} width={bw-4} height={blockedH} fill="var(--warn)" opacity="0.85" />
        </g>;
      })}
      {/* x labels */}
      {data.map((d, i) => i % 3 === 0 ? (
        <text key={i} x={padL + i*bw + bw/2} y={h-6} textAnchor="middle" fontSize="9" fill="var(--text-mute)" fontFamily="var(--font-mono)">{d.hour}</text>
      ) : null)}
      {/* legend */}
      <g transform={`translate(${w-220}, 10)`}>
        <rect width="10" height="10" fill="var(--info)" opacity="0.5" /><text x="14" y="9" fontSize="10" fill="var(--text-dim)">Detected</text>
        <rect x="70" width="10" height="10" fill="var(--threat)" /><text x="84" y="9" fontSize="10" fill="var(--text-dim)">Decoyed</text>
        <rect x="140" width="10" height="10" fill="var(--warn)" opacity="0.85" /><text x="154" y="9" fontSize="10" fill="var(--text-dim)">Blocked</text>
      </g>
    </svg>
  );
}

function TechniqueDonut() {
  const total = TECHNIQUE_DIST.reduce((s, d) => s + d.value, 0);
  const r = 56, cx = 80, cy = 80;
  let acc = 0;
  const arcs = TECHNIQUE_DIST.map(d => {
    const a0 = (acc/total) * Math.PI * 2 - Math.PI/2;
    acc += d.value;
    const a1 = (acc/total) * Math.PI * 2 - Math.PI/2;
    const large = (a1 - a0) > Math.PI ? 1 : 0;
    const x0 = cx + r*Math.cos(a0), y0 = cy + r*Math.sin(a0);
    const x1 = cx + r*Math.cos(a1), y1 = cy + r*Math.sin(a1);
    const r2 = 30;
    const x2 = cx + r2*Math.cos(a1), y2 = cy + r2*Math.sin(a1);
    const x3 = cx + r2*Math.cos(a0), y3 = cy + r2*Math.sin(a0);
    return { d: `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1} L ${x2} ${y2} A ${r2} ${r2} 0 ${large} 0 ${x3} ${y3} Z`, color: d.color, name: d.name, value: d.value };
  });
  return (
    <div style={{ display:'flex', alignItems:'center', gap: 16 }}>
      <svg width="160" height="160" viewBox="0 0 160 160">
        {arcs.map((a, i) => <path key={i} d={a.d} fill={a.color} />)}
        <text x="80" y="76" textAnchor="middle" fontSize="11" fill="var(--text-mute)" fontFamily="var(--font-mono)">TOTAL</text>
        <text x="80" y="92" textAnchor="middle" fontSize="18" fill="var(--text)" fontFamily="var(--font-mono)" fontWeight="500">{total*23}</text>
      </svg>
      <div style={{ flex: 1, display:'flex', flexDirection:'column', gap: 6 }}>
        {TECHNIQUE_DIST.map(d => (
          <div key={d.name} style={{ display:'flex', alignItems:'center', gap: 8, fontSize: 11 }}>
            <span style={{ width: 8, height: 8, background: d.color, borderRadius: 1 }} />
            <span style={{ flex: 1 }}>{d.name}</span>
            <span className="mono mute">{d.value}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function GeoList() {
  const data = [
    { country: 'Russia', code: 'RU', count: 421, pct: 28 },
    { country: 'China', code: 'CN', count: 318, pct: 21 },
    { country: 'Iran', code: 'IR', count: 187, pct: 12 },
    { country: 'North Korea', code: 'KP', count: 142, pct: 9 },
    { country: 'Brazil', code: 'BR', count: 88, pct: 6 },
    { country: 'Vietnam', code: 'VN', count: 71, pct: 5 },
    { country: 'Other (47)', code: '··', count: 287, pct: 19 },
  ];
  return (
    <div style={{ display:'flex', flexDirection:'column', gap: 10 }}>
      {data.map(d => (
        <div key={d.code} style={{ display:'flex', alignItems:'center', gap: 10 }}>
          <span className="mono" style={{ width: 24, color:'var(--text-mute)' }}>{d.code}</span>
          <span style={{ flex: 1, fontSize: 12 }}>{d.country}</span>
          <div style={{ width: 80, height: 4, background:'var(--bg-2)', borderRadius: 2 }}>
            <div style={{ width: `${d.pct*3}%`, height:'100%', background:'var(--threat)', opacity: 0.4 + d.pct/40, borderRadius: 2 }} />
          </div>
          <span className="mono" style={{ width: 40, textAlign:'right', fontSize: 11 }}>{d.count}</span>
        </div>
      ))}
    </div>
  );
}

window.OverviewView = OverviewView;
