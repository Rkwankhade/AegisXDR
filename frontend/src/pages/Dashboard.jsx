// Dashboard — Main overview
import React, { useEffect, useState } from 'react';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { getDashboardStats, getSiemStats, getBlockchainStats, getHealth } from '../api';

const SEVERITY_COLORS = {
  critical: '#ff3366', high: '#ff8c00', medium: '#ffd700', low: '#00ff88', info: '#00aaff'
};

const mockTrend = Array.from({ length: 24 }, (_, i) => ({
  hour: `${i}:00`,
  alerts: Math.floor(Math.random() * 20),
  events: Math.floor(Math.random() * 200),
}));

export default function Dashboard() {
  const [stats, setStats]   = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getDashboardStats(), getHealth()])
      .then(([s, h]) => { setStats(s.data); setHealth(h.data); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <LoadingSkeleton />;

  const severityData = stats?.alerts?.by_severity
    ? Object.entries(stats.alerts.by_severity).map(([k, v]) => ({ name: k, value: v, color: SEVERITY_COLORS[k] || '#666' }))
    : [];

  const moduleStatuses = health?.modules || {};

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }} className="fade-in">

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 700, color: 'var(--text-primary)' }}>
            THREAT <span style={{ color: 'var(--accent-green)' }}>OPERATIONS</span> CENTER
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            {new Date().toLocaleString()} · All systems nominal
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <span className="dot dot-green pulse" />
          <span style={{ fontSize: 11, color: 'var(--accent-green)' }}>LIVE</span>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid-5">
        <StatCard label="TOTAL ALERTS" value={stats?.alerts?.total ?? 0} color="red"
          sub={`${stats?.alerts?.open ?? 0} open`} icon="◈" />
        <StatCard label="CRYPTO KEYS" value={stats?.keys?.total ?? 0} color="blue"
          sub={`${stats?.keys?.active ?? 0} active`} icon="⬢" />
        <StatCard label="SECRETS" value={stats?.secrets?.total ?? 0} color="purple"
          sub={`${stats?.secrets?.active ?? 0} active`} icon="⬟" />
        <StatCard label="IOC INDICATORS" value={stats?.threat_indicators ?? 0} color="orange"
          sub="threat intel" icon="◉" />
        <StatCard label="CHAIN BLOCKS" value={stats?.blockchain_blocks ?? 0} color="green"
          sub={stats?.blockchain_valid ? '✓ valid' : '⚠ tampered'} icon="⬡" />
      </div>

      {/* Charts row */}
      <div className="grid-2">
        <div className="card">
          <div style={{ marginBottom: 12, fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            Alert Trend (24h)
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={mockTrend}>
              <defs>
                <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff3366" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ff3366" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="hour" tick={{ fill: '#475569', fontSize: 9 }} tickLine={false} />
              <YAxis tick={{ fill: '#475569', fontSize: 9 }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', fontSize: 11 }} />
              <Area type="monotone" dataKey="alerts" stroke="#ff3366" fill="url(#alertGrad)" strokeWidth={1.5} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div style={{ marginBottom: 12, fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            Alerts by Severity
          </div>
          {severityData.length > 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie data={severityData} cx="50%" cy="50%" innerRadius={40} outerRadius={60}
                    dataKey="value" strokeWidth={0}>
                    {severityData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {severityData.map(d => (
                  <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color }} />
                    <span style={{ fontSize: 11, color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{d.name}</span>
                    <span style={{ fontSize: 11, color: 'var(--text-primary)', fontWeight: 600, marginLeft: 'auto' }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
              No alerts yet — system clean
            </div>
          )}
        </div>
      </div>

      {/* Module status grid */}
      <div className="card">
        <div style={{ marginBottom: 14, fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
          Module Status
        </div>
        <div className="grid-4" style={{ gap: 10 }}>
          {Object.entries(moduleStatuses).map(([mod, status]) => (
            <div key={mod} style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '8px 12px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
            }}>
              <span className={`dot ${status === 'active' ? 'dot-green' : status === 'not_initialized' ? 'dot-orange' : 'dot-red'}`} />
              <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{mod.replace(/_/g, ' ')}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Quick actions */}
      <div className="card">
        <div style={{ marginBottom: 14, fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
          Quick Actions
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
          {[
            { label: '⬢ Generate Key', color: 'btn-primary' },
            { label: '⬟ Store Secret', color: 'btn-green' },
            { label: '⬠ Issue Certificate', color: 'btn-ghost' },
            { label: '◉ Add IOC', color: 'btn-ghost' },
            { label: '⬡ Verify Chain', color: 'btn-ghost' },
            { label: '◈ Correlate Alerts', color: 'btn-ghost' },
          ].map(a => (
            <button key={a.label} className={`btn ${a.color}`} style={{ fontSize: 11 }}>
              {a.label}
            </button>
          ))}
        </div>
      </div>

    </div>
  );
}

function StatCard({ label, value, color, sub, icon }) {
  return (
    <div className={`stat-card ${color}`}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="stat-value" style={{
            color: color === 'red' ? 'var(--accent-red)' :
                   color === 'blue' ? 'var(--accent-blue)' :
                   color === 'green' ? 'var(--accent-green)' :
                   color === 'orange' ? 'var(--accent-orange)' : 'var(--accent-purple)'
          }}>{value}</div>
          <div className="stat-label">{label}</div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>{sub}</div>
        </div>
        <span style={{ fontSize: 22, opacity: 0.3 }}>{icon}</span>
      </div>
    </div>
  );
}

function LoadingSkeleton() {
  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="grid-5">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="skeleton" style={{ height: 90, borderRadius: 10 }} />
        ))}
      </div>
      <div className="grid-2">
        {[...Array(2)].map((_, i) => (
          <div key={i} className="skeleton" style={{ height: 220, borderRadius: 10 }} />
        ))}
      </div>
    </div>
  );
}
