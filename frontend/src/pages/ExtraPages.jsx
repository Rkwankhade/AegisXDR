// Login Page + Remaining Pages
import React, { useState } from 'react';
import { toast } from 'react-toastify';
import { login } from '../api';
import { useStore } from '../store';
import { scanCryptoThreats } from '../api';

// ─── Login ────────────────────────────────────────────────────────────────────
export function LoginPage() {
  const { setToken, setUser } = useStore();
  const [form, setForm] = useState({ username: 'admin', password: '', mfa: '' });
  const [loading, setLoading] = useState(false);
  const [glitch, setGlitch] = useState(false);

  const handleLogin = async () => {
    if (!form.password) return;
    setLoading(true);
    try {
      const r = await login(form.username, form.password, form.mfa || undefined);
      setToken(r.data.access_token);
      setUser({ username: r.data.username, role: r.data.role });
    } catch (e) {
      setGlitch(true);
      setTimeout(() => setGlitch(false), 600);
      toast.error(e.response?.data?.detail || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg-primary)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Animated background grid */}
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: 'linear-gradient(rgba(0,170,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,170,255,0.03) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
        pointerEvents: 'none',
      }} />

      <div style={{
        width: 420,
        position: 'relative',
        zIndex: 1,
        animation: glitch ? 'none' : undefined,
        ...(glitch ? { transform: 'translate(2px, -1px)' } : {}),
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 12,
            marginBottom: 10,
          }}>
            <div style={{
              width: 48, height: 48,
              background: 'linear-gradient(135deg, #00ff88, #00aaff)',
              borderRadius: 10,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 22, fontWeight: 700, color: '#000',
              fontFamily: 'var(--font-display)',
              boxShadow: '0 0 30px rgba(0,255,136,0.3)',
            }}>AX</div>
            <div style={{ textAlign: 'left' }}>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 28, fontWeight: 700, letterSpacing: '0.1em' }}>
                AEGIS<span style={{ color: 'var(--accent-blue)' }}>XDR</span>
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.2em' }}>SECURITY OPERATIONS PLATFORM</div>
            </div>
          </div>
        </div>

        {/* Login card */}
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 12,
          padding: 32,
          boxShadow: '0 0 60px rgba(0,0,0,0.5)',
        }}>
          <div style={{ marginBottom: 24, textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.2em', textTransform: 'uppercase' }}>
              AUTHENTICATION REQUIRED
            </div>
            <div className="cursor" style={{ fontSize: 11, color: 'var(--accent-green)', marginTop: 6 }}>
              Enter credentials to proceed
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Username</div>
              <input className="input" placeholder="username"
                value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))} />
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Password</div>
              <input className="input" type="password" placeholder="••••••••••••"
                value={form.password}
                onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                onKeyDown={e => e.key === 'Enter' && handleLogin()} />
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>MFA Code (optional)</div>
              <input className="input" placeholder="6-digit TOTP code"
                value={form.mfa}
                onChange={e => setForm(f => ({ ...f, mfa: e.target.value }))}
                onKeyDown={e => e.key === 'Enter' && handleLogin()} />
            </div>

            <button className="btn btn-green"
              style={{ width: '100%', justifyContent: 'center', padding: '12px', marginTop: 6, fontSize: 13, fontFamily: 'var(--font-display)', letterSpacing: '0.1em' }}
              onClick={handleLogin} disabled={loading}>
              {loading ? <span className="spin">↻</span> : '▶ AUTHENTICATE'}
            </button>
          </div>

          <div style={{ marginTop: 20, padding: '12px', background: 'var(--bg-secondary)', borderRadius: 6, fontSize: 11, color: 'var(--text-muted)' }}>
            Default: <span style={{ color: 'var(--accent-green)' }}>admin</span> / <span style={{ color: 'var(--accent-green)' }}>AegisXDR@2024!</span>
          </div>
        </div>

        {/* Module tags */}
        <div style={{ marginTop: 24, display: 'flex', flexWrap: 'wrap', gap: 6, justifyContent: 'center' }}>
          {['SIEM', 'XDR', 'SOAR', 'KMS', 'PKI', 'VAULT', 'UEBA', 'FORENSICS', 'PQC', 'BLOCKCHAIN'].map(tag => (
            <span key={tag} style={{ padding: '2px 8px', border: '1px solid var(--border)', borderRadius: 3, fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.1em' }}>{tag}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Incidents Page ───────────────────────────────────────────────────────────
import { correlateAlerts } from '../api';

export function IncidentsPage() {
  const [incidents, setIncidents] = useState([]);
  const [correlating, setCorrelating] = useState(false);

  const correlate = async () => {
    setCorrelating(true);
    try {
      const r = await correlateAlerts(30);
      setIncidents(r.data.incidents || []);
      toast.success(`${r.data.incidents?.length || 0} incidents created`);
    } catch { toast.error('Correlation failed'); }
    finally { setCorrelating(false); }
  };

  const sevColor = s => ({ critical: 'var(--accent-red)', high: 'var(--accent-orange)', medium: 'var(--accent-yellow)', low: 'var(--accent-green)' }[s] || 'var(--text-muted)');

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }} className="fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 700 }}>INCIDENT MANAGEMENT</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>SOAR · Auto-correlation · Alert grouping · Timeline</div>
        </div>
        <button className="btn btn-primary" onClick={correlate} disabled={correlating}>
          {correlating ? '↻ Correlating...' : '⚑ Auto-Correlate Alerts → Incidents'}
        </button>
      </div>

      {incidents.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <div style={{ fontSize: 40, opacity: 0.2, marginBottom: 12 }}>⚑</div>
          <div style={{ color: 'var(--text-muted)', fontSize: 12, marginBottom: 16 }}>
            No incidents yet. Click Auto-Correlate to group related alerts into incidents.
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Requires 3+ related alerts within a 30-minute window
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {incidents.map(inc => (
            <div key={inc.id} className="card" style={{ borderLeft: `3px solid ${sevColor(inc.severity)}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 6 }}>{inc.title}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8 }}>{inc.description}</div>
                  <div style={{ display: 'flex', gap: 12, fontSize: 11 }}>
                    <span style={{ color: sevColor(inc.severity), fontWeight: 600, textTransform: 'uppercase' }}>{inc.severity}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{inc.alert_ids?.length} alerts</span>
                    <span style={{ color: 'var(--text-muted)' }}>{inc.created_at && new Date(inc.created_at).toLocaleString()}</span>
                  </div>
                  {inc.mitre_techniques?.length > 0 && (
                    <div style={{ marginTop: 8, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {inc.mitre_techniques.map(t => (
                        <span key={t} style={{ padding: '2px 6px', background: 'rgba(124,58,237,0.15)', border: '1px solid rgba(124,58,237,0.25)', borderRadius: 3, fontSize: 10, color: 'var(--accent-purple)' }}>{t}</span>
                      ))}
                    </div>
                  )}
                </div>
                <span style={{ padding: '4px 10px', background: 'rgba(255,140,0,0.1)', border: '1px solid rgba(255,140,0,0.25)', borderRadius: 4, fontSize: 11, color: 'var(--accent-orange)' }}>
                  {inc.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Crypto Threat Detection Page ─────────────────────────────────────────────
export function CryptoDetectPage() {
  const [input, setInput] = useState(`[
  {
    "src_ip": "10.0.0.1",
    "dst_ip": "93.184.216.34",
    "tls_version": "TLSv1.0",
    "cipher_suite": "TLS_RSA_WITH_RC4_128_MD5",
    "cert_subject": "CN=example.com",
    "cert_issuer": "CN=example.com",
    "cert_valid": true
  },
  {
    "src_ip": "10.0.0.2",
    "dst_ip": "172.217.0.1",
    "tls_version": "TLSv1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "cert_subject": "CN=google.com",
    "cert_issuer": "CN=Google Trust Services",
    "cert_valid": true,
    "cert_expiry": "2026-01-01T00:00:00"
  }
]`);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const scan = async () => {
    setLoading(true);
    try {
      const events = JSON.parse(input);
      const r = await scanCryptoThreats(events);
      setResults(r.data);
    } catch (e) {
      toast.error(e.message || 'Scan failed');
    } finally { setLoading(false); }
  };

  const riskColor = r => r >= 0.8 ? 'var(--accent-red)' : r >= 0.5 ? 'var(--accent-orange)' : r >= 0.3 ? 'var(--accent-yellow)' : 'var(--accent-green)';
  const findingTypeColor = t => ({ deprecated_tls: 'var(--accent-red)', weak_cipher: 'var(--accent-red)', self_signed_cert: 'var(--accent-orange)', invalid_cert: 'var(--accent-red)', expired_cert: 'var(--accent-red)', expiring_soon: 'var(--accent-yellow)' }[t] || 'var(--text-muted)');

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }} className="fade-in">
      <div>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 700 }}>CRYPTOGRAPHIC THREAT DETECTION</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Weak TLS · Self-signed certs · Expired certs · Deprecated ciphers · Certificate spoofing</div>
      </div>

      <div className="card">
        <div style={{ marginBottom: 12, fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
          Network Events JSON
        </div>
        <textarea className="input" rows={12} value={input}
          onChange={e => setInput(e.target.value)}
          style={{ fontFamily: 'var(--font-mono)', resize: 'vertical', fontSize: 11 }} />
        <div style={{ marginTop: 10, display: 'flex', gap: 10 }}>
          <button className="btn btn-primary" onClick={scan} disabled={loading}>
            {loading ? '↻ Scanning...' : '◈ Scan for Crypto Threats'}
          </button>
        </div>
      </div>

      {results && (
        <>
          <div className="grid-4">
            {[
              { label: 'Scanned', value: results.total_scanned, color: 'blue' },
              { label: 'Compliant', value: results.compliant, color: 'green' },
              { label: 'Non-Compliant', value: results.non_compliant, color: 'red' },
              { label: 'Weak Ciphers', value: results.summary?.weak_ciphers, color: 'orange' },
            ].map(c => (
              <div key={c.label} className={`stat-card ${c.color}`}>
                <div className="stat-value" style={{ color: `var(--accent-${c.color})` }}>{c.value}</div>
                <div className="stat-label">{c.label}</div>
              </div>
            ))}
          </div>

          {results.results?.map((r, i) => r.findings?.length > 0 && (
            <div key={i} className="card" style={{ borderColor: 'rgba(255,51,102,0.2)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                  {r.src_ip || '?'} → {r.dst_ip || '?'}
                </span>
                <span style={{ color: riskColor(r.risk_score), fontFamily: 'var(--font-display)', fontWeight: 700 }}>
                  {r.risk_level?.toUpperCase()} ({(r.risk_score * 100).toFixed(0)}%)
                </span>
              </div>
              {r.findings?.map((f, j) => (
                <div key={j} style={{ padding: '8px 12px', marginBottom: 6, background: 'rgba(255,51,102,0.05)', border: '1px solid rgba(255,51,102,0.15)', borderRadius: 5 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: findingTypeColor(f.type), fontSize: 11, fontWeight: 600 }}>{f.type?.replace(/_/g, ' ').toUpperCase()}</span>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>{f.detail}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>→ {f.remediation}</div>
                </div>
              ))}
            </div>
          ))}
        </>
      )}
    </div>
  );
}

// ─── Multi-Tenant Page ────────────────────────────────────────────────────────
import { listTenants, createTenant } from '../api';

export function TenantsPage() {
  const [tenants, setTenants] = useState([]);
  const [form, setForm] = useState({ id: '', name: '' });

  const load = () => listTenants().then(r => setTenants(r.data.tenants || [])).catch(() => {});
  useEffect(() => { load(); }, []);

  const handleCreate = async () => {
    if (!form.id || !form.name) return toast.error('ID and name required');
    try {
      await createTenant(form.id, form.name);
      toast.success(`Tenant "${form.name}" created with dedicated crypto keys`);
      setForm({ id: '', name: '' });
      load();
    } catch (e) { toast.error(e.response?.data?.detail || 'Failed'); }
  };

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }} className="fade-in">
      <div>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 700 }}>MULTI-TENANT SECURITY</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Cryptographic isolation · Per-tenant keys · Isolated secrets/logs/storage</div>
      </div>

      <div style={{ padding: 16, background: 'rgba(0,170,255,0.06)', border: '1px solid rgba(0,170,255,0.2)', borderRadius: 6, fontSize: 11, color: 'var(--text-secondary)' }}>
        Each tenant gets: <span style={{ color: 'var(--accent-blue)' }}>dedicated AES-256-GCM tenant key</span> · isolated KMS namespace · separate secret store · partitioned audit logs · cryptographically isolated storage
      </div>

      <div className="card">
        <div style={{ marginBottom: 14, fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Create Tenant</div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
          <div style={{ flex: '0 1 140px' }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 5, textTransform: 'uppercase' }}>Tenant ID</div>
            <input className="input" placeholder="acme-corp" value={form.id} onChange={e => setForm(f => ({ ...f, id: e.target.value }))} />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 5, textTransform: 'uppercase' }}>Organization Name</div>
            <input className="input" placeholder="Acme Corporation" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          </div>
          <button className="btn btn-primary" onClick={handleCreate}>◉ Create Tenant</button>
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
          Tenants ({tenants.length})
        </div>
        {tenants.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>No tenants</div>
        ) : (
          <table className="table">
            <thead><tr><th>ID</th><th>Name</th><th>Tenant Key ID</th><th>Status</th><th>Created</th></tr></thead>
            <tbody>
              {tenants.map(t => (
                <tr key={t.id}>
                  <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)', fontSize: 12 }}>{t.id}</td>
                  <td style={{ fontWeight: 600 }}>{t.name}</td>
                  <td style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{t.tenant_key_id?.slice(0, 16) || 'N/A'}...</td>
                  <td><span style={{ color: t.active ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: 11, fontWeight: 600 }}>● {t.active ? 'ACTIVE' : 'INACTIVE'}</span></td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>{t.created_at && new Date(t.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// Need useEffect
import { useEffect } from 'react';
