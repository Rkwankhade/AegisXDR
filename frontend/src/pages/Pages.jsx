// Secrets Vault Page
import React, { useEffect, useState } from 'react';
import { listSecrets, storeSecret, revokeSecret, emergencyRevoke } from '../api';
import { toast } from 'react-toastify';

const SECRET_TYPES = ['api_key','db_password','certificate','jwt_secret','ssh_key','cloud_credential','oauth_token','custom'];

export function VaultPage() {
  const [secrets, setSecrets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ name: '', value: '', secret_type: 'api_key', lease_duration: 3600, auto_rotate: false });
  const [showValues, setShowValues] = useState({});

  const load = () => {
    setLoading(true);
    listSecrets().then(r => setSecrets(r.data.secrets || [])).finally(() => setLoading(false));
  };
  useEffect(load, []);

  const handleStore = async () => {
    if (!form.name || !form.value) return toast.error('Name and value required');
    try {
      await storeSecret(form);
      toast.success('Secret stored securely');
      setForm({ name: '', value: '', secret_type: 'api_key', lease_duration: 3600, auto_rotate: false });
      load();
    } catch (e) { toast.error(e.response?.data?.detail || 'Failed'); }
  };

  const handleRevoke = async (id) => {
    if (!window.confirm('Revoke this secret?')) return;
    try { await revokeSecret(id, 'manual'); toast.success('Secret revoked'); load(); }
    catch { toast.error('Failed'); }
  };

  const handleEmergencyRevoke = async () => {
    if (!window.confirm('⚠️ EMERGENCY: Revoke ALL secrets for this tenant?')) return;
    try { const r = await emergencyRevoke(); toast.error(`${r.data.revoked_count} secrets revoked`); load(); }
    catch { toast.error('Failed'); }
  };

  const typeColor = t => ({ api_key:'#00aaff', db_password:'#ff3366', certificate:'#00ff88', jwt_secret:'#7c3aed', ssh_key:'#ff8c00' }[t] || '#94a3b8');

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }} className="fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>SECRETS VAULT</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>HashiCorp Vault-like · Auto-rotation · Emergency revocation</div>
        </div>
        <button className="btn btn-danger" onClick={handleEmergencyRevoke}>⚠ Emergency Revoke All</button>
      </div>

      <div className="grid-4">
        {[
          { label: 'Total Secrets', value: secrets.length, color: 'blue' },
          { label: 'Active', value: secrets.filter(s=>!s.revoked).length, color: 'green' },
          { label: 'Revoked', value: secrets.filter(s=>s.revoked).length, color: 'red' },
          { label: 'Auto-Rotate', value: secrets.filter(s=>s.auto_rotate).length, color: 'orange' },
        ].map(c => (
          <div key={c.label} className={`stat-card ${c.color}`}>
            <div className="stat-value" style={{ color: `var(--accent-${c.color})` }}>{c.value}</div>
            <div className="stat-label">{c.label}</div>
          </div>
        ))}
      </div>

      <div className="card">
        <div style={{ marginBottom: 14, fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
          ⬟ Store New Secret
        </div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: '1 1 160px' }}>
            <FieldLabel>Name</FieldLabel>
            <input className="input" placeholder="e.g. prod-db-password"
              value={form.name} onChange={e => setForm(f=>({...f,name:e.target.value}))} />
          </div>
          <div style={{ flex: '2 1 200px' }}>
            <FieldLabel>Value (will be AES-encrypted)</FieldLabel>
            <input className="input" type="password" placeholder="secret value..."
              value={form.value} onChange={e => setForm(f=>({...f,value:e.target.value}))} />
          </div>
          <div style={{ flex: '1 1 140px' }}>
            <FieldLabel>Type</FieldLabel>
            <select className="input" value={form.secret_type}
              onChange={e => setForm(f=>({...f,secret_type:e.target.value}))}>
              {SECRET_TYPES.map(t=><option key={t}>{t}</option>)}
            </select>
          </div>
          <div style={{ flex: '0 1 110px' }}>
            <FieldLabel>Lease (sec)</FieldLabel>
            <input className="input" type="number" value={form.lease_duration}
              onChange={e => setForm(f=>({...f,lease_duration:+e.target.value}))} />
          </div>
          <label style={{ display:'flex', alignItems:'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)', cursor:'pointer' }}>
            <input type="checkbox" checked={form.auto_rotate}
              onChange={e => setForm(f=>({...f,auto_rotate:e.target.checked}))} />
            Auto-rotate
          </label>
          <button className="btn btn-green" onClick={handleStore}>+ Store Secret</button>
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            Stored Secrets ({secrets.length})
          </span>
        </div>
        {loading ? <div style={{ padding: 30, textAlign:'center', color:'var(--text-muted)' }}>Loading...</div> :
         secrets.length === 0 ? <div style={{ padding: 30, textAlign:'center', color:'var(--text-muted)' }}>No secrets stored yet</div> : (
          <table className="table">
            <thead><tr><th>Name</th><th>Type</th><th>Version</th><th>Status</th><th>Lease</th><th>Created</th><th>Actions</th></tr></thead>
            <tbody>
              {secrets.map(s => (
                <tr key={s.id}>
                  <td><div style={{ fontWeight: 600 }}>{s.name}</div><div style={{ fontSize:10, color:'var(--text-muted)' }}>{s.id?.slice(0,8)}...</div></td>
                  <td><span style={{ color: typeColor(s.secret_type), fontSize: 11, fontWeight: 600 }}>{s.secret_type}</span></td>
                  <td style={{ color:'var(--text-muted)', textAlign:'center' }}>v{s.version}</td>
                  <td><span style={{ color: s.revoked ? 'var(--accent-red)' : 'var(--accent-green)', fontSize: 11, fontWeight: 600 }}>● {s.revoked ? 'REVOKED' : 'ACTIVE'}</span></td>
                  <td style={{ color:'var(--text-muted)', fontSize: 11 }}>{s.lease_duration}s {s.auto_rotate && <span style={{ color:'var(--accent-orange)' }}>↺</span>}</td>
                  <td style={{ color:'var(--text-muted)', fontSize: 11 }}>{s.created_at ? new Date(s.created_at).toLocaleDateString() : '-'}</td>
                  <td>
                    {!s.revoked && (
                      <button className="btn btn-danger" style={{ padding:'4px 10px', fontSize: 10 }}
                        onClick={() => handleRevoke(s.id)}>✕ Revoke</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── PKI Page ──────────────────────────────────────────────────────────────────
import { createRootCA, createIntermediateCA, issueCertificate, getCRL, ocspCheck } from '../api';

export function PKIPage() {
  const [certs, setCerts] = useState([]);
  const [crl, setCRL] = useState([]);
  const [form, setForm] = useState({ common_name: '', cert_type: 'server', valid_days: 365 });
  const [loading, setLoading] = useState(false);
  const [initStatus, setInitStatus] = useState(null);
  const [ocspId, setOcspId] = useState('');
  const [ocspResult, setOcspResult] = useState(null);

  const initPKI = async () => {
    setLoading(true);
    try {
      await createRootCA('AegisXDR');
      await createIntermediateCA('AegisXDR');
      setInitStatus({ success: true, message: 'Root CA + Intermediate CA initialized' });
      toast.success('PKI initialized');
    } catch (e) { setInitStatus({ success: false, message: e.response?.data?.detail || 'Failed' }); }
    finally { setLoading(false); }
  };

  const issueCert = async () => {
    if (!form.common_name) return toast.error('Common name required');
    setLoading(true);
    try {
      const r = await issueCertificate(form);
      setCerts(c => [r.data, ...c]);
      toast.success(`Certificate issued: ${form.common_name}`);
      setForm({ common_name: '', cert_type: 'server', valid_days: 365 });
    } catch (e) { toast.error(e.response?.data?.detail || 'Issue failed'); }
    finally { setLoading(false); }
  };

  const loadCRL = async () => {
    const r = await getCRL();
    setCRL(r.data.crl || []);
  };

  const checkOCSP = async () => {
    if (!ocspId) return;
    const r = await ocspCheck(ocspId);
    setOcspResult(r.data);
  };

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }} className="fade-in">
      <div>
        <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>PKI INFRASTRUCTURE</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Root CA → Intermediate CA → End-Entity Certs · X.509 · OCSP</div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div style={{ marginBottom: 12, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>⬠ Initialize PKI Chain</div>
          <div style={{ fontSize: 12, color:'var(--text-secondary)', marginBottom: 14, lineHeight: 1.7 }}>
            Creates a 3-tier PKI hierarchy:<br />
            <span style={{ color:'var(--accent-blue)' }}>Root CA</span> → <span style={{ color:'var(--accent-cyan)' }}>Intermediate CA</span> → <span style={{ color:'var(--accent-green)' }}>End-Entity Certs</span>
          </div>
          <button className="btn btn-primary" onClick={initPKI} disabled={loading}>
            {loading ? '↻ Initializing...' : '⬠ Initialize PKI'}
          </button>
          {initStatus && (
            <div style={{ marginTop: 12, padding: 10, borderRadius: 6, background: initStatus.success ? 'rgba(0,255,136,0.08)' : 'rgba(255,51,102,0.08)', border: `1px solid ${initStatus.success ? 'rgba(0,255,136,0.2)' : 'rgba(255,51,102,0.2)'}`, fontSize: 12, color: initStatus.success ? 'var(--accent-green)' : 'var(--accent-red)' }}>
              {initStatus.message}
            </div>
          )}
        </div>

        <div className="card">
          <div style={{ marginBottom: 12, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>◎ OCSP Check</div>
          <div style={{ display:'flex', gap: 8 }}>
            <input className="input" placeholder="Certificate ID..."
              value={ocspId} onChange={e => setOcspId(e.target.value)} />
            <button className="btn btn-ghost" onClick={checkOCSP}>Check</button>
          </div>
          {ocspResult && (
            <div style={{ marginTop: 12, padding: 10, borderRadius: 6, background: 'var(--bg-secondary)', border: '1px solid var(--border)', fontSize: 12 }}>
              <span style={{ color: ocspResult.status === 'good' ? 'var(--accent-green)' : ocspResult.status === 'revoked' ? 'var(--accent-red)' : 'var(--accent-orange)' }}>
                ● {ocspResult.status?.toUpperCase()}
              </span>
              {ocspResult.reason && <div style={{ color:'var(--text-muted)', marginTop: 4 }}>Reason: {ocspResult.reason}</div>}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div style={{ marginBottom: 14, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>◈ Issue Certificate</div>
        <div style={{ display:'flex', gap: 12, flexWrap:'wrap', alignItems:'flex-end' }}>
          <div style={{ flex:'2 1 200px' }}>
            <FieldLabel>Common Name (CN)</FieldLabel>
            <input className="input" placeholder="e.g. api.internal.example.com"
              value={form.common_name} onChange={e => setForm(f=>({...f,common_name:e.target.value}))} />
          </div>
          <div style={{ flex:'1 1 130px' }}>
            <FieldLabel>Type</FieldLabel>
            <select className="input" value={form.cert_type}
              onChange={e => setForm(f=>({...f,cert_type:e.target.value}))}>
              <option value="server">Server</option>
              <option value="client">Client</option>
            </select>
          </div>
          <div style={{ flex:'0 1 110px' }}>
            <FieldLabel>Valid (days)</FieldLabel>
            <input className="input" type="number" value={form.valid_days}
              onChange={e => setForm(f=>({...f,valid_days:+e.target.value}))} />
          </div>
          <button className="btn btn-green" onClick={issueCert} disabled={loading}>Issue Certificate</button>
          <button className="btn btn-ghost" onClick={loadCRL}>Load CRL</button>
        </div>
      </div>

      {certs.length > 0 && (
        <div className="card" style={{ padding: 0 }}>
          <div style={{ padding:'14px 20px', borderBottom:'1px solid var(--border)', fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>
            Issued Certificates ({certs.length})
          </div>
          <table className="table">
            <thead><tr><th>Common Name</th><th>Type</th><th>Serial</th><th>Not After</th><th>ID</th></tr></thead>
            <tbody>
              {certs.map(c => (
                <tr key={c.id}>
                  <td style={{ fontWeight:600, color:'var(--accent-blue)' }}>{c.common_name}</td>
                  <td><span style={{ fontSize:11, color: c.cert_type==='server' ? 'var(--accent-purple)' : 'var(--accent-cyan)' }}>{c.cert_type}</span></td>
                  <td style={{ fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-muted)' }}>{c.serial?.slice(0,16)}...</td>
                  <td style={{ fontSize:11, color:'var(--text-muted)' }}>{c.not_after ? new Date(c.not_after).toLocaleDateString() : '-'}</td>
                  <td style={{ fontSize:10, color:'var(--text-muted)' }}>{c.id?.slice(0,8)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {crl.length > 0 && (
        <div className="card">
          <div style={{ marginBottom: 12, fontSize: 11, color:'var(--accent-red)', textTransform:'uppercase', letterSpacing:'0.1em' }}>Certificate Revocation List ({crl.length})</div>
          {crl.map((r,i) => (
            <div key={i} style={{ padding:'8px 12px', marginBottom: 6, background:'rgba(255,51,102,0.06)', border:'1px solid rgba(255,51,102,0.15)', borderRadius: 6, fontSize: 11 }}>
              <span style={{ color:'var(--accent-red)' }}>✕ {r.cert_id?.slice(0,8)}...</span>
              <span style={{ color:'var(--text-muted)', marginLeft: 12 }}>Reason: {r.reason}</span>
              <span style={{ color:'var(--text-muted)', marginLeft: 12 }}>{r.revoked_at && new Date(r.revoked_at).toLocaleDateString()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Alerts Page ───────────────────────────────────────────────────────────────
import { getAlerts, updateAlert, correlateAlerts, ingestEvents } from '../api';

export function AlertsPage() {
  const [alerts, setAlerts]     = useState([]);
  const [loading, setLoading]   = useState(true);
  const [filter, setFilter]     = useState({ status: '', severity: '' });
  const [selected, setSelected] = useState(null);

  const load = () => {
    setLoading(true);
    getAlerts(filter.status || undefined, filter.severity || undefined)
      .then(r => setAlerts(r.data.alerts || []))
      .finally(() => setLoading(false));
  };
  useEffect(load, [filter]);

  const handleCorrelate = async () => {
    const r = await correlateAlerts();
    toast.success(`${r.data.incidents?.length || 0} incidents created`);
  };

  const injectTestEvent = async () => {
    const testEvents = [
      { event_type: 'auth_failure', user_id: 'user123', ip: '192.168.1.50', source: 'test' },
      { event_type: 'auth_failure', user_id: 'user123', ip: '10.0.0.5', source: 'test' },
      { event_type: 'auth_failure', user_id: 'user123', ip: '172.16.0.1', source: 'test' },
      { event_type: 'auth_failure', user_id: 'user123', ip: '192.168.2.1', source: 'test' },
      { event_type: 'auth_failure', user_id: 'user123', ip: '10.0.1.1', source: 'test' },
      { event_type: 'process_injection', pid: 1234, target_pid: 5678, source: 'endpoint' },
    ];
    const r = await ingestEvents(testEvents);
    toast.success(`${r.data.alerts_generated} alerts generated`);
    load();
  };

  const severityBadge = sev => ({
    critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium',
    low: 'badge-low', info: 'badge-info'
  }[sev] || 'badge-info');

  return (
    <div style={{ display:'flex', height:'100%' }}>
      <div style={{ flex: 1, padding: 24, display:'flex', flexDirection:'column', gap: 16, overflow:'auto' }} className="fade-in">
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <div>
            <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>ALERTS <span style={{ color:'var(--accent-red)' }}>◈</span></div>
            <div style={{ fontSize: 11, color:'var(--text-muted)' }}>SIEM correlation · Real-time detection · MITRE ATT&CK</div>
          </div>
          <div style={{ display:'flex', gap: 8 }}>
            <button className="btn btn-ghost" onClick={injectTestEvent}>⚡ Inject Test Events</button>
            <button className="btn btn-primary" onClick={handleCorrelate}>◈ Correlate → Incidents</button>
            <button className="btn btn-ghost" onClick={load}>↻</button>
          </div>
        </div>

        <div style={{ display:'flex', gap: 10 }}>
          <select className="input" style={{ width: 140 }} value={filter.severity}
            onChange={e => setFilter(f=>({...f,severity:e.target.value}))}>
            <option value="">All Severities</option>
            {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="input" style={{ width: 130 }} value={filter.status}
            onChange={e => setFilter(f=>({...f,status:e.target.value}))}>
            <option value="">All Status</option>
            {['open','in_progress','resolved','false_positive'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <span style={{ marginLeft: 'auto', fontSize: 11, color:'var(--text-muted)', alignSelf:'center' }}>
            {alerts.length} alerts
          </span>
        </div>

        <div className="card" style={{ padding: 0, flex: 1 }}>
          {loading ? <div style={{ padding:40, textAlign:'center', color:'var(--text-muted)' }}>Loading...</div> :
           alerts.length === 0 ? (
            <div style={{ padding:60, textAlign:'center', color:'var(--text-muted)' }}>
              <div style={{ fontSize: 40, marginBottom: 12, opacity: 0.3 }}>◈</div>
              <div>No alerts. Click "Inject Test Events" to generate some.</div>
            </div>
          ) : (
            <table className="table">
              <thead><tr><th>Severity</th><th>Title</th><th>Source</th><th>MITRE</th><th>Status</th><th>Time</th></tr></thead>
              <tbody>
                {alerts.map(alert => (
                  <tr key={alert.id} style={{ cursor:'pointer' }}
                    onClick={() => setSelected(alert)}>
                    <td><span className={`badge ${severityBadge(alert.severity)}`}>{alert.severity}</span></td>
                    <td>
                      <div style={{ fontWeight:600, color:'var(--text-primary)' }}>{alert.title}</div>
                      <div style={{ fontSize:10, color:'var(--text-muted)' }}>{alert.id?.slice(0,8)}...</div>
                    </td>
                    <td style={{ color:'var(--text-secondary)', fontSize: 11 }}>{alert.source}</td>
                    <td>
                      {(alert.mitre_techniques||[]).map(t => (
                        <span key={t} style={{ display:'inline-block', margin:'1px 2px', padding:'2px 6px', background:'rgba(124,58,237,0.15)', border:'1px solid rgba(124,58,237,0.25)', borderRadius: 3, fontSize: 10, color:'var(--accent-purple)' }}>{t}</span>
                      ))}
                    </td>
                    <td>
                      <span style={{ fontSize:11, color: alert.status==='open' ? 'var(--accent-orange)' : alert.status==='resolved' ? 'var(--accent-green)' : 'var(--text-muted)', fontWeight: 600 }}>
                        {alert.status}
                      </span>
                    </td>
                    <td style={{ color:'var(--text-muted)', fontSize: 11 }}>{alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Alert detail panel */}
      {selected && (
        <div style={{ width: 360, borderLeft:'1px solid var(--border)', background:'var(--bg-secondary)', padding: 20, overflow:'auto' }}>
          <div style={{ display:'flex', justifyContent:'space-between', marginBottom: 16 }}>
            <span style={{ fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>Alert Detail</span>
            <button onClick={() => setSelected(null)} style={{ background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer', fontSize: 16 }}>✕</button>
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap: 12 }}>
            <div><span className={`badge ${severityBadge(selected.severity)}`}>{selected.severity}</span></div>
            <div style={{ fontWeight:700, fontSize: 14, color:'var(--text-primary)' }}>{selected.title}</div>
            <div style={{ fontSize: 11, color:'var(--text-secondary)' }}>{selected.description}</div>
            <DetailRow label="ID" value={selected.id} mono />
            <DetailRow label="Source" value={selected.source} />
            <DetailRow label="Status" value={selected.status} />
            <DetailRow label="Risk Score" value={selected.risk_score?.toFixed(3)} />
            <DetailRow label="Created" value={selected.created_at && new Date(selected.created_at).toLocaleString()} />
            {(selected.mitre_techniques||[]).length > 0 && (
              <div>
                <div style={{ fontSize: 10, color:'var(--text-muted)', marginBottom: 6, textTransform:'uppercase' }}>MITRE ATT&CK</div>
                {selected.mitre_techniques.map((t,i) => (
                  <div key={i} style={{ padding:'4px 8px', margin:'2px 0', background:'rgba(124,58,237,0.1)', border:'1px solid rgba(124,58,237,0.2)', borderRadius: 4, fontSize: 11, color:'var(--accent-purple)' }}>
                    {t} — {selected.mitre_descriptions?.[i] || ''}
                  </div>
                ))}
              </div>
            )}
            <div style={{ display:'flex', gap: 8, marginTop: 8 }}>
              <button className="btn btn-green" style={{ flex:1, fontSize: 11 }}
                onClick={async () => { await updateAlert(selected.id, { status:'resolved' }); toast.success('Resolved'); load(); setSelected(null); }}>
                ✓ Resolve
              </button>
              <button className="btn btn-ghost" style={{ flex:1, fontSize: 11 }}
                onClick={async () => { await updateAlert(selected.id, { false_positive: true, status:'resolved' }); toast.info('Marked FP'); load(); setSelected(null); }}>
                FP
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Zero Trust Page ───────────────────────────────────────────────────────────
import { evaluateAccess } from '../api';

export function ZeroTrustPage() {
  const [form, setForm] = useState({
    user_id: 'user-001', device_fingerprint: 'fp-abc123',
    ip_address: '192.168.1.10', resource: '/api/sensitive-data',
    action: 'READ', context: '{}'
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const evaluate = async () => {
    setLoading(true);
    try {
      let ctx = {};
      try { ctx = JSON.parse(form.context); } catch {}
      const r = await evaluateAccess({ ...form, context: ctx });
      setResult(r.data);
    } catch (e) { toast.error(e.response?.data?.detail || 'Evaluation failed'); }
    finally { setLoading(false); }
  };

  const trustColor = lvl => ({ high:'var(--accent-green)', medium:'var(--accent-orange)', low:'var(--accent-red)', none:'#666' }[lvl] || '#666');

  return (
    <div style={{ padding: 24, display:'flex', flexDirection:'column', gap: 20 }} className="fade-in">
      <div>
        <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>ZERO TRUST ENGINE</div>
        <div style={{ fontSize: 11, color:'var(--text-muted)' }}>Never trust, always verify · Device + User + Location + Behavior</div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div style={{ marginBottom: 14, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>Access Evaluation</div>
          <div style={{ display:'flex', flexDirection:'column', gap: 10 }}>
            {[
              { key:'user_id', label:'User ID', placeholder:'user-001' },
              { key:'device_fingerprint', label:'Device Fingerprint', placeholder:'fp-abc123def456' },
              { key:'ip_address', label:'IP Address', placeholder:'192.168.1.10' },
              { key:'resource', label:'Resource', placeholder:'/api/sensitive-data' },
              { key:'action', label:'Action', placeholder:'READ / WRITE / DELETE' },
            ].map(f => (
              <div key={f.key}>
                <FieldLabel>{f.label}</FieldLabel>
                <input className="input" placeholder={f.placeholder}
                  value={form[f.key]} onChange={e => setForm(p=>({...p,[f.key]:e.target.value}))} />
              </div>
            ))}
            <div>
              <FieldLabel>Context (JSON)</FieldLabel>
              <textarea className="input" rows={3} placeholder='{"mfa_verified": true, "vpn": false}'
                value={form.context} onChange={e => setForm(p=>({...p,context:e.target.value}))}
                style={{ resize:'vertical' }} />
            </div>
            <button className="btn btn-primary" onClick={evaluate} disabled={loading}>
              {loading ? '↻ Evaluating...' : '◆ Evaluate Access'}
            </button>
          </div>
        </div>

        <div>
          {result ? (
            <div style={{ display:'flex', flexDirection:'column', gap: 14 }}>
              <div className="card" style={{ borderColor: result.granted ? 'rgba(0,255,136,0.3)' : 'rgba(255,51,102,0.3)', background: result.granted ? 'rgba(0,255,136,0.04)' : 'rgba(255,51,102,0.04)' }}>
                <div style={{ fontFamily:'var(--font-display)', fontSize: 28, fontWeight: 700, color: result.granted ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                  {result.granted ? '✓ ACCESS GRANTED' : '✕ ACCESS DENIED'}
                </div>
                {result.requires_mfa && <div style={{ fontSize: 11, color:'var(--accent-orange)', marginTop: 6 }}>⚠ MFA Required for full access</div>}
                <div style={{ marginTop: 14 }}>
                  <div style={{ fontSize: 11, color:'var(--text-muted)', marginBottom: 6 }}>Trust Level</div>
                  <div style={{ display:'flex', alignItems:'center', gap: 10 }}>
                    <span style={{ fontFamily:'var(--font-display)', fontSize: 22, fontWeight: 700, color: trustColor(result.trust_level) }}>
                      {result.trust_level?.toUpperCase()}
                    </span>
                    <span style={{ fontSize: 12, color:'var(--text-muted)' }}>{(result.trust_score * 100).toFixed(1)}% trust · {(result.risk_score * 100).toFixed(1)}% risk</span>
                  </div>
                </div>
              </div>

              <div className="card">
                <div style={{ fontSize: 11, color:'var(--text-muted)', marginBottom: 10, textTransform:'uppercase', letterSpacing:'0.1em' }}>Signal Breakdown</div>
                {result.signals && Object.entries(result.signals).map(([k,v]) => (
                  <div key={k} style={{ marginBottom: 8 }}>
                    <div style={{ display:'flex', justifyContent:'space-between', marginBottom: 3 }}>
                      <span style={{ fontSize: 11, color:'var(--text-secondary)', textTransform:'capitalize' }}>{k.replace(/_/g,' ')}</span>
                      <span style={{ fontSize: 11, color:(v>0.6)?'var(--accent-green)':(v>0.3)?'var(--accent-orange)':'var(--accent-red)' }}>{(v*100).toFixed(0)}%</span>
                    </div>
                    <div className="progress"><div className="progress-bar" style={{ width:`${v*100}%`, background:(v>0.6)?'var(--accent-green)':(v>0.3)?'var(--accent-orange)':'var(--accent-red)' }} /></div>
                  </div>
                ))}
              </div>

              {result.risk_factors?.length > 0 && (
                <div className="card" style={{ borderColor:'rgba(255,51,102,0.2)' }}>
                  <div style={{ fontSize: 11, color:'var(--accent-red)', marginBottom: 8, textTransform:'uppercase' }}>Risk Factors</div>
                  {result.risk_factors.map((f,i) => <div key={i} style={{ fontSize: 11, color:'var(--text-secondary)', padding:'3px 0' }}>⚠ {f}</div>)}
                </div>
              )}

              {result.recommendations?.length > 0 && (
                <div className="card" style={{ borderColor:'rgba(255,215,0,0.2)' }}>
                  <div style={{ fontSize: 11, color:'var(--accent-yellow)', marginBottom: 8, textTransform:'uppercase' }}>Recommendations</div>
                  {result.recommendations.map((r,i) => <div key={i} style={{ fontSize: 11, color:'var(--text-secondary)', padding:'3px 0' }}>→ {r}</div>)}
                </div>
              )}
            </div>
          ) : (
            <div className="card" style={{ height: '100%', display:'flex', alignItems:'center', justifyContent:'center', flexDirection:'column', gap: 12, color:'var(--text-muted)' }}>
              <div style={{ fontSize: 40, opacity: 0.2 }}>◆</div>
              <div style={{ fontSize: 12 }}>Fill in access request details and click Evaluate</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Shared helpers ─────────────────────────────────────────────────────────────
function FieldLabel({ children }) {
  return <div style={{ fontSize: 10, color:'var(--text-muted)', marginBottom: 5, textTransform:'uppercase', letterSpacing:'0.08em' }}>{children}</div>;
}

function DetailRow({ label, value, mono }) {
  return (
    <div style={{ display:'flex', justifyContent:'space-between', gap: 8 }}>
      <span style={{ fontSize: 11, color:'var(--text-muted)', flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 11, color:'var(--text-secondary)', fontFamily: mono ? 'var(--font-mono)' : undefined, textAlign:'right', wordBreak:'break-all' }}>{value || '—'}</span>
    </div>
  );
}
