// KMS — Enterprise Key Management System
import React, { useEffect, useState } from 'react';
import { listKeys, createKey, rotateKey, revokeKey } from '../api';
import { toast } from 'react-toastify';

const ALGORITHMS = ['AES-256-GCM', 'RSA-4096', 'ECC-P256', 'ECC-X25519'];
const PURPOSES   = ['encrypt', 'sign', 'exchange', 'tenant_encryption'];

export default function KMSPage() {
  const [keys, setKeys]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm]     = useState({ name: '', algorithm: 'AES-256-GCM', purpose: 'encrypt', rotation_days: 90 });
  const [creating, setCreating] = useState(false);

  const load = () => {
    setLoading(true);
    listKeys().then(r => setKeys(r.data.keys || [])).finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleCreate = async () => {
    if (!form.name) return toast.error('Key name required');
    setCreating(true);
    try {
      await createKey(form);
      toast.success(`Key "${form.name}" created`);
      setForm({ name: '', algorithm: 'AES-256-GCM', purpose: 'encrypt', rotation_days: 90 });
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Failed to create key');
    } finally { setCreating(false); }
  };

  const handleRotate = async (id) => {
    try {
      await rotateKey(id);
      toast.success('Key rotated');
      load();
    } catch (e) { toast.error('Rotation failed'); }
  };

  const handleRevoke = async (id) => {
    if (!window.confirm('Revoke this key? This cannot be undone.')) return;
    try {
      await revokeKey(id, 'manual');
      toast.success('Key revoked');
      load();
    } catch (e) { toast.error('Revocation failed'); }
  };

  const statusColor = s => s === 'active' ? 'var(--accent-green)' : s === 'rotated' ? 'var(--accent-orange)' : 'var(--accent-red)';
  const algColor = a => a.startsWith('AES') ? 'var(--accent-blue)' : a.startsWith('RSA') ? 'var(--accent-purple)' : 'var(--accent-cyan)';

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }} className="fade-in">
      <PageHeader title="KEY MANAGEMENT SYSTEM" sub="AES-256-GCM · RSA-4096 · ECC (P-256, X25519)" />

      {/* Info cards */}
      <div className="grid-4">
        {[
          { label: 'Total Keys',  value: keys.length,                                color: 'blue' },
          { label: 'Active',      value: keys.filter(k=>k.status==='active').length,   color: 'green' },
          { label: 'Rotated',     value: keys.filter(k=>k.status==='rotated').length,  color: 'orange' },
          { label: 'Revoked',     value: keys.filter(k=>k.status==='revoked').length,  color: 'red' },
        ].map(c => (
          <div key={c.label} className={`stat-card ${c.color}`}>
            <div className="stat-value" style={{ color: `var(--accent-${c.color})` }}>{c.value}</div>
            <div className="stat-label">{c.label}</div>
          </div>
        ))}
      </div>

      {/* Generate key form */}
      <div className="card">
        <div style={{ marginBottom: 14, fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
          ⬢ Generate New Key
        </div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: '1 1 160px' }}>
            <Label>Key Name</Label>
            <input className="input" placeholder="e.g. db-encryption-key"
              value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          </div>
          <div style={{ flex: '1 1 140px' }}>
            <Label>Algorithm</Label>
            <select className="input" value={form.algorithm}
              onChange={e => setForm(f => ({ ...f, algorithm: e.target.value }))}>
              {ALGORITHMS.map(a => <option key={a}>{a}</option>)}
            </select>
          </div>
          <div style={{ flex: '1 1 130px' }}>
            <Label>Purpose</Label>
            <select className="input" value={form.purpose}
              onChange={e => setForm(f => ({ ...f, purpose: e.target.value }))}>
              {PURPOSES.map(p => <option key={p}>{p}</option>)}
            </select>
          </div>
          <div style={{ flex: '0 1 120px' }}>
            <Label>Rotation (days)</Label>
            <input className="input" type="number" value={form.rotation_days}
              onChange={e => setForm(f => ({ ...f, rotation_days: +e.target.value }))} />
          </div>
          <button className="btn btn-green" onClick={handleCreate} disabled={creating}>
            {creating ? <span className="spin">↻</span> : '+'} Generate Key
          </button>
        </div>
      </div>

      {/* Key table */}
      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            Cryptographic Keys ({keys.length})
          </span>
          <button className="btn btn-ghost" style={{ fontSize: 10 }} onClick={load}>↻ Refresh</button>
        </div>
        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading keys...</div>
        ) : keys.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
            No keys yet. Generate your first key above.
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Algorithm</th>
                <th>Purpose</th>
                <th>Status</th>
                <th>Version</th>
                <th>Created</th>
                <th>Next Rotation</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map(key => (
                <tr key={key.id}>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{key.name}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {key.id?.slice(0, 8)}...
                    </div>
                  </td>
                  <td>
                    <span style={{ color: algColor(key.algorithm), fontSize: 11, fontWeight: 600 }}>
                      {key.algorithm}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{key.purpose}</td>
                  <td>
                    <span style={{ color: statusColor(key.status), fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>
                      ● {key.status}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)', textAlign: 'center' }}>v{key.version}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                    {key.created_at ? new Date(key.created_at).toLocaleDateString() : '-'}
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                    {key.next_rotation ? new Date(key.next_rotation).toLocaleDateString() : '-'}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 6 }}>
                      {key.status === 'active' && (
                        <>
                          <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 10 }}
                            onClick={() => handleRotate(key.id)}>↻ Rotate</button>
                          <button className="btn btn-danger" style={{ padding: '4px 10px', fontSize: 10 }}
                            onClick={() => handleRevoke(key.id)}>✕ Revoke</button>
                        </>
                      )}
                      {key.status !== 'active' && (
                        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>—</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Algorithm info */}
      <div className="grid-3">
        {[
          { alg: 'AES-256-GCM', type: 'Symmetric', use: 'Data encryption, AEAD', bits: '256-bit key', color: 'var(--accent-blue)' },
          { alg: 'RSA-4096', type: 'Asymmetric', use: 'Signing, Key wrapping', bits: '4096-bit key', color: 'var(--accent-purple)' },
          { alg: 'ECC (P-256 / X25519)', type: 'Elliptic Curve', use: 'ECDH exchange, ECDSA signing', bits: '256-bit', color: 'var(--accent-cyan)' },
        ].map(a => (
          <div key={a.alg} className="card" style={{ borderColor: `${a.color}33` }}>
            <div style={{ color: a.color, fontWeight: 700, marginBottom: 6 }}>{a.alg}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{a.type} · {a.bits}</div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{a.use}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Label({ children }) {
  return <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{children}</div>;
}

function PageHeader({ title, sub }) {
  return (
    <div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 700 }}>
        {title}
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{sub}</div>
    </div>
  );
}
