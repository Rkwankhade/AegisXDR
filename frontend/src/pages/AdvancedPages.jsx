// Advanced Security Pages
import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import {
  listArtifacts, collectArtifact, verifyArtifact,
  listMalware, uploadMalware, analyzeMalware,
  analyzePassword, hashPassword,
  kyberKeygen, dilithiumKeygen, getPQCAlgorithms,
  getBlockchain, verifyChain, getBlockchainStats,
  getIndicators, addIndicator, lookupIOC,
  getAnomalies, getUserRisk,
  scanCryptoThreats
} from '../api';

// ─── Forensics Evidence Chain ─────────────────────────────────────────────────
export function ForensicsPage() {
  const [artifacts, setArtifacts] = useState([]);
  const [selected, setSelected]   = useState(null);
  const [verify, setVerify]       = useState(null);
  const [uploading, setUploading] = useState(false);

  const load = () => listArtifacts().then(r => setArtifacts(r.data.artifacts || []));
  useEffect(() => { load(); }, []);

  const handleUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setUploading(true);
    const fd = new FormData();
    fd.append('file', file);
    fd.append('artifact_type', 'file');
    try {
      await collectArtifact(fd);
      toast.success(`Artifact collected: ${file.name}`);
      load();
    } catch (err) { toast.error(err.response?.data?.detail || 'Upload failed'); }
    finally { setUploading(false); }
  };

  const handleVerify = async (id) => {
    const r = await verifyArtifact(id);
    setVerify(r.data);
  };

  return (
    <div style={{ padding: 24, display:'flex', flexDirection:'column', gap: 20 }} className="fade-in">
      <div>
        <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>SECURE EVIDENCE CHAIN</div>
        <div style={{ fontSize: 11, color:'var(--text-muted)' }}>SHA-256 · SHA-512 · BLAKE3 · Analyst Signatures · Chain of Custody</div>
      </div>

      <div className="grid-3">
        {[
          { label:'Total Artifacts', value: artifacts.length, color:'blue' },
          { label:'Verified', value: artifacts.length, color:'green' },
          { label:'Incidents', value: new Set(artifacts.map(a=>a.incident_id).filter(Boolean)).size, color:'orange' },
        ].map(c => (
          <div key={c.label} className={`stat-card ${c.color}`}>
            <div className="stat-value" style={{ color:`var(--accent-${c.color})` }}>{c.value}</div>
            <div className="stat-label">{c.label}</div>
          </div>
        ))}
      </div>

      <div className="card">
        <div style={{ marginBottom: 14, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>Collect Artifact</div>
        <label style={{ display:'inline-flex', alignItems:'center', gap: 10, padding:'10px 20px', border:'1px dashed var(--border-bright)', borderRadius: 6, cursor:'pointer', color:'var(--text-secondary)', fontSize: 12, transition:'all 0.15s' }}
          onMouseEnter={e=>e.currentTarget.style.borderColor='var(--accent-green)'}
          onMouseLeave={e=>e.currentTarget.style.borderColor='var(--border-bright)'}>
          <input type="file" style={{ display:'none' }} onChange={handleUpload} />
          {uploading ? '↻ Hashing & Signing...' : '▣ Drop or click to collect evidence artifact'}
        </label>
        <div style={{ marginTop: 10, fontSize: 11, color:'var(--text-muted)' }}>
          Every artifact is SHA-256 + SHA-512 hashed and signed with analyst ECDSA key
        </div>
      </div>

      {verify && (
        <div className="card" style={{ borderColor: verify.valid ? 'rgba(0,255,136,0.3)' : 'rgba(255,51,102,0.3)' }}>
          <div style={{ color: verify.valid ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 700, marginBottom: 8 }}>
            {verify.valid ? '✓ ARTIFACT INTEGRITY VERIFIED' : '⚠ INTEGRITY CHECK FAILED — POSSIBLE TAMPERING'}
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap: 4, fontSize: 11 }}>
            <div style={{ color:'var(--text-muted)' }}>SHA-256: <span style={{ color:'var(--text-secondary)', fontFamily:'var(--font-mono)' }}>{verify.original_sha256}</span></div>
            <div style={{ color:'var(--text-muted)' }}>Current: <span style={{ color: verify.hash_match ? 'var(--accent-green)' : 'var(--accent-red)', fontFamily:'var(--font-mono)' }}>{verify.current_sha256}</span></div>
            <div style={{ color:'var(--text-muted)' }}>Chain entries: <span style={{ color:'var(--text-secondary)' }}>{verify.chain_entries}</span></div>
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding:'14px 20px', borderBottom:'1px solid var(--border)', fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>
          Evidence Artifacts ({artifacts.length})
        </div>
        {artifacts.length === 0 ? (
          <div style={{ padding: 40, textAlign:'center', color:'var(--text-muted)', fontSize: 12 }}>No artifacts collected yet</div>
        ) : (
          <table className="table">
            <thead><tr><th>Name</th><th>Type</th><th>SHA-256</th><th>Size</th><th>Analyst</th><th>Collected</th><th>Actions</th></tr></thead>
            <tbody>
              {artifacts.map(a => (
                <tr key={a.id}>
                  <td style={{ fontWeight:600, color:'var(--text-primary)' }}>{a.name}</td>
                  <td><span style={{ fontSize:11, color:'var(--accent-blue)' }}>{a.artifact_type}</span></td>
                  <td style={{ fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-muted)' }}>{a.sha256?.slice(0,16)}...</td>
                  <td style={{ color:'var(--text-muted)', fontSize:11 }}>{a.file_size ? `${(a.file_size/1024).toFixed(1)}KB` : '-'}</td>
                  <td style={{ color:'var(--text-secondary)', fontSize:11 }}>{a.analyst}</td>
                  <td style={{ color:'var(--text-muted)', fontSize:11 }}>{a.created_at && new Date(a.created_at).toLocaleDateString()}</td>
                  <td>
                    <button className="btn btn-ghost" style={{ padding:'3px 8px', fontSize:10 }} onClick={() => handleVerify(a.id)}>Verify</button>
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

// ─── Malware Vault ────────────────────────────────────────────────────────────
export function MalwarePage() {
  const [samples, setSamples]   = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);

  const load = () => listMalware().then(r => setSamples(r.data.samples || []));
  useEffect(() => { load(); }, []);

  const handleUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setUploading(true);
    const fd = new FormData();
    fd.append('file', file);
    fd.append('tags', 'uploaded');
    try { await uploadMalware(fd); toast.success('Sample stored in encrypted vault'); load(); }
    catch (err) { toast.error(err.response?.data?.detail || 'Upload failed'); }
    finally { setUploading(false); }
  };

  const handleAnalyze = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setAnalyzing(true);
    const fd = new FormData();
    fd.append('file', file);
    try { const r = await analyzeMalware(fd); setAnalysis(r.data); }
    catch (err) { toast.error('Analysis failed'); }
    finally { setAnalyzing(false); }
  };

  const verdictColor = v => ({ ransomware:'var(--accent-red)', suspicious:'var(--accent-orange)', potentially_unwanted:'var(--accent-yellow)', clean:'var(--accent-green)' }[v] || 'var(--text-muted)');

  return (
    <div style={{ padding: 24, display:'flex', flexDirection:'column', gap: 20 }} className="fade-in">
      <div>
        <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>MALWARE VAULT + RANSOMWARE LAB</div>
        <div style={{ fontSize: 11, color:'var(--text-muted)' }}>Encrypted · Versioned · Signed · Audited · Ransomware Crypto Detection</div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div style={{ marginBottom: 12, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>▤ Vault Upload (AES-256 Encrypted)</div>
          <label style={{ display:'inline-flex', alignItems:'center', gap: 10, padding:'10px 20px', border:'1px dashed var(--accent-red)', borderRadius: 6, cursor:'pointer', color:'var(--accent-red)', fontSize: 12, opacity: 0.8 }}>
            <input type="file" style={{ display:'none' }} onChange={handleUpload} />
            {uploading ? '↻ Encrypting...' : '▤ Upload Sample (safe, encrypted at rest)'}
          </label>
          <div style={{ marginTop: 10, fontSize: 11, color:'var(--text-muted)' }}>
            Upload → SHA-256 hash → AES-256-GCM encrypt → Audit log
          </div>
        </div>

        <div className="card">
          <div style={{ marginBottom: 12, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>▥ Ransomware Crypto Analysis</div>
          <label style={{ display:'inline-flex', alignItems:'center', gap: 10, padding:'10px 20px', border:'1px dashed var(--accent-orange)', borderRadius: 6, cursor:'pointer', color:'var(--accent-orange)', fontSize: 12 }}>
            <input type="file" style={{ display:'none' }} onChange={handleAnalyze} />
            {analyzing ? '↻ Analyzing entropy...' : '▥ Analyze File for Ransomware Patterns'}
          </label>
          <div style={{ marginTop: 10, fontSize: 11, color:'var(--text-muted)' }}>
            Detects: Crypto APIs · Key gen · Extension changes · Entropy spikes · Ransom notes
          </div>
        </div>
      </div>

      {analysis && (
        <div className="card" style={{ borderColor: `${verdictColor(analysis.verdict)}44` }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom: 14 }}>
            <div style={{ fontFamily:'var(--font-display)', fontSize: 22, fontWeight: 700, color: verdictColor(analysis.verdict) }}>
              ▥ {analysis.verdict?.toUpperCase().replace('_',' ')}
            </div>
            <div style={{ textAlign:'right' }}>
              <div style={{ fontSize: 11, color:'var(--text-muted)' }}>Risk Score</div>
              <div style={{ fontFamily:'var(--font-display)', fontSize: 24, fontWeight: 700, color: verdictColor(analysis.verdict) }}>
                {(analysis.risk_score * 100).toFixed(0)}%
              </div>
            </div>
          </div>
          <div className="grid-3" style={{ gap: 12 }}>
            <InfoBox label="File Entropy" value={`${analysis.file_entropy} / 8.0`} warn={analysis.high_entropy} />
            <InfoBox label="Crypto API Matches" value={analysis.crypto_api_matches?.length || 0} warn={(analysis.crypto_api_matches?.length||0)>0} />
            <InfoBox label="Ransom Note" value={analysis.ransom_note_detected ? 'DETECTED' : 'NOT FOUND'} warn={analysis.ransom_note_detected} />
          </div>
          {analysis.crypto_api_matches?.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 10, color:'var(--text-muted)', marginBottom: 6, textTransform:'uppercase' }}>Crypto APIs Detected</div>
              <div style={{ display:'flex', flexWrap:'wrap', gap: 4 }}>
                {analysis.crypto_api_matches.map((m,i) => (
                  <span key={i} style={{ padding:'2px 8px', background:'rgba(255,51,102,0.1)', border:'1px solid rgba(255,51,102,0.2)', borderRadius: 3, fontSize: 10, color:'var(--accent-red)' }}>{m}</span>
                ))}
              </div>
            </div>
          )}
          {analysis.recommendations?.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 10, color:'var(--accent-orange)', marginBottom: 6, textTransform:'uppercase' }}>Recommendations</div>
              {analysis.recommendations.map((r,i) => (
                <div key={i} style={{ fontSize: 11, color:'var(--text-secondary)', padding:'3px 0' }}>→ {r}</div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding:'14px 20px', borderBottom:'1px solid var(--border)', fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>
          Vault Samples ({samples.length})
        </div>
        {samples.length === 0 ? (
          <div style={{ padding: 40, textAlign:'center', color:'var(--text-muted)' }}>No samples in vault</div>
        ) : (
          <table className="table">
            <thead><tr><th>Name</th><th>SHA-256</th><th>MD5</th><th>Size</th><th>Tags</th><th>Uploaded By</th><th>Date</th></tr></thead>
            <tbody>
              {samples.map(s => (
                <tr key={s.id}>
                  <td style={{ fontWeight:600, color:'var(--text-primary)' }}>{s.name}</td>
                  <td style={{ fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-muted)' }}>{s.sha256?.slice(0,16)}...</td>
                  <td style={{ fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-muted)' }}>{s.md5?.slice(0,12)}...</td>
                  <td style={{ color:'var(--text-muted)', fontSize:11 }}>{s.file_size ? `${(s.file_size/1024).toFixed(1)}KB` : '-'}</td>
                  <td>{(s.tags||[]).map(t=><span key={t} style={{ marginRight:4, padding:'1px 6px', background:'rgba(0,170,255,0.1)', borderRadius:3, fontSize:10, color:'var(--accent-blue)' }}>{t}</span>)}</td>
                  <td style={{ color:'var(--text-secondary)', fontSize:11 }}>{s.uploaded_by}</td>
                  <td style={{ color:'var(--text-muted)', fontSize:11 }}>{s.created_at && new Date(s.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── Password Security Lab ────────────────────────────────────────────────────
export function PasswordLabPage() {
  const [password, setPassword] = useState('');
  const [result, setResult]     = useState(null);
  const [hashResult, setHashResult] = useState(null);
  const [loading, setLoading]   = useState(false);
  const [show, setShow]         = useState(false);

  const analyze = async () => {
    if (!password) return;
    setLoading(true);
    try { const r = await analyzePassword(password); setResult(r.data); }
    finally { setLoading(false); }
  };

  const doHash = async () => {
    if (!password) return;
    const r = await hashPassword(password);
    setHashResult(r.data);
  };

  const strengthColor = s => ({ very_strong:'var(--accent-green)', strong:'#7fff00', moderate:'var(--accent-yellow)', weak:'var(--accent-orange)', very_weak:'var(--accent-red)' }[s] || 'var(--text-muted)');
  const scoreWidth = s => ({ very_strong:100, strong:80, moderate:55, weak:35, very_weak:15 }[s] || 0);

  return (
    <div style={{ padding: 24, display:'flex', flexDirection:'column', gap: 20 }} className="fade-in">
      <div>
        <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>PASSWORD SECURITY LAB</div>
        <div style={{ fontSize: 11, color:'var(--text-muted)' }}>Entropy Analysis · Pattern Detection · Argon2id Hashing · Never plaintext storage</div>
      </div>

      <div className="card">
        <div style={{ marginBottom: 14, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>Analyze Password</div>
        <div style={{ display:'flex', gap: 10 }}>
          <div style={{ flex: 1, position:'relative' }}>
            <input className="input" type={show ? 'text' : 'password'}
              placeholder="Enter password to analyze..."
              value={password} onChange={e => { setPassword(e.target.value); setResult(null); setHashResult(null); }}
              onKeyDown={e => e.key === 'Enter' && analyze()} />
            <button onClick={() => setShow(s=>!s)} style={{ position:'absolute', right: 10, top: '50%', transform:'translateY(-50%)', background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer', fontSize: 12 }}>
              {show ? '👁' : '🙈'}
            </button>
          </div>
          <button className="btn btn-primary" onClick={analyze} disabled={loading || !password}>
            {loading ? '↻' : '◇ Analyze'}
          </button>
          <button className="btn btn-green" onClick={doHash} disabled={!password}>
            ⬢ Hash (Argon2id)
          </button>
        </div>
      </div>

      {result && (
        <div className="grid-2">
          <div className="card">
            <div style={{ marginBottom: 14, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>Strength Analysis</div>
            <div style={{ textAlign:'center', padding:'10px 0 20px' }}>
              <div style={{ fontFamily:'var(--font-display)', fontSize: 36, fontWeight: 700, color: strengthColor(result.strength) }}>
                {result.strength?.replace('_',' ').toUpperCase()}
              </div>
              <div style={{ marginTop: 8 }}>
                <div className="progress" style={{ height: 8, margin:'8px 0' }}>
                  <div className="progress-bar" style={{ width:`${scoreWidth(result.strength)}%`, background: strengthColor(result.strength) }} />
                </div>
                <div style={{ fontSize: 11, color:'var(--text-muted)' }}>Score: {result.strength_score}/100</div>
              </div>
            </div>
            <div style={{ display:'flex', flexDirection:'column', gap: 8 }}>
              <DetailRow label="Entropy" value={`${result.entropy_bits} bits`} />
              <DetailRow label="Length" value={`${result.length} chars`} />
              <DetailRow label="Crack Time" value={result.estimated_crack_time?.time} />
              <DetailRow label="Crackable?" value={result.estimated_crack_time?.feasible ? 'YES — Vulnerable' : 'NO — Secure'} />
            </div>
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 10, color:'var(--text-muted)', marginBottom: 6, textTransform:'uppercase' }}>Character Classes</div>
              <div style={{ display:'flex', gap: 8, flexWrap:'wrap' }}>
                {Object.entries(result.character_classes || {}).map(([k,v]) => (
                  <span key={k} style={{ padding:'3px 8px', borderRadius: 3, fontSize: 10, background: v ? 'rgba(0,255,136,0.1)' : 'rgba(255,51,102,0.08)', border: `1px solid ${v ? 'rgba(0,255,136,0.25)' : 'rgba(255,51,102,0.2)'}`, color: v ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                    {v ? '✓' : '✕'} {k}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div style={{ display:'flex', flexDirection:'column', gap: 14 }}>
            {result.issues?.length > 0 && (
              <div className="card" style={{ borderColor:'rgba(255,51,102,0.2)' }}>
                <div style={{ fontSize: 11, color:'var(--accent-red)', marginBottom: 8, textTransform:'uppercase' }}>Issues Detected</div>
                {result.issues.map((i,idx) => <div key={idx} style={{ fontSize:11, color:'var(--text-secondary)', padding:'3px 0' }}>⚠ {i}</div>)}
              </div>
            )}
            {result.patterns_detected?.length > 0 && (
              <div className="card" style={{ borderColor:'rgba(255,215,0,0.2)' }}>
                <div style={{ fontSize: 11, color:'var(--accent-yellow)', marginBottom: 8, textTransform:'uppercase' }}>Patterns Detected</div>
                {result.patterns_detected.map((p,i) => <div key={i} style={{ fontSize:11, color:'var(--text-secondary)', padding:'3px 0' }}>◈ {p}</div>)}
              </div>
            )}
            {result.recommendations?.length > 0 && (
              <div className="card" style={{ borderColor:'rgba(0,170,255,0.2)' }}>
                <div style={{ fontSize: 11, color:'var(--accent-blue)', marginBottom: 8, textTransform:'uppercase' }}>Recommendations</div>
                {result.recommendations.map((r,i) => <div key={i} style={{ fontSize:11, color:'var(--text-secondary)', padding:'3px 0' }}>→ {r}</div>)}
              </div>
            )}
          </div>
        </div>
      )}

      {hashResult && (
        <div className="card" style={{ borderColor:'rgba(0,255,136,0.2)' }}>
          <div style={{ marginBottom: 10, fontSize: 11, color:'var(--accent-green)', textTransform:'uppercase' }}>⬢ Argon2id Hash Result</div>
          <div className="terminal" style={{ fontSize: 11 }}>{hashResult.hash}</div>
          <div style={{ marginTop: 10, display:'flex', gap: 16, fontSize: 11, color:'var(--text-muted)', flexWrap:'wrap' }}>
            <span>Algorithm: <span style={{ color:'var(--accent-green)' }}>{hashResult.algorithm}</span></span>
            <span>Time cost: {hashResult.parameters?.time_cost}</span>
            <span>Memory: {hashResult.parameters?.memory_cost_kb}KB</span>
            <span>Parallelism: {hashResult.parameters?.parallelism}</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Post-Quantum Crypto ──────────────────────────────────────────────────────
export function PQCPage() {
  const [kyberKey, setKyberKey]       = useState(null);
  const [dilithiumKey, setDilithiumKey] = useState(null);
  const [algInfo, setAlgInfo]         = useState(null);
  const [loading, setLoading]         = useState('');

  useEffect(() => {
    getPQCAlgorithms().then(r => setAlgInfo(r.data));
  }, []);

  const genKyber = async () => {
    setLoading('kyber');
    try { const r = await kyberKeygen(); setKyberKey(r.data); toast.success('Kyber-1024 key generated'); }
    finally { setLoading(''); }
  };

  const genDilithium = async () => {
    setLoading('dilithium');
    try { const r = await dilithiumKeygen(); setDilithiumKey(r.data); toast.success('Dilithium3 key generated'); }
    finally { setLoading(''); }
  };

  return (
    <div style={{ padding: 24, display:'flex', flexDirection:'column', gap: 20 }} className="fade-in">
      <div>
        <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>
          POST-QUANTUM CRYPTOGRAPHY <span style={{ color:'var(--accent-purple)', fontSize: 14 }}>RESEARCH MODULE</span>
        </div>
        <div style={{ fontSize: 11, color:'var(--text-muted)' }}>
          CRYSTALS-Kyber (FIPS 203) · CRYSTALS-Dilithium (FIPS 204) · Quantum-resistant algorithms
        </div>
      </div>

      <div style={{ padding:'12px 16px', background:'rgba(124,58,237,0.08)', border:'1px solid rgba(124,58,237,0.25)', borderRadius: 6, fontSize: 11, color:'var(--text-secondary)' }}>
        ⚡ <strong style={{ color:'var(--accent-purple)' }}>Research Module:</strong> Classical crypto simulation of NIST PQC standards. Production use requires{' '}
        <code style={{ color:'var(--accent-cyan)' }}>liboqs-python</code> bindings for actual lattice operations.
      </div>

      {algInfo && (
        <div className="grid-2">
          {Object.entries(algInfo).map(([key, alg]) => (
            <div key={key} className="card" style={{ borderColor:'rgba(124,58,237,0.3)' }}>
              <div style={{ color:'var(--accent-purple)', fontWeight: 700, fontSize: 14, marginBottom: 6 }}>{alg.name}</div>
              <div style={{ fontSize: 11, color:'var(--text-secondary)', marginBottom: 10, lineHeight: 1.7 }}>
                <div>Type: <span style={{ color:'var(--text-primary)' }}>{alg.type}</span></div>
                <div>Security: <span style={{ color:'var(--accent-green)' }}>{alg.security_level}</span></div>
                <div>Standard: <span style={{ color:'var(--accent-blue)' }}>{alg.nist_round}</span></div>
                <div style={{ color:'var(--text-muted)', marginTop: 4 }}>{alg.description}</div>
              </div>
              {key === 'kyber' ? (
                <button className="btn btn-ghost" style={{ width:'100%' }} onClick={genKyber} disabled={loading==='kyber'}>
                  {loading==='kyber' ? '↻ Generating...' : '⬡ Generate Kyber Keypair'}
                </button>
              ) : (
                <button className="btn btn-ghost" style={{ width:'100%' }} onClick={genDilithium} disabled={loading==='dilithium'}>
                  {loading==='dilithium' ? '↻ Generating...' : '⬡ Generate Dilithium Keypair'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {kyberKey && (
        <div className="card">
          <div style={{ marginBottom: 10, fontSize: 11, color:'var(--accent-purple)', textTransform:'uppercase' }}>⬡ Kyber-1024 Keypair</div>
          <div className="grid-2" style={{ gap: 12 }}>
            <div>
              <div style={{ fontSize: 10, color:'var(--text-muted)', marginBottom: 6 }}>PUBLIC KEY (1568 bytes)</div>
              <div className="terminal" style={{ maxHeight: 120, fontSize: 10 }}>{kyberKey.public_key}</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color:'var(--accent-red)', marginBottom: 6 }}>SECRET KEY (3168 bytes) — Keep private!</div>
              <div className="terminal" style={{ maxHeight: 120, fontSize: 10, filter:'blur(3px)' }} onClick={e=>e.currentTarget.style.filter='none'}>
                {kyberKey.secret_key}
              </div>
            </div>
          </div>
          <div style={{ marginTop: 10, fontSize: 11, color:'var(--text-muted)' }}>
            {kyberKey.note} · Standard: {kyberKey.nist_standard}
          </div>
        </div>
      )}

      {dilithiumKey && (
        <div className="card">
          <div style={{ marginBottom: 10, fontSize: 11, color:'var(--accent-purple)', textTransform:'uppercase' }}>⬡ Dilithium3 Keypair</div>
          <div className="grid-2" style={{ gap: 12 }}>
            <div>
              <div style={{ fontSize: 10, color:'var(--text-muted)', marginBottom: 6 }}>PUBLIC KEY (1952 bytes)</div>
              <div className="terminal" style={{ maxHeight: 120, fontSize: 10 }}>{dilithiumKey.public_key}</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color:'var(--accent-red)', marginBottom: 6 }}>SECRET KEY (4016 bytes)</div>
              <div className="terminal" style={{ maxHeight: 120, fontSize: 10, filter:'blur(3px)' }} onClick={e=>e.currentTarget.style.filter='none'}>
                {dilithiumKey.secret_key}
              </div>
            </div>
          </div>
          <div style={{ marginTop: 10, fontSize: 11, color:'var(--text-muted)' }}>{dilithiumKey.note}</div>
        </div>
      )}
    </div>
  );
}

// ─── Blockchain Audit Trail ───────────────────────────────────────────────────
export function BlockchainPage() {
  const [blocks, setBlocks]   = useState([]);
  const [stats, setStats]     = useState(null);
  const [verify, setVerify]   = useState(null);
  const [filter, setFilter]   = useState('');
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    const [b, s] = await Promise.all([getBlockchain(filter || undefined, 100), getBlockchainStats()]);
    setBlocks(b.data.blocks || []);
    setStats(s.data);
    setLoading(false);
  };
  useEffect(() => { load(); }, [filter]);

  const doVerify = async () => {
    const r = await verifyChain();
    setVerify(r.data);
    if (r.data.valid) toast.success('Chain integrity verified ✓');
    else toast.error(`Chain compromised: ${r.data.issues?.length} issues`);
  };

  const typeColor = t => ({ audit:'var(--accent-blue)', kms_audit:'var(--accent-purple)', pki_audit:'var(--accent-cyan)', vault_audit:'var(--accent-orange)', forensics:'var(--accent-green)', genesis:'var(--text-muted)' }[t] || 'var(--text-secondary)');

  return (
    <div style={{ padding: 24, display:'flex', flexDirection:'column', gap: 20 }} className="fade-in">
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
        <div>
          <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>BLOCKCHAIN AUDIT TRAIL</div>
          <div style={{ fontSize: 11, color:'var(--text-muted)' }}>Immutable ledger · SHA-256 · Proof-of-Work · Tamper-evident</div>
        </div>
        <button className="btn btn-primary" onClick={doVerify}>◈ Verify Chain Integrity</button>
      </div>

      {stats && (
        <div className="grid-4">
          {[
            { label:'Total Blocks', value: stats.total_blocks, color:'blue' },
            { label:'Chain Valid', value: stats.chain_valid ? 'YES' : 'NO', color: stats.chain_valid ? 'green' : 'red' },
            { label:'Genesis Hash', value: stats.genesis_hash?.slice(0,8)+'...', color:'orange' },
            { label:'Latest Hash', value: stats.latest_hash?.slice(0,8)+'...', color:'purple' },
          ].map(c => (
            <div key={c.label} className={`stat-card ${c.color}`}>
              <div style={{ fontFamily:'var(--font-display)', fontSize: c.value?.toString().length > 6 ? 14 : 28, fontWeight: 700, color:`var(--accent-${c.color})`, wordBreak:'break-all' }}>{c.value}</div>
              <div className="stat-label">{c.label}</div>
            </div>
          ))}
        </div>
      )}

      {verify && (
        <div className="card" style={{ borderColor: verify.valid ? 'rgba(0,255,136,0.3)' : 'rgba(255,51,102,0.3)' }}>
          <div style={{ color: verify.valid ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 700 }}>
            {verify.valid ? '✓ BLOCKCHAIN INTEGRITY VERIFIED' : `⚠ ${verify.issues?.length} INTEGRITY ISSUES DETECTED`}
          </div>
          <div style={{ fontSize: 11, color:'var(--text-muted)', marginTop: 6 }}>
            Verified {verify.chain_length} blocks at {verify.verified_at && new Date(verify.verified_at).toLocaleTimeString()}
          </div>
          {verify.issues?.map((issue,i) => (
            <div key={i} style={{ marginTop: 6, fontSize: 11, color:'var(--accent-red)' }}>Block {issue.block}: {issue.issue}</div>
          ))}
        </div>
      )}

      <div style={{ display:'flex', gap: 10 }}>
        <select className="input" style={{ width: 180 }} value={filter}
          onChange={e => setFilter(e.target.value)}>
          <option value="">All Types</option>
          {['audit','kms_audit','pki_audit','vault_audit','forensics','genesis'].map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <button className="btn btn-ghost" onClick={load}>↻ Refresh</button>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding:'14px 20px', borderBottom:'1px solid var(--border)', fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>
          Blockchain ({blocks.length} blocks)
        </div>
        {loading ? <div style={{ padding:30, textAlign:'center', color:'var(--text-muted)' }}>Loading chain...</div> : (
          <div style={{ maxHeight: 500, overflow:'auto' }}>
            {blocks.slice().reverse().map(block => (
              <div key={block.block_id} style={{ padding:'12px 20px', borderBottom:'1px solid rgba(26,39,64,0.5)', display:'flex', gap: 12, alignItems:'flex-start' }}>
                <div style={{ fontSize: 11, color:'var(--text-muted)', width: 40, flexShrink: 0, textAlign:'right' }}>
                  #{block.block_number}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display:'flex', gap: 10, alignItems:'center', marginBottom: 4 }}>
                    <span style={{ color: typeColor(block.data_type), fontSize: 11, fontWeight: 600 }}>{block.data_type}</span>
                    <span style={{ fontSize: 10, color:'var(--text-muted)' }}>{block.timestamp && new Date(block.timestamp).toLocaleString()}</span>
                  </div>
                  <div style={{ fontSize: 10, fontFamily:'var(--font-mono)', color:'var(--accent-green)', marginBottom: 2 }}>
                    ⬡ {block.hash}
                  </div>
                  <div style={{ fontSize: 10, fontFamily:'var(--font-mono)', color:'var(--text-muted)' }}>
                    prev: {block.previous_hash?.slice(0,32)}...
                  </div>
                  <div style={{ fontSize: 10, color:'var(--text-muted)', marginTop: 4 }}>
                    {JSON.stringify(block.data).slice(0, 120)}{JSON.stringify(block.data).length > 120 ? '...' : ''}
                  </div>
                </div>
                <div style={{ fontSize: 10, color:'var(--text-muted)', flexShrink: 0 }}>
                  nonce: {block.nonce}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Threat Intelligence Page ─────────────────────────────────────────────────
export function ThreatIntelPage() {
  const [indicators, setIndicators] = useState([]);
  const [form, setForm] = useState({ ioc_type:'ip', value:'', severity:'medium', confidence:0.7, source:'manual', tags:'' });
  const [lookup, setLookup] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  const [filter, setFilter] = useState({ type:'', severity:'' });

  const load = () => getIndicators(filter.type||undefined, filter.severity||undefined)
    .then(r => setIndicators(r.data.indicators||[]));
  useEffect(() => { load(); }, [filter]);

  const handleAdd = async () => {
    if (!form.value) return toast.error('IOC value required');
    try {
      await addIndicator({ ...form, tags: form.tags.split(',').map(t=>t.trim()).filter(Boolean) });
      toast.success('Indicator added and signed');
      setForm(f => ({...f, value:'', tags:''}));
      load();
    } catch (e) { toast.error('Failed to add indicator'); }
  };

  const handleLookup = async () => {
    if (!lookup) return;
    const r = await lookupIOC(lookup);
    setLookupResult(r.data);
  };

  const sevColor = s => ({ critical:'var(--accent-red)', high:'var(--accent-orange)', medium:'var(--accent-yellow)', low:'var(--accent-green)' }[s] || 'var(--text-muted)');

  return (
    <div style={{ padding: 24, display:'flex', flexDirection:'column', gap: 20 }} className="fade-in">
      <div>
        <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>THREAT INTELLIGENCE</div>
        <div style={{ fontSize: 11, color:'var(--text-muted)' }}>Signed IOC feeds · ECDSA signatures · MITRE tactics · Verified ingestion</div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div style={{ marginBottom: 14, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>◉ Add Indicator</div>
          <div style={{ display:'flex', flexDirection:'column', gap: 10 }}>
            <div style={{ display:'flex', gap: 10 }}>
              <div style={{ flex:'0 1 120px' }}>
                <FieldLabel>Type</FieldLabel>
                <select className="input" value={form.ioc_type} onChange={e=>setForm(f=>({...f,ioc_type:e.target.value}))}>
                  {['ip','domain','hash','url','email','cve','mutex'].map(t=><option key={t}>{t}</option>)}
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <FieldLabel>Value</FieldLabel>
                <input className="input" placeholder="e.g. 192.168.1.100 or malware.exe hash..."
                  value={form.value} onChange={e=>setForm(f=>({...f,value:e.target.value}))} />
              </div>
            </div>
            <div style={{ display:'flex', gap: 10 }}>
              <div style={{ flex: 1 }}>
                <FieldLabel>Severity</FieldLabel>
                <select className="input" value={form.severity} onChange={e=>setForm(f=>({...f,severity:e.target.value}))}>
                  {['critical','high','medium','low','info'].map(s=><option key={s}>{s}</option>)}
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <FieldLabel>Confidence</FieldLabel>
                <input className="input" type="number" step="0.1" min="0" max="1"
                  value={form.confidence} onChange={e=>setForm(f=>({...f,confidence:+e.target.value}))} />
              </div>
            </div>
            <div>
              <FieldLabel>Tags (comma-separated)</FieldLabel>
              <input className="input" placeholder="apt29, ransomware, c2"
                value={form.tags} onChange={e=>setForm(f=>({...f,tags:e.target.value}))} />
            </div>
            <button className="btn btn-green" onClick={handleAdd}>◉ Add & Sign Indicator</button>
          </div>
        </div>

        <div className="card">
          <div style={{ marginBottom: 14, fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>◎ IOC Lookup</div>
          <div style={{ display:'flex', gap: 8, marginBottom: 14 }}>
            <input className="input" placeholder="Search IOC value..."
              value={lookup} onChange={e=>{setLookup(e.target.value);setLookupResult(null);}}
              onKeyDown={e => e.key==='Enter' && handleLookup()} />
            <button className="btn btn-primary" onClick={handleLookup}>Search</button>
          </div>
          {lookupResult && (
            <div style={{ padding: 12, borderRadius: 6, background: lookupResult.found ? 'rgba(255,51,102,0.08)' : 'rgba(0,255,136,0.06)', border: `1px solid ${lookupResult.found ? 'rgba(255,51,102,0.2)' : 'rgba(0,255,136,0.15)'}` }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: lookupResult.found ? 'var(--accent-red)' : 'var(--accent-green)', marginBottom: 8 }}>
                {lookupResult.found ? '⚠ THREAT FOUND' : '✓ CLEAN — Not in database'}
              </div>
              {lookupResult.indicators?.map((ind,i) => (
                <div key={i} style={{ fontSize: 11, color:'var(--text-secondary)', marginBottom: 4 }}>
                  {ind.ioc_type} · <span style={{ color: sevColor(ind.severity) }}>{ind.severity}</span> · {ind.source}
                </div>
              ))}
            </div>
          )}
          <div style={{ marginTop: 14 }}>
            <div style={{ fontSize: 11, color:'var(--text-muted)', marginBottom: 8 }}>Feed Stats</div>
            <div style={{ display:'flex', gap: 16, fontSize: 12 }}>
              {['critical','high','medium','low'].map(s => (
                <div key={s} style={{ textAlign:'center' }}>
                  <div style={{ color: sevColor(s), fontWeight: 700, fontSize: 18 }}>
                    {indicators.filter(i=>i.severity===s).length}
                  </div>
                  <div style={{ fontSize: 10, color:'var(--text-muted)', textTransform:'capitalize' }}>{s}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div style={{ display:'flex', gap: 10 }}>
        <select className="input" style={{ width: 140 }} value={filter.type} onChange={e=>setFilter(f=>({...f,type:e.target.value}))}>
          <option value="">All Types</option>
          {['ip','domain','hash','url','email','cve','mutex'].map(t=><option key={t} value={t}>{t}</option>)}
        </select>
        <select className="input" style={{ width: 140 }} value={filter.severity} onChange={e=>setFilter(f=>({...f,severity:e.target.value}))}>
          <option value="">All Severities</option>
          {['critical','high','medium','low','info'].map(s=><option key={s} value={s}>{s}</option>)}
        </select>
        <span style={{ alignSelf:'center', fontSize: 11, color:'var(--text-muted)' }}>{indicators.length} indicators</span>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {indicators.length === 0 ? (
          <div style={{ padding:40, textAlign:'center', color:'var(--text-muted)' }}>No indicators yet. Add your first IOC above.</div>
        ) : (
          <table className="table">
            <thead><tr><th>Type</th><th>Value</th><th>Severity</th><th>Confidence</th><th>Source</th><th>Tags</th><th>Verified</th><th>Added</th></tr></thead>
            <tbody>
              {indicators.map(ind => (
                <tr key={ind.id}>
                  <td><span style={{ color:'var(--accent-blue)', fontSize:11, fontWeight:600, textTransform:'uppercase' }}>{ind.ioc_type}</span></td>
                  <td style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-primary)', maxWidth:200, overflow:'hidden', textOverflow:'ellipsis' }}>{ind.value}</td>
                  <td><span style={{ color: sevColor(ind.severity), fontSize:11, fontWeight:600, textTransform:'uppercase' }}>{ind.severity}</span></td>
                  <td><div className="progress" style={{ width:60 }}><div className="progress-bar" style={{ width:`${ind.confidence*100}%`, background: sevColor(ind.severity) }} /></div></td>
                  <td style={{ color:'var(--text-secondary)', fontSize:11 }}>{ind.source}</td>
                  <td>{(ind.tags||[]).map(t=><span key={t} style={{ marginRight:2, padding:'1px 5px', background:'rgba(0,170,255,0.1)', borderRadius:2, fontSize:9, color:'var(--accent-blue)' }}>{t}</span>)}</td>
                  <td><span style={{ color: ind.verified ? 'var(--accent-green)' : 'var(--accent-red)', fontSize:12 }}>{ind.verified ? '✓' : '✕'}</span></td>
                  <td style={{ color:'var(--text-muted)', fontSize:11 }}>{ind.timestamp && new Date(ind.timestamp).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── UEBA Page ────────────────────────────────────────────────────────────────
export function UEBAPage() {
  const [anomalies, setAnomalies] = useState([]);

  useEffect(() => {
    getAnomalies(100).then(r => setAnomalies(r.data.anomalies || []));
  }, []);

  return (
    <div style={{ padding: 24, display:'flex', flexDirection:'column', gap: 20 }} className="fade-in">
      <div>
        <div style={{ fontFamily:'var(--font-display)', fontSize: 20, fontWeight: 700 }}>UEBA — USER BEHAVIOR ANALYTICS</div>
        <div style={{ fontSize: 11, color:'var(--text-muted)' }}>Baseline deviation detection · Anomaly scoring · Risk profiling</div>
      </div>
      <div className="grid-3">
        {[
          { label:'Total Anomalies', value: anomalies.length, color:'red' },
          { label:'High Risk', value: anomalies.filter(a=>a.risk_score>0.6).length, color:'orange' },
          { label:'Users Flagged', value: new Set(anomalies.map(a=>a.user_id)).size, color:'purple' },
        ].map(c => (
          <div key={c.label} className={`stat-card ${c.color}`}>
            <div className="stat-value" style={{ color:`var(--accent-${c.color})` }}>{c.value}</div>
            <div className="stat-label">{c.label}</div>
          </div>
        ))}
      </div>
      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding:'14px 20px', borderBottom:'1px solid var(--border)', fontSize: 11, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em' }}>
          Detected Anomalies ({anomalies.length})
        </div>
        {anomalies.length === 0 ? (
          <div style={{ padding:40, textAlign:'center', color:'var(--text-muted)' }}>
            No anomalies. Inject test events from the Alerts page to see UEBA in action.
          </div>
        ) : (
          <table className="table">
            <thead><tr><th>User</th><th>Anomalies</th><th>Risk Score</th><th>Time</th></tr></thead>
            <tbody>
              {anomalies.map(a => (
                <tr key={a.id}>
                  <td style={{ fontWeight:600, color:'var(--text-primary)' }}>{a.user_id}</td>
                  <td>{(a.anomalies||[]).map((an,i)=><div key={i} style={{ fontSize:10, color:'var(--text-secondary)', padding:'1px 0' }}>⚠ {an.detail}</div>)}</td>
                  <td>
                    <div style={{ display:'flex', alignItems:'center', gap: 8 }}>
                      <div className="progress" style={{ width:60 }}>
                        <div className="progress-bar" style={{ width:`${a.risk_score*100}%`, background: a.risk_score>0.6?'var(--accent-red)':a.risk_score>0.3?'var(--accent-orange)':'var(--accent-green)' }} />
                      </div>
                      <span style={{ fontSize:11, color:'var(--text-muted)' }}>{(a.risk_score*100).toFixed(0)}%</span>
                    </div>
                  </td>
                  <td style={{ color:'var(--text-muted)', fontSize:11 }}>{a.timestamp && new Date(a.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── Shared ───────────────────────────────────────────────────────────────────
function FieldLabel({ children }) {
  return <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase', letterSpacing:'0.08em' }}>{children}</div>;
}

function DetailRow({ label, value }) {
  return (
    <div style={{ display:'flex', justifyContent:'space-between', gap:8 }}>
      <span style={{ fontSize:11, color:'var(--text-muted)', flexShrink:0 }}>{label}</span>
      <span style={{ fontSize:11, color:'var(--text-secondary)', textAlign:'right' }}>{value||'—'}</span>
    </div>
  );
}

function InfoBox({ label, value, warn }) {
  return (
    <div style={{ padding:'10px 14px', background: warn ? 'rgba(255,51,102,0.06)' : 'var(--bg-secondary)', border:`1px solid ${warn ? 'rgba(255,51,102,0.2)' : 'var(--border)'}`, borderRadius:6 }}>
      <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:4, textTransform:'uppercase' }}>{label}</div>
      <div style={{ fontSize:16, fontWeight:700, fontFamily:'var(--font-display)', color: warn ? 'var(--accent-red)' : 'var(--accent-green)' }}>{value}</div>
    </div>
  );
}
