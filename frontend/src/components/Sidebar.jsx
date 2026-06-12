// Sidebar — hacker terminal nav
import React, { useState } from 'react';
import { useStore } from '../store';

const NAV_SECTIONS = [
  {
    label: 'OPERATIONS',
    items: [
      { id: 'dashboard',    icon: '⬡', label: 'Dashboard',       sub: 'Overview' },
      { id: 'alerts',       icon: '◈', label: 'Alerts',           sub: 'SIEM/XDR' },
      { id: 'incidents',    icon: '⚑', label: 'Incidents',        sub: 'SOAR' },
      { id: 'threat-intel', icon: '◉', label: 'Threat Intel',     sub: 'IOC Feeds' },
      { id: 'ueba',         icon: '◎', label: 'UEBA',             sub: 'Behavior Analytics' },
    ]
  },
  {
    label: 'CRYPTOGRAPHY',
    items: [
      { id: 'kms',          icon: '⬢', label: 'Key Mgmt (KMS)',   sub: 'AES/RSA/ECC' },
      { id: 'vault',        icon: '⬟', label: 'Secrets Vault',    sub: 'Credentials' },
      { id: 'pki',          icon: '⬠', label: 'PKI / Certs',      sub: 'CA Chain' },
      { id: 'pqc',          icon: '⬡', label: 'Post-Quantum',     sub: 'Kyber/Dilithium' },
    ]
  },
  {
    label: 'IDENTITY',
    items: [
      { id: 'zerotrust',    icon: '◆', label: 'Zero Trust',       sub: 'Continuous Verify' },
      { id: 'password-lab', icon: '◇', label: 'Password Lab',     sub: 'Entropy Analysis' },
    ]
  },
  {
    label: 'FORENSICS',
    items: [
      { id: 'forensics',    icon: '▣', label: 'Evidence Chain',   sub: 'Chain of Custody' },
      { id: 'malware',      icon: '▤', label: 'Malware Vault',    sub: 'Sample Storage' },
      { id: 'ransomware',   icon: '▥', label: 'Ransomware Lab',   sub: 'Crypto Analysis' },
    ]
  },
  {
    label: 'INFRASTRUCTURE',
    items: [
      { id: 'blockchain',   icon: '⬡', label: 'Audit Blockchain', sub: 'Immutable Log' },
      { id: 'crypto-detect',icon: '◈', label: 'Crypto Detection', sub: 'TLS/Cert Monitor' },
      { id: 'tenants',      icon: '◉', label: 'Multi-Tenant',     sub: 'Isolation' },
    ]
  },
];

export default function Sidebar() {
  const { activeModule, setActiveModule, user } = useStore();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside style={{
      width: collapsed ? 56 : 230,
      minWidth: collapsed ? 56 : 230,
      background: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      transition: 'width 0.2s ease, min-width 0.2s ease',
      overflow: 'hidden',
    }}>
      {/* Logo */}
      <div style={{
        padding: '16px 12px',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        cursor: 'pointer',
        userSelect: 'none',
      }} onClick={() => setCollapsed(c => !c)}>
        <div style={{
          width: 32, height: 32, flexShrink: 0,
          background: 'linear-gradient(135deg, #00ff88, #00aaff)',
          borderRadius: 6,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 14, fontWeight: 700, color: '#000',
          fontFamily: 'var(--font-display)',
        }}>
          AX
        </div>
        {!collapsed && (
          <div>
            <div style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 15, color: 'var(--text-primary)', letterSpacing: '0.08em' }}>
              AEGIS<span style={{ color: 'var(--accent-blue)' }}>XDR</span>
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.15em' }}>
              SECURITY PLATFORM
            </div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, overflowY: 'auto', padding: '8px 0' }}>
        {NAV_SECTIONS.map(section => (
          <div key={section.label}>
            {!collapsed && (
              <div style={{
                padding: '12px 14px 4px',
                fontSize: 9,
                fontWeight: 700,
                color: 'var(--text-muted)',
                letterSpacing: '0.15em',
              }}>
                {section.label}
              </div>
            )}
            {section.items.map(item => {
              const active = activeModule === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveModule(item.id)}
                  title={collapsed ? item.label : undefined}
                  style={{
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    padding: collapsed ? '9px 0' : '7px 14px',
                    justifyContent: collapsed ? 'center' : 'flex-start',
                    background: active ? 'rgba(0,170,255,0.08)' : 'transparent',
                    borderLeft: active ? '2px solid var(--accent-blue)' : '2px solid transparent',
                    border: 'none',
                    cursor: 'pointer',
                    color: active ? 'var(--accent-blue)' : 'var(--text-secondary)',
                    transition: 'all 0.12s',
                    textAlign: 'left',
                  }}
                  onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--bg-hover)'; }}
                  onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}
                >
                  <span style={{ fontSize: 14, flexShrink: 0 }}>{item.icon}</span>
                  {!collapsed && (
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 500 }}>{item.label}</div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1 }}>{item.sub}</div>
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* User footer */}
      {!collapsed && user && (
        <div style={{
          padding: '12px 14px',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: '50%',
            background: 'linear-gradient(135deg, var(--accent-purple), var(--accent-blue))',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 11, fontWeight: 700, color: 'white', flexShrink: 0,
          }}>
            {user.username?.[0]?.toUpperCase() || 'A'}
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)', truncate: 'ellipsis' }}>
              {user.username}
            </div>
            <div style={{ fontSize: 10, color: 'var(--accent-green)' }}>
              <span className="dot dot-green" style={{ marginRight: 4 }} />
              {user.role}
            </div>
          </div>
        </div>
      )}
    </aside>
  );
}
