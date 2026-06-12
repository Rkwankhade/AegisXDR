// AegisXDR Main App
import React, { useEffect } from 'react';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './index.css';

import { useStore } from './store';
import Sidebar from './components/Sidebar';

// Pages
import Dashboard from './pages/Dashboard';
import KMSPage from './pages/KMS';
import { VaultPage, PKIPage, AlertsPage, ZeroTrustPage } from './pages/Pages';
import {
  ForensicsPage, MalwarePage, PasswordLabPage,
  PQCPage, BlockchainPage, ThreatIntelPage, UEBAPage
} from './pages/AdvancedPages';
import {
  LoginPage, IncidentsPage, CryptoDetectPage, TenantsPage
} from './pages/ExtraPages';

const PAGE_MAP = {
  dashboard:     Dashboard,
  kms:           KMSPage,
  vault:         VaultPage,
  pki:           PKIPage,
  alerts:        AlertsPage,
  incidents:     IncidentsPage,
  'zero trust':  ZeroTrustPage,
  zerotrust:     ZeroTrustPage,
  'threat-intel': ThreatIntelPage,
  forensics:     ForensicsPage,
  malware:       MalwarePage,
  ransomware:    MalwarePage,
  'password-lab': PasswordLabPage,
  pqc:           PQCPage,
  blockchain:    BlockchainPage,
  ueba:          UEBAPage,
  'crypto-detect': CryptoDetectPage,
  tenants:       TenantsPage,
};

export default function App() {
  const { token, activeModule } = useStore();

  if (!token) return <LoginPage />;

  const PageComponent = PAGE_MAP[activeModule] || Dashboard;

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <Sidebar />
      <main style={{
        flex: 1,
        overflow: 'auto',
        background: 'var(--bg-primary)',
        position: 'relative',
      }}>
        {/* Top bar */}
        <TopBar />
        <PageComponent />
      </main>

      <ToastContainer
        position="bottom-right"
        autoClose={3000}
        hideProgressBar={false}
        theme="dark"
        style={{ fontSize: 12 }}
      />
    </div>
  );
}

function TopBar() {
  const { user, logout, activeModule } = useStore();

  return (
    <div style={{
      height: 44,
      background: 'var(--bg-secondary)',
      borderBottom: '1px solid var(--border)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 20px',
      position: 'sticky',
      top: 0,
      zIndex: 10,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
          AEGISXDR
        </span>
        <span style={{ color: 'var(--border-bright)' }}>/</span>
        <span style={{ fontSize: 11, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          {activeModule.replace(/-/g, ' ')}
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="dot dot-green pulse" />
          <span style={{ fontSize: 10, color: 'var(--accent-green)' }}>LIVE</span>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {new Date().toLocaleTimeString()}
        </div>
        {user && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              {user.username}
            </span>
            <span style={{ padding: '2px 8px', background: 'rgba(124,58,237,0.15)', border: '1px solid rgba(124,58,237,0.3)', borderRadius: 3, fontSize: 10, color: 'var(--accent-purple)' }}>
              {user.role}
            </span>
            <button
              onClick={logout}
              style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 4, color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10, padding: '3px 8px' }}
              onMouseEnter={e => e.currentTarget.style.color = 'var(--accent-red)'}
              onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
            >
              Logout
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
