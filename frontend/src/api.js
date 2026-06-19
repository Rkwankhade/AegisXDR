// AegisXDR API Service
import axios from 'axios';

const API = axios.create({ baseURL: process.env.REACT_APP_API_URL || '/api' });

// Attach JWT token
API.interceptors.request.use(cfg => {
  const token = localStorage.getItem('aegis_token');
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

// Handle 401
API.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('aegis_token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

// ── Auth ──────────────────────────────────────────────────────
export const login = (username, password, mfa_code) =>
  API.post('/auth/login', { username, password, mfa_code });

export const getMe = () => API.get('/auth/me');
export const getMFASetup = () => API.get('/auth/mfa/setup');

// ── Dashboard ─────────────────────────────────────────────────
export const getDashboardStats = () => API.get('/dashboard/stats');
export const getHealth = () => API.get('/health');

// ── KMS ───────────────────────────────────────────────────────
export const listKeys = () => API.get('/kms/keys');
export const createKey = (data) => API.post('/kms/keys', data);
export const rotateKey = (id) => API.post(`/kms/keys/${id}/rotate`);
export const revokeKey = (id, reason) => API.post(`/kms/keys/${id}/revoke?reason=${reason}`);
export const encryptData = (data) => API.post('/kms/encrypt', data);
export const signData = (data) => API.post('/kms/sign', data);
export const verifySignature = (data) => API.post('/kms/verify', data);

// ── Vault ─────────────────────────────────────────────────────
export const listSecrets = () => API.get('/vault/secrets');
export const storeSecret = (data) => API.post('/vault/secrets', data);
export const getSecret = (id) => API.get(`/vault/secrets/${id}`);
export const rotateSecret = (id, newValue) =>
  API.post(`/vault/secrets/${id}/rotate?new_value=${encodeURIComponent(newValue)}`);
export const revokeSecret = (id, reason) =>
  API.post(`/vault/secrets/${id}/revoke?reason=${reason}`);
export const emergencyRevoke = () => API.post('/vault/emergency-revoke');

// ── PKI ───────────────────────────────────────────────────────
export const createRootCA = (org) => API.post(`/pki/root-ca?org=${encodeURIComponent(org)}`);
export const createIntermediateCA = (org) => API.post(`/pki/intermediate-ca?org=${encodeURIComponent(org)}`);
export const issueCertificate = (data) => API.post('/pki/certificates', data);
export const getCRL = () => API.get('/pki/crl');
export const ocspCheck = (id) => API.get(`/pki/ocsp/${id}`);
export const revokeCertificate = (id, reason) =>
  API.post(`/pki/certificates/${id}/revoke?reason=${reason}`);
export const generateCSR = (cn, org) =>
  API.post(`/pki/csr?common_name=${encodeURIComponent(cn)}&org=${encodeURIComponent(org)}`);

// ── Zero Trust ────────────────────────────────────────────────
export const evaluateAccess = (data) => API.post('/zerotrust/evaluate', data);
export const registerDevice = (fp, owner, name, trusted) =>
  API.post(`/zerotrust/devices?device_fingerprint=${fp}&owner=${owner}&device_name=${name}&trusted=${trusted}`);
export const getUserRiskProfile = (uid) => API.get(`/zerotrust/users/${uid}/risk`);

// ── SIEM ──────────────────────────────────────────────────────
export const ingestEvents = (events) => API.post('/siem/events', { events });
export const getAlerts = (status, severity, limit = 100) => {
  const params = new URLSearchParams({ limit });
  if (status) params.set('status', status);
  if (severity) params.set('severity', severity);
  return API.get(`/siem/alerts?${params}`);
};
export const updateAlert = (id, data) => API.patch(`/siem/alerts/${id}`, data);
export const correlateAlerts = () => API.post('/siem/correlate');
export const getSiemStats = () => API.get('/siem/stats');

// ── Threat Intel ──────────────────────────────────────────────
export const addIndicator = (data) => API.post('/threat-intel/indicators', data);
export const getIndicators = (type, severity) => {
  const params = new URLSearchParams();
  if (type) params.set('ioc_type', type);
  if (severity) params.set('severity', severity);
  return API.get(`/threat-intel/indicators?${params}`);
};
export const lookupIOC = (value) => API.get(`/threat-intel/lookup/${encodeURIComponent(value)}`);

// ── Forensics ─────────────────────────────────────────────────
export const collectArtifact = (formData) =>
  API.post('/forensics/artifacts', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });
export const listArtifacts = () => API.get('/forensics/artifacts');
export const verifyArtifact = (id) => API.get(`/forensics/artifacts/${id}/verify`);
export const transferCustody = (id, to, reason) =>
  API.post(`/forensics/artifacts/${id}/transfer?to_analyst=${to}&reason=${reason}`);

// ── Malware ───────────────────────────────────────────────────
export const uploadMalware = (formData) =>
  API.post('/malware/samples', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });
export const listMalware = () => API.get('/malware/samples');
export const analyzeMalware = (formData) =>
  API.post('/malware/analyze', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });

// ── Password Lab ──────────────────────────────────────────────
export const analyzePassword = (password) => API.post('/password/analyze', { password });
export const hashPassword = (password) => API.post('/password/hash', { password });

// ── Crypto Detection ──────────────────────────────────────────
export const scanCryptoThreats = (events) => API.post('/crypto-detect/scan', { network_events: events });

// ── PQC ───────────────────────────────────────────────────────
export const kyberKeygen = () => API.post('/pqc/kyber/keygen');
export const dilithiumKeygen = () => API.post('/pqc/dilithium/keygen');
export const getPQCAlgorithms = () => API.get('/pqc/algorithms');

// ── Blockchain ────────────────────────────────────────────────
export const getBlockchain = (type, limit) => {
  const params = new URLSearchParams({ limit: limit || 50 });
  if (type) params.set('data_type', type);
  return API.get(`/blockchain/chain?${params}`);
};
export const verifyChain = () => API.get('/blockchain/verify');
export const getBlockchainStats = () => API.get('/blockchain/stats');

// ── UEBA ──────────────────────────────────────────────────────
export const getAnomalies = (limit = 100) => API.get(`/ueba/anomalies?limit=${limit}`);
export const getUserRisk = (uid) => API.get(`/ueba/users/${uid}/risk`);

// ── Tenants ───────────────────────────────────────────────────
export const listTenants = () => API.get('/tenants');
export const createTenant = (id, name) =>
  API.post(`/tenants?tenant_id=${id}&name=${encodeURIComponent(name)}`);

export default API;
