// Global state store
import { create } from 'zustand';

export const useStore = create((set, get) => ({
  // Auth
  token: localStorage.getItem('aegis_token') || null,
  user: null,
  setToken: (token) => {
    localStorage.setItem('aegis_token', token);
    set({ token });
  },
  setUser: (user) => set({ user }),
  logout: () => {
    localStorage.removeItem('aegis_token');
    set({ token: null, user: null });
  },

  // Dashboard stats
  stats: null,
  setStats: (stats) => set({ stats }),

  // Alerts
  alerts: [],
  setAlerts: (alerts) => set({ alerts }),
  addAlert: (alert) => set(s => ({ alerts: [alert, ...s.alerts].slice(0, 500) })),

  // Active tab
  activeModule: 'dashboard',
  setActiveModule: (mod) => set({ activeModule: mod }),

  // Loading states
  loading: {},
  setLoading: (key, val) => set(s => ({ loading: { ...s.loading, [key]: val } })),

  // Notifications
  notifications: [],
  addNotification: (n) => set(s => ({
    notifications: [{ id: Date.now(), ...n }, ...s.notifications].slice(0, 50)
  })),
}));
