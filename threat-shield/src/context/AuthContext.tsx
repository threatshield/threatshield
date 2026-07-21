import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { API_BASE_URL } from '../services/api';

const TOKEN_KEY = 'ts_auth_token';

export interface AuthUser {
  email: string;
  name: string;
  picture: string;
}

interface AuthContextType {
  user: AuthUser | null;
  loading: boolean;
  isMcpAdmin: boolean;
  login: (googleToken: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [isMcpAdmin, setIsMcpAdmin] = useState(false);

  // On mount, validate any existing stored token
  useEffect(() => {
    const stored = localStorage.getItem(TOKEN_KEY);
    if (!stored) {
      setLoading(false);
      return;
    }
    fetch(`${API_BASE_URL}/auth/user`, {
      headers: { Authorization: `Bearer ${stored}` },
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data?.user) {
          setUser(data.user);
          // Check MCP admin status after confirming user is authenticated
          return fetch(`${API_BASE_URL}/mcp-admin-check`, {
            headers: { Authorization: `Bearer ${stored}` },
          }).then((r) => r.ok ? r.json() : null).then((d) => {
            if (d?.is_admin) setIsMcpAdmin(true);
          }).catch(() => {});
        } else {
          localStorage.removeItem(TOKEN_KEY);
        }
      })
      .catch(() => localStorage.removeItem(TOKEN_KEY))
      .finally(() => setLoading(false));
  }, []);

  const login = async (googleToken: string) => {
    const res = await fetch(`${API_BASE_URL}/auth/google`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: googleToken }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Login failed');
    }
    const data = await res.json();
    localStorage.setItem(TOKEN_KEY, data.token);
    setUser(data.user);
    // Check MCP admin status after login
    fetch(`${API_BASE_URL}/mcp-admin-check`, {
      headers: { Authorization: `Bearer ${data.token}` },
    }).then((r) => r.ok ? r.json() : null).then((d) => {
      setIsMcpAdmin(d?.is_admin === true);
    }).catch(() => {});
  };

  const logout = async () => {
    const stored = localStorage.getItem(TOKEN_KEY);
    localStorage.removeItem(TOKEN_KEY);
    setUser(null);
    setIsMcpAdmin(false);
    if (stored) {
      fetch(`${API_BASE_URL}/auth/logout`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${stored}` },
      }).catch(() => {});
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, isMcpAdmin, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
};
