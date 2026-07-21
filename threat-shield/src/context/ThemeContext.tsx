import React, { createContext, useContext, useEffect, useState } from 'react';
import { apiService } from '../services/api';

interface ThemeContextValue {
  isDark: boolean;
  toggleDark: () => void;
}

const ThemeContext = createContext<ThemeContextValue>({ isDark: false, toggleDark: () => {} });

export const useTheme = () => useContext(ThemeContext);

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isDark, setIsDark] = useState(false);

  // Load dark mode preference from settings on mount
  useEffect(() => {
    apiService.getSettings()
      .then((res: any) => {
        const dark = res?.data?.darkMode === true;
        setIsDark(dark);
        document.documentElement.classList.toggle('dark', dark);
      })
      .catch(() => {
        // fallback: check localStorage
        const stored = localStorage.getItem('darkMode');
        const dark = stored === 'true';
        setIsDark(dark);
        document.documentElement.classList.toggle('dark', dark);
      });
  }, []);

  const toggleDark = () => {
    const next = !isDark;
    setIsDark(next);
    document.documentElement.classList.toggle('dark', next);
    localStorage.setItem('darkMode', String(next));
    // Persist to settings.json via API (best-effort)
    apiService.getSettings()
      .then((res: any) => {
        const current = res?.data ?? {};
        return apiService.saveSettings({ ...current, darkMode: next });
      })
      .catch(() => {});
  };

  return (
    <ThemeContext.Provider value={{ isDark, toggleDark }}>
      {children}
    </ThemeContext.Provider>
  );
};
