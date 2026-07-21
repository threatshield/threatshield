import React, { useState, useEffect } from 'react';
import { apiService } from '../services/api';
import { useTheme } from '../context/ThemeContext';

interface ThreatModelSettings {
  preContext: string;
  darkMode?: boolean;
}

interface LLMConfig {
  method: 'OPENAI' | 'BEDROCK';
  model: string;
  base_url?: string;
  configured?: boolean;
}

const Settings: React.FC = () => {
  const { isDark } = useTheme();
  const [settings, setSettings] = useState<ThreatModelSettings>({
    preContext: '',
  });
  const [llmConfig, setLlmConfig] = useState<LLMConfig | null>(null);
  const [saveStatus, setSaveStatus] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const loadSettings = async () => {
      try {
        setIsLoading(true);
        const response = await apiService.getSettings();
        if (response?.data) {
          setSettings(response.data);
        }
        if (response?.llmConfig) {
          setLlmConfig(response.llmConfig);
        }
      } catch (error) {
        console.error('Error loading settings:', error);
      } finally {
        setIsLoading(false);
      }
    };
    loadSettings();
  }, []);

  const handleSaveSettings = async () => {
    try {
      setIsLoading(true);
      await apiService.saveSettings({ ...settings, darkMode: isDark });
      setSaveStatus('Settings saved successfully!');
      setTimeout(() => setSaveStatus(null), 3000);
    } catch (error) {
      console.error('Error saving settings:', error);
      setSaveStatus('Error saving settings. Please try again.');
      setTimeout(() => setSaveStatus(null), 3000);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading && !settings.preContext) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-14 h-14">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700"></div>
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin"></div>
          </div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Loading settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      <div className="px-6 py-8">

        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-1">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
              <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </div>
            <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Settings</h1>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400">Manage application preferences and threat modeling configuration.</p>
        </div>

        {/* Status Banner */}
        {saveStatus && (
          <div className={`mb-6 px-4 py-3 rounded-lg text-sm font-medium flex items-center gap-2 ${
            saveStatus.includes('Error')
              ? 'bg-red-50 text-red-700 border border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800'
              : 'bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800'
          }`}>
            {saveStatus.includes('Error')
              ? (
                <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              ) : (
                <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              )
            }
            {saveStatus}
          </div>
        )}

        {/* Model Configuration Card */}
        {llmConfig && (
          <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden mb-6">
            <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Model Configuration</h2>
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold border ${
                llmConfig.method === 'BEDROCK'
                  ? 'bg-violet-50 text-violet-700 border-violet-200 dark:bg-violet-900/20 dark:text-violet-400 dark:border-violet-800/40'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800/40'
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${llmConfig.method === 'BEDROCK' ? 'bg-violet-500' : 'bg-emerald-500'}`} />
                {llmConfig.method === 'BEDROCK' ? 'AWS Bedrock' : 'OpenAI'}
              </span>
            </div>
            <div className="px-6 py-5">
              <p className="text-xs text-slate-400 dark:text-slate-500 mb-4">
                Configured via <code className="bg-slate-100 dark:bg-gray-800 text-slate-600 dark:text-slate-400 px-1.5 py-0.5 rounded text-xs">.env</code> — read-only.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {/* Method */}
                <div className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-4 border border-slate-200 dark:border-gray-700/60">
                  <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">LLM Method</p>
                  <div className="flex items-center gap-2">
                    {llmConfig.method === 'BEDROCK' ? (
                      <svg className="w-4 h-4 text-violet-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                      </svg>
                    ) : (
                      <svg className="w-4 h-4 text-emerald-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
                      </svg>
                    )}
                    <p className="text-sm font-semibold text-slate-800 dark:text-slate-100">
                      {llmConfig.method === 'BEDROCK' ? 'AWS Bedrock' : 'OpenAI'}
                    </p>
                  </div>
                </div>

                {/* Model */}
                <div className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-4 border border-slate-200 dark:border-gray-700/60">
                  <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Model</p>
                  <p className="text-sm font-semibold text-slate-800 dark:text-slate-100 font-mono">{llmConfig.model}</p>
                </div>

                {/* Endpoint / Status */}
                {llmConfig.method === 'BEDROCK' && llmConfig.base_url ? (
                  <div className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-4 border border-slate-200 dark:border-gray-700/60">
                    <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Endpoint</p>
                    <p className="text-sm font-semibold text-slate-800 dark:text-slate-100 font-mono truncate" title={llmConfig.base_url}>
                      {llmConfig.base_url}
                    </p>
                  </div>
                ) : llmConfig.method === 'OPENAI' ? (
                  <div className={`rounded-lg p-4 border ${
                    llmConfig.configured
                      ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800/40'
                      : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800/40'
                  }`}>
                    <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">API Key</p>
                    <div className="flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${llmConfig.configured ? 'bg-emerald-500' : 'bg-red-400'}`} />
                      <p className={`text-sm font-semibold ${
                        llmConfig.configured
                          ? 'text-emerald-700 dark:text-emerald-400'
                          : 'text-red-600 dark:text-red-400'
                      }`}>
                        {llmConfig.configured ? 'Configured' : 'Not configured'}
                      </p>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        )}

        {/* Pre-Context Configuration Card */}
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden mb-6">
          <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Pre-Context Configuration</h2>
          </div>
          <div className="px-6 py-6 space-y-4">
            <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
              Document existing security mechanisms or controls in your organization. This prevents false positives during threat modeling by acknowledging implemented security measures.
            </p>
            <div>
              <label htmlFor="preContext" className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                Security Controls and Mechanisms
              </label>
              <textarea
                id="preContext"
                rows={10}
                value={settings.preContext}
                onChange={(e) => setSettings(prev => ({ ...prev, preContext: e.target.value }))}
                placeholder="Describe existing security controls, authentication mechanisms, encryption standards, etc."
                className="w-full px-3 py-2.5 text-sm border rounded-lg text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc] transition-all resize-none bg-white dark:bg-gray-800 border-slate-200 dark:border-gray-700"
              />
            </div>
          </div>
        </div>

        {/* Save Button */}
        <div className="flex justify-end">
          <button
            onClick={handleSaveSettings}
            disabled={isLoading}
            className="px-5 py-2.5 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] focus:outline-none focus:ring-2 focus:ring-[#0052cc] focus:ring-offset-2 dark:focus:ring-offset-transparent transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
          >
            {isLoading ? (
              <span className="flex items-center gap-2">
                <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Saving...
              </span>
            ) : 'Save Settings'}
          </button>
        </div>

      </div>
    </div>
  );
};

export default Settings;
