import React, { useState, useEffect } from 'react';
import { API_BASE_URL } from '../services/api';

interface ConnectionStatus {
  connected: boolean;
  message: string;
}

interface SlackChannel {
  id: string;
  name: string;
  is_private: boolean;
}

interface Connections {
  openai?: ConnectionStatus;
  jira?: ConnectionStatus;
  confluence?: ConnectionStatus;
  slack?: ConnectionStatus;
  google_docs?: ConnectionStatus;
  slack_channels?: SlackChannel[];
}

const CONNECTION_LABELS: Record<string, string> = {
  openai: 'OpenAI',
  jira: 'JIRA',
  confluence: 'Confluence',
  slack: 'Slack',
  google_docs: 'Google Docs',
};

const CONNECTION_ORDER = ['openai', 'jira', 'confluence', 'slack', 'google_docs'] as const;

const SERVICE_ICONS: Record<string, React.ReactNode> = {
  openai: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456z" />
    </svg>
  ),
  jira: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
    </svg>
  ),
  confluence: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
    </svg>
  ),
  slack: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7.5 8.25h9m-9 3H12m-9.75 1.51c0 1.6 1.123 2.994 2.707 3.227 1.129.166 2.27.293 3.423.379.35.026.67.21.865.501L12 21l2.755-4.133a1.14 1.14 0 01.865-.501 48.172 48.172 0 003.423-.379c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z" />
    </svg>
  ),
  google_docs: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" />
    </svg>
  ),
};

const Integrations: React.FC = () => {
  const [connections, setConnections] = useState<Connections | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkConnections();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const checkConnections = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/connections`);
      if (response.ok) {
        const data = await response.json();
        setConnections(data);
      }
    } catch (error) {
      console.error('Error checking connections:', error);
    } finally {
      setLoading(false);
    }
  };

  const connectedCount = connections
    ? CONNECTION_ORDER.filter(k => connections[k]?.connected).length
    : 0;

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      <div className="px-6 py-8">

        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
                  <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                  </svg>
                </div>
                <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Integrations</h1>
              </div>
              <p className="text-sm text-slate-500 dark:text-slate-400">External services connected to ThreatShield</p>
            </div>
            <button
              onClick={checkConnections}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 text-slate-600 text-sm font-medium rounded-lg hover:border-[#0052cc]/40 hover:text-[#0052cc] hover:bg-blue-50/50 dark:bg-gray-800/60 dark:border-gray-700 dark:text-slate-300 transition-all duration-200 shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : (
                <svg className="h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              )}
              {loading ? 'Checking...' : 'Refresh'}
            </button>
          </div>
        </div>

        {/* Summary Stat Card */}
        {connections && !loading && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
            <div className="bg-white border border-slate-200 dark:bg-gray-900/80 dark:border-gray-700/60 rounded-xl p-4 shadow-sm">
              <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Connected</p>
              <p className="text-2xl font-bold text-slate-800 dark:text-slate-100">{connectedCount} <span className="text-sm font-normal text-slate-400">/ {CONNECTION_ORDER.length}</span></p>
            </div>
            <div className={`border rounded-xl p-4 shadow-sm ${
              connectedCount === CONNECTION_ORDER.length
                ? 'bg-white dark:bg-gray-900/80 border-emerald-100 dark:border-emerald-800/40'
                : 'bg-white dark:bg-gray-900/80 border-amber-100 dark:border-amber-800/40'
            }`}>
              <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Status</p>
              <p className={`text-sm font-semibold ${
                connectedCount === CONNECTION_ORDER.length
                  ? 'text-emerald-600 dark:text-emerald-400'
                  : 'text-amber-600 dark:text-amber-400'
              }`}>
                {connectedCount === CONNECTION_ORDER.length ? 'All Systems OK' : 'Partial'}
              </p>
            </div>
          </div>
        )}

        {/* Services Grid */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-7 h-7 rounded-lg bg-blue-50 border border-blue-200 dark:bg-blue-900/20 dark:border-blue-800/40 flex items-center justify-center">
              <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">Services</h2>
          </div>

          {loading && !connections ? (
            <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm flex items-center justify-center py-16">
              <div className="flex flex-col items-center gap-4">
                <div className="relative w-10 h-10">
                  <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
                  <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
                </div>
                <p className="text-sm text-slate-400 dark:text-slate-500">Checking connections...</p>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {CONNECTION_ORDER.map((key) => {
                const conn = connections?.[key];
                const isConnected = conn?.connected ?? false;
                return (
                  <div
                    key={key}
                    className={`bg-white dark:bg-gray-900/80 rounded-xl border shadow-sm p-5 transition-all ${
                      isConnected
                        ? 'border-slate-200 dark:border-gray-700/60'
                        : 'border-slate-200 dark:border-gray-700/60'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-3">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${
                          isConnected
                            ? 'bg-blue-50 dark:bg-blue-900/20 text-[#0052cc] dark:text-blue-400'
                            : 'bg-slate-100 dark:bg-gray-800/60 text-slate-400 dark:text-slate-500'
                        }`}>
                          {SERVICE_ICONS[key]}
                        </div>
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">{CONNECTION_LABELS[key]}</p>
                          <p className={`text-xs mt-0.5 leading-relaxed ${
                            isConnected
                              ? 'text-emerald-600 dark:text-emerald-400'
                              : 'text-slate-400 dark:text-slate-500'
                          }`}>
                            {conn?.message ?? 'No status available'}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <span className={`inline-block w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-500' : 'bg-red-400'}`} />
                        <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${
                          isConnected
                            ? 'bg-emerald-50 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/50'
                            : 'bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800/50'
                        }`}>
                          {isConnected ? 'Connected' : 'Not connected'}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>


        {/* Slack Channels Section */}
        {connections?.slack?.connected && (
          <div className="mt-8 mb-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-7 h-7 rounded-lg bg-blue-50 border border-blue-200 dark:bg-blue-900/20 dark:border-blue-800/40 flex items-center justify-center">
                <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14" />
                </svg>
              </div>
              <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">Slack Channels</h2>
              {connections.slack_channels && connections.slack_channels.length > 0 && (
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-blue-50 text-[#0052cc] border border-blue-100 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800/40">
                  {connections.slack_channels.length}
                </span>
              )}
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-400 mb-3">
              Channels the bot has been added to and can read threads from.
            </p>

            {connections.slack_channels && connections.slack_channels.length > 0 ? (
              <div className="bg-white border border-slate-200 dark:bg-gray-900/80 dark:border-gray-700/60 rounded-xl overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 dark:bg-gray-800/60 dark:border-gray-700/60">
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3">Channel</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3">Type</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3">Channel ID</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-gray-800/60">
                      {connections.slack_channels.map(ch => (
                        <tr key={ch.id} className="hover:bg-slate-50/70 dark:hover:bg-gray-800/40 transition-colors">
                          <td className="px-5 py-3.5 font-medium text-slate-800 dark:text-slate-200">#{ch.name}</td>
                          <td className="px-5 py-3.5">
                            <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full font-semibold border ${
                              ch.is_private
                                ? 'bg-amber-50 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800/50'
                                : 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-800/50'
                            }`}>
                              {ch.is_private ? (
                                <>
                                  <svg className="h-3 w-3" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                                  </svg>
                                  Private
                                </>
                              ) : (
                                <>
                                  <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14" />
                                  </svg>
                                  Public
                                </>
                              )}
                            </span>
                          </td>
                          <td className="px-5 py-3.5 text-slate-400 dark:text-slate-500 font-mono text-xs">{ch.id}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-amber-100 dark:border-amber-800/40 shadow-sm p-5">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-amber-50 border border-amber-200 dark:bg-amber-900/20 dark:border-amber-800/40 flex items-center justify-center flex-shrink-0">
                    <svg className="h-4 w-4 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-slate-700 dark:text-slate-300">Bot has no channel access</p>
                    <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                      The Slack bot is authenticated but has not been added to any channels.
                      Invite it with{' '}
                      <code className="bg-slate-100 dark:bg-gray-800 text-slate-700 dark:text-slate-300 px-1.5 py-0.5 rounded text-xs">/invite @YourBotName</code>
                      {' '}in each channel.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Slack Not Connected Info */}
        {connections && !connections.slack?.connected && (
          <div className="mt-8 bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 dark:bg-blue-900/20 dark:border-blue-800/40 flex items-center justify-center flex-shrink-0">
                <svg className="h-4 w-4 text-[#0052cc]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                Configure{' '}
                <code className="bg-slate-100 dark:bg-gray-800 text-slate-700 dark:text-slate-300 px-1.5 py-0.5 rounded text-xs">SLACK_API_TOKEN</code>
                {' '}in your{' '}
                <code className="bg-slate-100 dark:bg-gray-800 text-slate-700 dark:text-slate-300 px-1.5 py-0.5 rounded text-xs">.env</code>
                {' '}file to enable Slack thread reading.
              </p>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};

export default Integrations;
