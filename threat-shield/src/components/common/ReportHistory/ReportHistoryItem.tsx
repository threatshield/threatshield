import React, { useState, useEffect } from 'react';
import { ReportMetadata } from '../../../types/reportTypes';

interface ReportHistoryItemProps {
  report: ReportMetadata;
  onClick: () => void;
  onDelete?: () => void;
  buttonText?: string;
}

const BADGE_CONFIG = [
  {
    key: 'threat_model',
    label: 'Threat Model',
    color: 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800/40',
    dot: 'bg-emerald-500',
    check: (r: ReportMetadata) => r.threat_model?.result !== undefined,
  },
  {
    key: 'dread_assessment',
    label: 'DREAD',
    color: 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800/40',
    dot: 'bg-amber-500',
    check: (r: ReportMetadata) => r.dread_assessment?.result !== undefined,
  },
  {
    key: 'mitigation',
    label: 'Mitigation',
    color: 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-900/20 dark:text-rose-400 dark:border-rose-800/40',
    dot: 'bg-rose-500',
    check: (r: ReportMetadata) => r.mitigation?.result !== undefined,
  },
  {
    key: 'attack_tree',
    label: 'Attack Tree',
    color: 'bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-900/20 dark:text-sky-400 dark:border-sky-800/40',
    dot: 'bg-sky-500',
    check: (r: ReportMetadata) => r.attack_tree?.result !== undefined,
  },
  {
    key: 'test_cases',
    label: 'Test Cases',
    color: 'bg-violet-50 text-violet-700 border-violet-200 dark:bg-violet-900/20 dark:text-violet-400 dark:border-violet-800/40',
    dot: 'bg-violet-500',
    check: (r: ReportMetadata) =>
      Array.isArray(r.test_cases?.result?.test_cases) && r.test_cases!.result.test_cases.length > 0,
  },
];

const ReportHistoryItem: React.FC<ReportHistoryItemProps> = ({ report, onClick, onDelete, buttonText = 'View Report' }) => {
  const [isAdmin, setIsAdmin] = useState<boolean>(false);

  useEffect(() => {
    const cookies = document.cookie.split(';');
    const adminCookie = cookies.find(cookie => cookie.trim().startsWith('admin='));
    setIsAdmin(adminCookie?.split('=')[1]?.toLowerCase() === 'true');
  }, []);

  const formatDate = (dateString: string) => {
    try {
      const date = new Date(dateString);
      const now = new Date();
      const diffDays = Math.floor(Math.abs(now.getTime() - date.getTime()) / 86400000);
      if (diffDays === 0) return `Today at ${date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
      if (diffDays === 1) return `Yesterday at ${date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
      if (diffDays < 7) return `${diffDays} days ago`;
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    } catch {
      return 'Unknown date';
    }
  };

  const getTestCaseCounts = () => {
    if (!Array.isArray(report.test_cases?.result?.test_cases)) return { total: 0, validated: 0 };
    const testCases = report.test_cases!.result.test_cases.filter((tc: any) => tc?.asvs_requirement !== 'Error');
    return {
      total: testCases.length,
      validated: testCases.filter((tc: any) => tc?.validated === true).length,
    };
  };

  const activeBadges = BADGE_CONFIG.filter(b => b.check(report));
  const { total: tcTotal, validated: tcValidated } = getTestCaseCounts();
  const validationPct = tcTotal > 0 ? Math.round((tcValidated / tcTotal) * 100) : 0;

  const projectName = report.details?.projectName ?? report.name;
  const department = report.details?.department;
  const methodology = report.details?.threatModelingMethodology;

  return (
    <div
      onClick={onClick}
      className="group relative bg-white dark:bg-gray-900 border border-slate-200 dark:border-gray-800 rounded-xl p-4 cursor-pointer transition-all duration-200 hover:border-[#0052cc]/40 dark:hover:border-blue-700/50 hover:shadow-[0_4px_20px_rgba(0,82,204,0.07)] dark:-translate-y-px"
    >
      {/* Top row */}
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-start gap-3 min-w-0">
          {/* Icon */}
          <div className="mt-0.5 w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-100 dark:border-blue-800/40 flex items-center justify-center flex-shrink-0">
            <svg style={{ width: 15, height: 15 }} className="text-[#0052cc] dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>

          {/* Title block */}
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5 flex-wrap mb-0.5">
              {department && (
                <span className="inline-block text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-100 dark:bg-gray-700 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-gray-600">
                  {department}
                </span>
              )}
              {methodology && (
                <span className="inline-block text-[10px] font-medium px-1.5 py-0.5 rounded bg-blue-50 dark:bg-blue-900/20 text-[#0052cc] dark:text-blue-400 border border-blue-100 dark:border-blue-800/40">
                  {methodology}
                </span>
              )}
            </div>
            <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-200 leading-snug truncate max-w-xs group-hover:text-[#0052cc] dark:group-hover:text-blue-400 transition-colors">
              {projectName}
            </h4>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="flex items-center gap-1 text-xs text-slate-400 dark:text-slate-500">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {formatDate(report.timestamp)}
              </span>
              <span className="text-xs text-slate-300 dark:text-slate-600 font-mono hidden sm:inline">{report.id.slice(0, 8)}…</span>
            </div>
          </div>
        </div>

        {/* Right: controls */}
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <div className="opacity-0 group-hover:opacity-100 transition-all duration-200 translate-x-1 group-hover:translate-x-0">
            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0052cc] text-white text-xs font-semibold rounded-lg shadow-sm hover:bg-[#0047b3] transition-colors whitespace-nowrap">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
              {buttonText}
            </div>
          </div>

          {isAdmin && onDelete && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                if (window.confirm('Are you sure you want to delete this threat model? This action cannot be undone.')) {
                  onDelete();
                }
              }}
              className="p-1.5 text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 dark:hover:text-red-400 rounded-md transition-all duration-150 opacity-0 group-hover:opacity-100"
              title="Delete"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          )}
        </div>
      </div>

      {/* Badges */}
      {activeBadges.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-2.5">
          {activeBadges.map(badge => (
            <span
              key={badge.key}
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${badge.color}`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${badge.dot}`} />
              {badge.key === 'test_cases' && tcTotal > 0
                ? `${badge.label} ${tcValidated}/${tcTotal}`
                : badge.label}
            </span>
          ))}
        </div>
      )}

      {/* Validation progress */}
      {tcTotal > 0 && (
        <div className="flex items-center gap-2.5">
          <span className="text-xs text-slate-500 dark:text-slate-400 w-24 flex-shrink-0">Test validation</span>
          <div className="flex-1 bg-slate-100 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-emerald-500 transition-all duration-500"
              style={{ width: `${validationPct}%` }}
            />
          </div>
          <span className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 w-8 text-right">{validationPct}%</span>
        </div>
      )}
    </div>
  );
};

export default ReportHistoryItem;
