import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { API_BASE_URL } from '../services/api';

interface FeedbackEntry {
  uuid: string;
  assessment_id: string;
  assessment_name: string;
  created_for: string;
  created_at: string;
  submitted: boolean;
  submitted_at: string | null;
  threat_modeling_methodology?: string;
  department?: string;
  answers: {
    threat_coverage?: number;
    threat_accuracy?: number;
    false_positive_count?: number;
    missing_threats_count?: number;
    dread_accuracy?: number;
    mitigation_quality?: number;
    test_case_relevance?: number;
    overall_usefulness?: number;
    would_recommend?: number;
    improvement_suggestions?: string;
  };
}

const SCORE_LABELS = ['', 'Poor', 'Below Avg', 'Average', 'Good', 'Excellent'];
const SCORE_COLORS: Record<number, string> = {
  1: 'text-red-400',
  2: 'text-orange-400',
  3: 'text-yellow-400',
  4: 'text-blue-400',
  5: 'text-emerald-400',
};

const ScoreBar: React.FC<{ value?: number }> = ({ value }) => {
  if (value === undefined || value === 0) return <span className="text-slate-600 text-xs">—</span>;
  return (
    <span className={`text-sm font-bold ${SCORE_COLORS[value] ?? 'text-slate-400'}`}>
      {value}/5 <span className="text-xs font-normal opacity-70">{SCORE_LABELS[value]}</span>
    </span>
  );
};

const formatDate = (iso: string) =>
  new Date(iso).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });

const averageScore = (answers: FeedbackEntry['answers']): number | null => {
  const keys: (keyof typeof answers)[] = [
    'threat_coverage', 'threat_accuracy', 'dread_accuracy',
    'mitigation_quality', 'test_case_relevance', 'overall_usefulness',
  ];
  const vals = keys.map(k => answers[k] as number).filter(v => v > 0);
  if (!vals.length) return null;
  return Math.round((vals.reduce((a, b) => a + b, 0) / vals.length) * 10) / 10;
};

const FeedbackList: React.FC = () => {
  const [feedbacks, setFeedbacks] = useState<FeedbackEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'submitted' | 'pending'>('all');
  const [departmentFilter, setDepartmentFilter] = useState<string>('all');
  const [methodologyFilter, setMethodologyFilter] = useState<string>('all');

  const frontendBase = window.location.origin;

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/feedback`);
        if (!res.ok) throw new Error('Failed to load feedback list');
        const data = await res.json();
        const sorted = (data.feedbacks as FeedbackEntry[]).sort(
          (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
        );
        setFeedbacks(sorted);
      } catch (e: any) {
        setError(e.message || 'Unknown error');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const visible = feedbacks.filter(f => {
    if (filter === 'submitted' && !f.submitted) return false;
    if (filter === 'pending' && f.submitted) return false;
    if (departmentFilter !== 'all' && (f.department || '').toLowerCase() !== departmentFilter.toLowerCase()) return false;
    if (methodologyFilter !== 'all' && (f.threat_modeling_methodology || '').toLowerCase() !== methodologyFilter.toLowerCase()) return false;
    return true;
  });

  const uniqueDepartments = Array.from(new Set(feedbacks.map(f => f.department).filter(Boolean))) as string[];
  const uniqueMethodologies = Array.from(new Set(feedbacks.map(f => f.threat_modeling_methodology).filter(Boolean))) as string[];

  const totalSubmitted = feedbacks.filter(f => f.submitted).length;

  const STATUS_LABELS = { all: 'All', submitted: 'Submitted', pending: 'Pending' } as const;
  const statusCount = { all: feedbacks.length, submitted: totalSubmitted, pending: feedbacks.length - totalSubmitted };

  const copyLink = (uuid: string) => {
    navigator.clipboard.writeText(`${frontendBase}/provide-feedback/${uuid}`);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-12 h-12">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
          </div>
          <p className="text-sm text-slate-400">Loading feedback…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      <div className="px-6 py-8">

        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-1">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
              <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
            </div>
            <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Feedback</h1>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Feedback requests for threat models you initiated. Sent to you via Slack when each assessment completes.
          </p>
        </div>

        {error && (
          <div className="mb-6 px-4 py-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/40 text-red-700 dark:text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Stats bar */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          {[
            { label: 'Total Requests', value: feedbacks.length, color: 'text-blue-600 dark:text-blue-400' },
            { label: 'Submitted', value: totalSubmitted, color: 'text-emerald-600 dark:text-emerald-400' },
            { label: 'Pending', value: feedbacks.length - totalSubmitted, color: 'text-amber-600 dark:text-amber-400' },
          ].map(s => (
            <div key={s.label} className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 px-5 py-4 shadow-sm">
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">{s.label}</p>
              <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* Filter toolbar */}
        <div className="flex items-center bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl shadow-sm mb-5 overflow-hidden">
          {/* Status segment */}
          <div className="flex items-center gap-1 px-3 py-2.5">
            {(['all', 'submitted', 'pending'] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-all ${
                  filter === f
                    ? 'bg-[#0052cc] text-white shadow-sm'
                    : 'text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-gray-700/60 hover:text-slate-700 dark:hover:text-slate-200'
                }`}
              >
                {STATUS_LABELS[f]}
                <span className={`ml-1.5 text-[10px] px-1 py-px rounded font-semibold ${
                  filter === f ? 'bg-white/20 text-white' : 'bg-slate-100 dark:bg-gray-700 text-slate-500 dark:text-slate-400'
                }`}>
                  {statusCount[f]}
                </span>
              </button>
            ))}
          </div>

          {/* Divider */}
          <div className="w-px self-stretch bg-slate-100 dark:bg-gray-700/60" />

          {/* Department */}
          {uniqueDepartments.length > 0 && (
            <div className="flex items-center gap-2 px-4 py-2.5">
              <span className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider whitespace-nowrap">Department</span>
              <select
                value={departmentFilter}
                onChange={e => setDepartmentFilter(e.target.value)}
                className={`text-xs font-medium rounded-md px-2 py-1 border transition-all focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 cursor-pointer ${
                  departmentFilter === 'all'
                    ? 'border-slate-200 dark:border-gray-700 bg-slate-50 dark:bg-gray-800 text-slate-600 dark:text-slate-300'
                    : 'border-violet-300 dark:border-violet-700 bg-violet-50 dark:bg-violet-900/20 text-violet-700 dark:text-violet-300'
                }`}
              >
                <option value="all">All</option>
                {uniqueDepartments.map(department => <option key={department} value={department}>{department}</option>)}
              </select>
            </div>
          )}

          {/* Methodology */}
          {uniqueMethodologies.length > 0 && (
            <>
              <div className="w-px self-stretch bg-slate-100 dark:bg-gray-700/60" />
              <div className="flex items-center gap-2 px-4 py-2.5">
                <span className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider whitespace-nowrap">Methodology</span>
                <select
                  value={methodologyFilter}
                  onChange={e => setMethodologyFilter(e.target.value)}
                  className={`text-xs font-medium rounded-md px-2 py-1 border transition-all focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 cursor-pointer ${
                    methodologyFilter === 'all'
                      ? 'border-slate-200 dark:border-gray-700 bg-slate-50 dark:bg-gray-800 text-slate-600 dark:text-slate-300'
                      : 'border-sky-300 dark:border-sky-700 bg-sky-50 dark:bg-sky-900/20 text-sky-700 dark:text-sky-300'
                  }`}
                >
                  <option value="all">All</option>
                  {uniqueMethodologies.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
            </>
          )}

          {/* Spacer + result count + clear */}
          <div className="flex items-center gap-3 px-4 py-2.5 ml-auto">
            <span className="text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap">
              {visible.length === feedbacks.length ? `${feedbacks.length} results` : `${visible.length} of ${feedbacks.length}`}
            </span>
            {(departmentFilter !== 'all' || methodologyFilter !== 'all') && (
              <button
                onClick={() => { setDepartmentFilter('all'); setMethodologyFilter('all'); }}
                className="flex items-center gap-1 text-xs font-medium text-slate-400 hover:text-red-500 dark:hover:text-red-400 transition-colors"
              >
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" />
                </svg>
                Clear
              </button>
            )}
          </div>
        </div>

        {/* List */}
        {visible.length === 0 ? (
          <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 px-6 py-12 text-center shadow-sm">
            <p className="text-sm text-slate-400">No feedback requests found for your account.</p>
            <p className="text-xs text-slate-500 mt-1">Feedback links are sent to you via Slack when a threat model you initiated completes.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {visible.map(entry => {
              const avg = entry.submitted ? averageScore(entry.answers) : null;
              const isOpen = expanded === entry.uuid;
              const feedbackUrl = `${frontendBase}/provide-feedback/${entry.uuid}`;
              return (
                <div
                  key={entry.uuid}
                  className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden"
                >
                  {/* Row header */}
                  <div
                    className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors"
                    onClick={() => setExpanded(isOpen ? null : entry.uuid)}
                  >
                    {/* Status dot */}
                    <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${entry.submitted ? 'bg-emerald-500' : 'bg-amber-400'}`} />

                    {/* Main info */}
                    <div className="flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold text-slate-800 dark:text-slate-100">
                          {entry.assessment_name}
                        </span>
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium border ${
                          entry.submitted
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800/40'
                            : 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800/40'
                        }`}>
                          {entry.submitted ? 'Submitted' : 'Awaiting Response'}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 mt-1 flex-wrap">
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          Created {formatDate(entry.created_at)}
                        </p>
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-100 dark:bg-gray-800 border border-slate-200 dark:border-gray-700/60 font-mono text-[10px] text-slate-500 dark:text-slate-400 select-all">
                          {entry.assessment_id}
                        </span>
                        {entry.department && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-violet-50 text-violet-600 border border-violet-200 dark:bg-violet-900/20 dark:text-violet-400 dark:border-violet-800/40">
                            {entry.department}
                          </span>
                        )}
                        {entry.threat_modeling_methodology && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-sky-50 text-sky-600 border border-sky-200 dark:bg-sky-900/20 dark:text-sky-400 dark:border-sky-800/40">
                            {entry.threat_modeling_methodology}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Avg score */}
                    {avg !== null && (
                      <div className="flex-shrink-0 text-right">
                        <p className="text-xs text-slate-400 dark:text-slate-500 mb-0.5">Avg Score</p>
                        <p className={`text-base font-bold ${avg >= 4 ? 'text-emerald-500' : avg >= 3 ? 'text-blue-400' : 'text-orange-400'}`}>
                          {avg}/5
                        </p>
                      </div>
                    )}

                    {/* Copy link */}
                    <button
                      onClick={e => { e.stopPropagation(); copyLink(entry.uuid); }}
                      title="Copy feedback link"
                      className="flex-shrink-0 p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-gray-700/60 transition-all"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>

                    {/* Open in new tab */}
                    <a
                      href={feedbackUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      title="Open feedback link"
                      onClick={e => e.stopPropagation()}
                      className="flex-shrink-0 p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-gray-700/60 transition-all"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </a>

                    {/* View Threat Model */}
                    <Link
                      to={`/view-threat-model/${entry.assessment_id}`}
                      onClick={e => e.stopPropagation()}
                      title="View Threat Model"
                      className="flex-shrink-0 flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium bg-blue-50 text-[#0052cc] border border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800/40 hover:bg-blue-100 dark:hover:bg-blue-900/30 transition-all"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                      View
                    </Link>

                    {/* Expand chevron */}
                    <svg
                      className={`w-4 h-4 text-slate-400 flex-shrink-0 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`}
                      fill="none" viewBox="0 0 24 24" stroke="currentColor"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </div>

                  {/* Expanded detail */}
                  {isOpen && (
                    <div className="border-t border-slate-100 dark:border-gray-800 px-5 py-5 space-y-5">
                      {/* Feedback link */}
                      <div>
                        <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1.5">Feedback Link</p>
                        <div className="flex items-center gap-2 bg-slate-50 dark:bg-gray-800/60 rounded-lg px-3 py-2 border border-slate-200 dark:border-gray-700/40">
                          <span className="text-xs text-slate-600 dark:text-slate-300 truncate flex-1">{feedbackUrl}</span>
                          <button
                            onClick={() => copyLink(entry.uuid)}
                            className="flex-shrink-0 text-xs text-[#0052cc] hover:underline font-medium"
                          >
                            Copy
                          </button>
                          <a
                            href={feedbackUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex-shrink-0 text-xs text-[#0052cc] hover:underline font-medium"
                          >
                            Open
                          </a>
                        </div>
                      </div>

                      {entry.submitted ? (
                        <>
                          <div>
                            <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-3">Quality Ratings</p>
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                              {[
                                { label: 'Threat Coverage', key: 'threat_coverage' },
                                { label: 'Threat Accuracy', key: 'threat_accuracy' },
                                { label: 'DREAD Accuracy', key: 'dread_accuracy' },
                                { label: 'Mitigation Quality', key: 'mitigation_quality' },
                                { label: 'Test Case Relevance', key: 'test_case_relevance' },
                                { label: 'Overall Usefulness', key: 'overall_usefulness' },
                              ].map(q => (
                                <div key={q.key} className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-3 border border-slate-200 dark:border-gray-700/40">
                                  <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">{q.label}</p>
                                  <ScoreBar value={entry.answers[q.key as keyof typeof entry.answers] as number} />
                                </div>
                              ))}
                            </div>
                          </div>

                          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                            <div className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-3 border border-slate-200 dark:border-gray-700/40">
                              <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">False Positives</p>
                              <span className="text-sm font-bold text-slate-700 dark:text-slate-200">
                                {entry.answers.false_positive_count ?? '—'}
                              </span>
                            </div>
                            <div className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-3 border border-slate-200 dark:border-gray-700/40">
                              <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Missing Threats</p>
                              <span className="text-sm font-bold text-slate-700 dark:text-slate-200">
                                {entry.answers.missing_threats_count ?? '—'}
                              </span>
                            </div>
                            <div className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-3 border border-slate-200 dark:border-gray-700/40">
                              <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Would Recommend</p>
                              <span className={`text-sm font-bold ${
                                entry.answers.would_recommend === 1
                                  ? 'text-emerald-600 dark:text-emerald-400'
                                  : entry.answers.would_recommend === 0
                                  ? 'text-red-500 dark:text-red-400'
                                  : 'text-slate-400'
                              }`}>
                                {entry.answers.would_recommend === 1 ? 'Yes' : entry.answers.would_recommend === 0 ? 'No' : '—'}
                              </span>
                            </div>
                          </div>

                          {entry.answers.improvement_suggestions && (
                            <div>
                              <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2">Improvement Suggestions</p>
                              <div className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-4 border border-slate-200 dark:border-gray-700/40">
                                <p className="text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap leading-relaxed">
                                  {entry.answers.improvement_suggestions}
                                </p>
                              </div>
                            </div>
                          )}

                          <p className="text-xs text-slate-400 dark:text-slate-500">
                            Submitted {entry.submitted_at ? formatDate(entry.submitted_at) : ''}
                          </p>
                        </>
                      ) : (
                        <div className="bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800/30 rounded-lg px-4 py-3">
                          <p className="text-sm text-amber-700 dark:text-amber-400">
                            Your feedback for this assessment is pending.
                            The link was sent to you via Slack when the assessment completed.
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default FeedbackList;
