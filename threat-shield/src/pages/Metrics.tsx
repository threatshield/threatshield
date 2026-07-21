import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiService } from '../services/api';

// ─── Types ────────────────────────────────────────────────────────────────────
interface MetricsData {
  total_assessments: number;
  completed_assessments: number;
  auto_triggered: number;
  secreview_total: number;
  secreview_auto_pct: number;
  total_threats: number;
  prev_period_threats: number;
  dread_tiers: { Critical: number; High: number; Medium: number; Low: number };
  total_dread_scored: number;
  tc_coverage_pct: number;
  total_test_cases: number;
  dread_coverage_pct: number;
  diagram_success_rate: number;
  avg_threats_per_review: number;
  auto_trigger_success_rate: number;
  e2e_completion_rate: number;
  context_failure_rate: number;
  total_cost: number;
  total_input_tokens: number;
  total_output_tokens: number;
  avg_cost_per_review: number;
  avg_tokens_per_review: number;
  cost_per_threat: number;
  cost_per_test_case: number;
}

interface CostTrendEntry {
  month: string;
  cost: number;
  input_tokens: number;
  output_tokens: number;
  count: number;
}

interface ApiResponse {
  period: MetricsData;
  all_time: MetricsData;
  cost_trend: CostTrendEntry[];
  window_start: string;
  window_end: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmt = (n: number, decimals = 0) =>
  n.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals });

const fmtCost = (n: number) => {
  if (n === 0) return '$0.00';
  if (n < 0.01) return `$${n.toFixed(6)}`;
  if (n < 1) return `$${n.toFixed(4)}`;
  return `$${n.toFixed(2)}`;
};

const fmtTokens = (n: number) => {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
};

const trendPct = (current: number, prev: number) => {
  if (prev === 0) return null;
  return ((current - prev) / prev) * 100;
};

// ─── Sub-components ───────────────────────────────────────────────────────────
const SectionLabel: React.FC<{ label: string; icon: React.ReactNode }> = ({ label, icon }) => (
  <div className="flex items-center gap-2 mb-4">
    <span className="text-[#0052cc] dark:text-blue-400/70">{icon}</span>
    <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400 dark:text-blue-300/50">
      {label}
    </span>
    <div className="flex-1 h-px bg-slate-200 dark:bg-white/5 ml-1" />
  </div>
);

type AccentKey = 'blue' | 'emerald' | 'amber' | 'rose' | 'violet' | 'cyan';

const accentMap: Record<AccentKey, { border: string; val: string; bar: string; chip: string }> = {
  blue:    { border: 'border-blue-200 dark:border-blue-500/30',       val: 'text-[#0052cc] dark:text-blue-300',    bar: 'bg-blue-500',    chip: 'bg-blue-50 dark:bg-blue-500/10' },
  emerald: { border: 'border-emerald-200 dark:border-emerald-500/30', val: 'text-emerald-600 dark:text-emerald-300', bar: 'bg-emerald-500', chip: 'bg-emerald-50 dark:bg-emerald-500/10' },
  amber:   { border: 'border-amber-200 dark:border-amber-500/30',     val: 'text-amber-600 dark:text-amber-300',   bar: 'bg-amber-500',   chip: 'bg-amber-50 dark:bg-amber-500/10' },
  rose:    { border: 'border-rose-200 dark:border-rose-500/30',       val: 'text-rose-600 dark:text-rose-300',     bar: 'bg-rose-500',    chip: 'bg-rose-50 dark:bg-rose-500/10' },
  violet:  { border: 'border-violet-200 dark:border-violet-500/30',   val: 'text-violet-600 dark:text-violet-300', bar: 'bg-violet-500',  chip: 'bg-violet-50 dark:bg-violet-500/10' },
  cyan:    { border: 'border-cyan-200 dark:border-cyan-500/30',       val: 'text-cyan-600 dark:text-cyan-300',     bar: 'bg-cyan-500',    chip: 'bg-cyan-50 dark:bg-cyan-500/10' },
};

const MetricCard: React.FC<{
  label: string;
  value: string;
  sub?: string;
  accent?: AccentKey;
  trendVal?: number | null;
  trendLabel?: string;
  bar?: number;
  barOverride?: string;
}> = ({ label, value, sub, accent = 'blue', trendVal, trendLabel, bar, barOverride }) => {
  const a = accentMap[accent];
  return (
    <div className={`relative rounded-xl border ${a.border} bg-white dark:bg-gray-900/80 p-4 flex flex-col gap-1 overflow-hidden`}>
      <div className={`absolute top-0 left-0 w-1 h-full rounded-l-xl ${a.bar}`} />
      <p className="text-[11px] font-medium text-slate-500 dark:text-slate-400 pl-3 leading-tight">{label}</p>
      <p className={`text-2xl font-bold tabular-nums tracking-tight pl-3 ${a.val}`}>{value}</p>
      {(sub || trendVal != null) && (
        <div className="flex items-center gap-2 pl-3 mt-0.5 flex-wrap">
          {sub && <span className="text-[11px] text-slate-400 dark:text-slate-500">{sub}</span>}
          {trendVal != null && (
            <span className={`text-[10px] font-semibold flex items-center gap-0.5 ${trendVal >= 0 ? 'text-emerald-500 dark:text-emerald-400' : 'text-rose-500 dark:text-rose-400'}`}>
              {trendVal >= 0 ? '↑' : '↓'}{Math.abs(trendVal).toFixed(0)}%{trendLabel ? ` ${trendLabel}` : ''}
            </span>
          )}
        </div>
      )}
      {bar != null && (
        <div className="pl-3 pr-1 mt-2">
          <div className="h-1 w-full bg-slate-100 dark:bg-white/5 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${barOverride || a.bar}`}
              style={{ width: `${Math.min(Math.max(bar, 0), 100)}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
};

const DreadBar: React.FC<{ tiers: MetricsData['dread_tiers'] }> = ({ tiers }) => {
  const total = tiers.Critical + tiers.High + tiers.Medium + tiers.Low;
  if (total === 0) return <p className="text-slate-400 dark:text-slate-500 text-xs">No DREAD data yet</p>;
  const segs = [
    { label: 'Critical', count: tiers.Critical, light: 'bg-rose-500',    dark: 'bg-rose-500' },
    { label: 'High',     count: tiers.High,     light: 'bg-amber-400',   dark: 'bg-amber-400' },
    { label: 'Medium',   count: tiers.Medium,   light: 'bg-yellow-400',  dark: 'bg-yellow-300' },
    { label: 'Low',      count: tiers.Low,      light: 'bg-emerald-500', dark: 'bg-emerald-400' },
  ];
  return (
    <div className="flex flex-col gap-3">
      <div className="flex h-3 rounded-full overflow-hidden w-full gap-0.5">
        {segs.map(s => s.count > 0 && (
          <div
            key={s.label}
            className={`${s.light} h-full rounded-full`}
            style={{ width: `${(s.count / total) * 100}%` }}
            title={`${s.label}: ${s.count}`}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-5 gap-y-1.5">
        {segs.map(s => (
          <div key={s.label} className="flex items-center gap-1.5">
            <span className={`w-2.5 h-2.5 rounded-full ${s.light} flex-shrink-0`} />
            <span className="text-[11px] text-slate-500 dark:text-slate-400">{s.label}</span>
            <span className="text-[12px] font-bold tabular-nums text-slate-700 dark:text-slate-200">{s.count}</span>
            <span className="text-[10px] text-slate-400 dark:text-slate-500">
              ({((s.count / total) * 100).toFixed(0)}%)
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

const CostSparkline: React.FC<{ data: CostTrendEntry[] }> = ({ data }) => {
  if (!data.length) return null;
  const maxCost = Math.max(...data.map(d => d.cost), 0.000001);
  const H = 52, W = 200;
  const step = W / Math.max(data.length - 1, 1);
  const pts = data.map((d, i) => ({ x: i * step, y: H - (d.cost / maxCost) * H * 0.85 }));
  const pathD = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const areaD = `${pathD} L${pts[pts.length - 1].x.toFixed(1)},${H} L0,${H} Z`;

  return (
    <div className="flex flex-col gap-3">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-14" preserveAspectRatio="none">
        <defs>
          <linearGradient id="sgL" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#0052cc" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#0052cc" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={areaD} fill="url(#sgL)" />
        <path d={pathD} fill="none" stroke="#0052cc" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        {pts.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="2" fill="#0052cc" />
        ))}
      </svg>
      <div className="flex justify-between gap-1 overflow-hidden">
        {data.map(d => (
          <div key={d.month} className="flex flex-col items-center gap-0.5 min-w-0">
            <span className="text-[9px] font-semibold tabular-nums text-[#0052cc] dark:text-blue-300 truncate">{fmtCost(d.cost)}</span>
            <span className="text-[9px] text-slate-400 dark:text-slate-500">{d.month.slice(5)}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ─── Main Page ────────────────────────────────────────────────────────────────
const Metrics: React.FC = () => {
  const [period, setPeriod] = useState<'weekly' | 'monthly' | 'custom'>('weekly');
  const [customStart, setCustomStart] = useState('');
  const [customEnd, setCustomEnd] = useState('');
  const [customOpen, setCustomOpen] = useState(false);
  const [data, setData] = useState<ApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const customRef = useRef<HTMLDivElement>(null);

  // Close popover on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (customRef.current && !customRef.current.contains(e.target as Node)) {
        setCustomOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const load = useCallback(async () => {
    // Don't fetch for custom mode until the user has applied dates
    if (period === 'custom' && (!customStart || !customEnd)) return;

    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = {};
      if (period === 'custom') {
        params.start_date = customStart;
        params.end_date   = customEnd;
      } else {
        params.period = period;
      }
      const res = await apiService.getMetrics(params);
      setData(res);
    } catch (e: any) {
      setError(e.message || 'Failed to load metrics');
    } finally {
      setLoading(false);
    }
  }, [period, customStart, customEnd]);

  useEffect(() => { load(); }, [load]);

  const m = data?.period;
  const at = data?.all_time;
  const threatTrend = m ? trendPct(m.total_threats, m.prev_period_threats) : null;

  const inputCls = "w-full bg-white dark:bg-gray-800 border border-slate-200 dark:border-gray-700 rounded-lg px-2.5 py-1.5 text-[12px] text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc]";

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      {/* ── Sticky header ── */}
      <div className="sticky top-0 z-20 bg-white/95 dark:bg-gray-900/95 backdrop-blur border-b border-slate-200 dark:border-white/5">
        <div className="px-6 py-3 flex items-center justify-between gap-4 flex-wrap">
          {/* Title */}
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
              <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8}
                  d="M16 8v8m-4-5v5m-4-2v2M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
            </div>
            <div>
              <h1 className="text-[15px] font-bold text-slate-800 dark:text-slate-100 tracking-tight">
                Metrics
              </h1>
              <p className="text-[10px] text-slate-400 dark:text-slate-500 leading-none mt-0.5">
                {data
                  ? `${new Date(data.window_start).toLocaleDateString()} – ${new Date(data.window_end).toLocaleDateString()}`
                  : 'Loading…'}
              </p>
            </div>
          </div>

          {/* Controls */}
          <div className="flex items-center gap-2.5 flex-wrap">
            {/* Period toggle + custom date popover */}
            <div className="relative" ref={customRef}>
              <div className="flex items-center bg-slate-100 dark:bg-white/5 border border-slate-200 dark:border-white/8 rounded-lg p-0.5 gap-0.5">
                {(['weekly', 'monthly'] as const).map(p => (
                  <button
                    key={p}
                    onClick={() => { setPeriod(p); setCustomOpen(false); }}
                    className={`px-3 py-1.5 rounded-md text-[11px] font-semibold transition-all duration-150 capitalize ${
                      period === p
                        ? 'bg-[#0052cc] text-white shadow-sm'
                        : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-white hover:bg-white dark:hover:bg-white/8'
                    }`}
                  >
                    {p}
                  </button>
                ))}
                <button
                  onClick={() => { setPeriod('custom'); setCustomOpen(o => !o); }}
                  className={`px-3 py-1.5 rounded-md text-[11px] font-semibold transition-all duration-150 flex items-center gap-1 ${
                    period === 'custom'
                      ? 'bg-[#0052cc] text-white shadow-sm'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-white hover:bg-white dark:hover:bg-white/8'
                  }`}
                >
                  Custom
                  <svg className={`w-3 h-3 transition-transform duration-150 ${customOpen ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
              </div>

              {/* Floating date picker popover */}
              {customOpen && (
                <div className="absolute right-0 top-full mt-2 z-50 bg-white dark:bg-gray-900 border border-slate-200 dark:border-gray-700 rounded-xl shadow-lg p-4 flex flex-col gap-3 min-w-[240px]">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">Custom date range</p>
                  <div className="flex flex-col gap-2">
                    <div>
                      <label className="text-[11px] text-slate-500 dark:text-slate-400 block mb-1">From</label>
                      <input
                        type="date"
                        value={customStart}
                        onChange={e => setCustomStart(e.target.value)}
                        className={inputCls}
                      />
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-500 dark:text-slate-400 block mb-1">To</label>
                      <input
                        type="date"
                        value={customEnd}
                        onChange={e => setCustomEnd(e.target.value)}
                        className={inputCls}
                      />
                    </div>
                  </div>
                  <button
                    onClick={() => { setCustomOpen(false); load(); }}
                    disabled={!customStart || !customEnd}
                    className="w-full py-2 rounded-lg bg-[#0052cc] text-white text-[12px] font-semibold hover:bg-blue-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    Apply
                  </button>
                </div>
              )}
            </div>

            {/* Period cost chip */}
            <div className="flex items-center gap-1.5 bg-blue-50 dark:bg-blue-950/60 border border-blue-200 dark:border-blue-500/25 rounded-lg px-3 py-1.5">
              <svg className="w-3 h-3 text-[#0052cc] dark:text-blue-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span className="text-[11px] text-blue-600/70 dark:text-blue-300/70">Period cost</span>
              <span className="text-[12px] font-bold text-[#0052cc] dark:text-blue-200 tabular-nums">
                {m ? fmtCost(m.total_cost) : '—'}
              </span>
            </div>

            {/* All-time spend — always visible, unaffected by period filter */}
            <div className="flex items-center gap-1.5 bg-violet-50 dark:bg-violet-950/60 border border-violet-200 dark:border-violet-500/25 rounded-lg px-3 py-1.5">
              <svg className="w-3 h-3 text-violet-600 dark:text-violet-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M9 7h6m0 10v-3m-3 3h.01M9 17h.01M9 11h.01M12 11h.01M15 11h.01M4 19h16a2 2 0 002-2V7a2 2 0 00-2-2H4a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              <span className="text-[11px] text-violet-600/70 dark:text-violet-300/70">All-time spend</span>
              <span className="text-[12px] font-bold text-violet-700 dark:text-violet-200 tabular-nums">
                {at ? fmtCost(at.total_cost) : '—'}
              </span>
            </div>

            {/* Refresh */}
            <button
              onClick={load}
              disabled={loading}
              className="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-100 dark:bg-white/5 border border-slate-200 dark:border-white/8 text-slate-400 hover:text-slate-700 dark:hover:text-white hover:bg-slate-200 dark:hover:bg-white/10 transition-all disabled:opacity-40"
            >
              <svg className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* ── Body ── */}
      <div className="px-6 py-6 space-y-8">

        {error && (
          <div className="rounded-xl border border-red-200 dark:border-rose-500/30 bg-red-50 dark:bg-rose-950/40 px-4 py-3 text-sm text-red-700 dark:text-rose-300">
            {error}
          </div>
        )}

        {loading && !data && (
          <div className="flex items-center justify-center py-24 gap-3 text-slate-400">
            <svg className="w-5 h-5 animate-spin text-[#0052cc]" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <span className="text-sm">Loading metrics…</span>
          </div>
        )}

        {m && typeof m.total_assessments === 'number' && (
          <>
            {/* ── 1. Review Volume & Automation ── */}
            <section>
              <SectionLabel
                label="Review Volume & Automation"
                icon={
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                  </svg>
                }
              />
              <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-3">
                <MetricCard
                  label="Total Reviews"
                  value={fmt(m.total_assessments)}
                  sub={`${fmt(m.completed_assessments)} completed`}
                  accent="blue"
                  bar={m.e2e_completion_rate}
                />
                <MetricCard
                  label="SecReview Tickets"
                  value={fmt(m.secreview_total)}
                  sub={`${m.secreview_auto_pct}% with auto trigger`}
                  accent="cyan"
                  bar={m.secreview_auto_pct}
                />
                <MetricCard
                  label="Auto-Triggered Reviews"
                  value={fmt(m.auto_triggered)}
                  sub={`${m.auto_trigger_success_rate}% success rate`}
                  accent="emerald"
                  bar={m.auto_trigger_success_rate}
                />
                <MetricCard
                  label="E2E Completion Rate"
                  value={`${m.e2e_completion_rate}%`}
                  accent="violet"
                  bar={m.e2e_completion_rate}
                />
                <MetricCard
                  label="Context Failure Rate"
                  value={`${m.context_failure_rate}%`}
                  sub="Missing Slack / Confluence"
                  accent={m.context_failure_rate > 20 ? 'rose' : 'amber'}
                  bar={m.context_failure_rate}
                  barOverride={m.context_failure_rate > 20 ? 'bg-rose-500' : 'bg-amber-500'}
                />
              </div>
            </section>

            {/* ── 2. Threat Intelligence ── */}
            <section>
              <SectionLabel
                label="Threat Intelligence"
                icon={
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                }
              />
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                {/* Left: 2×2 stat cards */}
                <div className="grid grid-cols-2 gap-3">
                  <MetricCard
                    label="Total Threats Identified"
                    value={fmt(m.total_threats)}
                    trendVal={threatTrend}
                    trendLabel="vs prev"
                    accent="rose"
                  />
                  <MetricCard label="Avg Threats / Review" value={fmt(m.avg_threats_per_review, 1)} accent="amber" />
                  <MetricCard
                    label="Full DREAD Report Rate"
                    value={`${m.dread_coverage_pct}%`}
                    accent="violet"
                    bar={m.dread_coverage_pct}
                  />
                </div>

                {/* Right: DREAD tier breakdown — spans 2 cols */}
                <div className="xl:col-span-2 rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 p-5 shadow-sm">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400 dark:text-slate-500 mb-4">
                    Threats by DREAD Score Tier
                  </p>
                  <DreadBar tiers={m.dread_tiers} />
                  <div className="mt-4 pt-4 border-t border-slate-100 dark:border-white/5 grid grid-cols-2 sm:grid-cols-4 gap-4">
                    {[
                      { label: 'Total DREAD-scored', val: fmt(m.total_dread_scored), cls: 'text-slate-700 dark:text-slate-200' },
                      { label: 'Critical + High', val: fmt(m.dread_tiers.Critical + m.dread_tiers.High), cls: 'text-rose-600 dark:text-rose-300' },
                      { label: 'Critical',         val: fmt(m.dread_tiers.Critical), cls: 'text-rose-600 dark:text-rose-300' },
                      { label: 'High',             val: fmt(m.dread_tiers.High),     cls: 'text-amber-600 dark:text-amber-300' },
                    ].map(r => (
                      <div key={r.label}>
                        <p className="text-[10px] text-slate-400 dark:text-slate-500">{r.label}</p>
                        <p className={`text-xl font-bold tabular-nums mt-0.5 ${r.cls}`}>{r.val}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>

            {/* ── 3. Coverage & Quality ── */}
            <section>
              <SectionLabel
                label="Coverage & Quality"
                icon={
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                }
              />
              <div className="grid grid-cols-2 sm:grid-cols-2 xl:grid-cols-4 gap-3">
                <MetricCard
                  label="ASVS Test Case Coverage"
                  value={`${m.tc_coverage_pct}%`}
                  sub={`${fmt(m.total_test_cases)} test cases`}
                  accent="emerald"
                  bar={m.tc_coverage_pct}
                />
                <MetricCard label="Diagram Generation Rate" value={`${m.diagram_success_rate}%`} accent="blue"   bar={m.diagram_success_rate} />
                <MetricCard label="Full DREAD Coverage"      value={`${m.dread_coverage_pct}%`}  accent="violet" bar={m.dread_coverage_pct} />
                <MetricCard
                  label="SecReview Full Coverage"
                  value={`${m.e2e_completion_rate}%`}
                  sub="Threat model + ASVS"
                  accent="amber"
                  bar={m.e2e_completion_rate}
                />
              </div>
            </section>

            {/* ── 4. LLM Cost & Usage ── */}
            <section>
              <SectionLabel
                label="LLM Cost & Usage"
                icon={
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                }
              />
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                {/* Cost cards */}
                <div className="grid grid-cols-2 gap-3">
                  <MetricCard label="Total Cost (Period)"   value={fmtCost(m.total_cost)}           accent="blue" />
                  <MetricCard label="Avg Cost / Review"     value={fmtCost(m.avg_cost_per_review)}   accent="violet" />
                  <MetricCard label="Cost / Threat Found"   value={fmtCost(m.cost_per_threat)}       accent="cyan" />
                  <MetricCard label="Cost / ASVS Test Case" value={fmtCost(m.cost_per_test_case)}    accent="emerald" />
                </div>

                {/* Token usage panel */}
                <div className="rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 p-5 shadow-sm flex flex-col gap-4">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400 dark:text-slate-500">
                    Token Consumption (Period)
                  </p>
                  <div className="grid grid-cols-2 gap-4">
                    {[
                      { label: 'Input tokens',       val: fmtTokens(m.total_input_tokens),                              cls: 'text-[#0052cc] dark:text-blue-300' },
                      { label: 'Output tokens',      val: fmtTokens(m.total_output_tokens),                             cls: 'text-violet-600 dark:text-violet-300' },
                      { label: 'Total tokens',       val: fmtTokens(m.total_input_tokens + m.total_output_tokens),      cls: 'text-slate-700 dark:text-slate-200' },
                      { label: 'Avg tokens / review',val: fmtTokens(m.avg_tokens_per_review),                           cls: 'text-cyan-600 dark:text-cyan-300' },
                    ].map(r => (
                      <div key={r.label}>
                        <p className="text-[10px] text-slate-400 dark:text-slate-500 mb-0.5">{r.label}</p>
                        <p className={`text-xl font-bold tabular-nums ${r.cls}`}>{r.val}</p>
                      </div>
                    ))}
                  </div>
                  {(m.total_input_tokens + m.total_output_tokens) > 0 && (
                    <div>
                      <p className="text-[10px] text-slate-400 dark:text-slate-500 mb-1.5">Input vs Output</p>
                      <div className="flex h-2 rounded-full overflow-hidden bg-slate-100 dark:bg-white/5">
                        <div
                          className="bg-[#0052cc] h-full"
                          style={{ width: `${(m.total_input_tokens / (m.total_input_tokens + m.total_output_tokens)) * 100}%` }}
                        />
                        <div className="bg-violet-500 h-full flex-1" />
                      </div>
                      <div className="flex justify-between mt-1">
                        <span className="text-[9px] text-[#0052cc] dark:text-blue-400 font-medium">
                          Input {((m.total_input_tokens / (m.total_input_tokens + m.total_output_tokens)) * 100).toFixed(0)}%
                        </span>
                        <span className="text-[9px] text-violet-600 dark:text-violet-400 font-medium">
                          Output {((m.total_output_tokens / (m.total_input_tokens + m.total_output_tokens)) * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Monthly cost sparkline */}
                <div className="rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 p-5 shadow-sm flex flex-col gap-3">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400 dark:text-slate-500">
                    Monthly Cost Trend
                  </p>
                  {data?.cost_trend?.length ? (
                    <CostSparkline data={data.cost_trend} />
                  ) : (
                    <p className="text-xs text-slate-400 dark:text-slate-500 mt-2">No trend data yet</p>
                  )}
                  {data?.cost_trend?.length && at ? (
                    <div className="mt-auto pt-3 border-t border-slate-100 dark:border-white/5 grid grid-cols-2 gap-3">
                      <div>
                        <p className="text-[10px] text-slate-400 dark:text-slate-500">All-time total</p>
                        <p className="text-base font-bold tabular-nums text-[#0052cc] dark:text-blue-200">{fmtCost(at.total_cost)}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-slate-400 dark:text-slate-500">All-time tokens</p>
                        <p className="text-base font-bold tabular-nums text-violet-600 dark:text-violet-200">
                          {fmtTokens(at.total_input_tokens + at.total_output_tokens)}
                        </p>
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            </section>

            {/* ── 5. Comparison table ── */}
            {at && typeof at.total_assessments === 'number' && (
              <section>
                <SectionLabel
                  label="All-Time Benchmarks"
                  icon={
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                    </svg>
                  }
                />
                <div className="rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 shadow-sm overflow-hidden">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-100 dark:border-white/5 bg-slate-50 dark:bg-white/2">
                        <th className="text-left text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5">Metric</th>
                        <th className="text-right text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5">Selected Period</th>
                        <th className="text-right text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5">All Time</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-white/4">
                      {[
                        { label: 'Total Reviews',           period: fmt(m.total_assessments),           alltime: fmt(at.total_assessments) },
                        { label: 'Completed Reviews',        period: fmt(m.completed_assessments),       alltime: fmt(at.completed_assessments) },
                        { label: 'Total Threats',            period: fmt(m.total_threats),               alltime: fmt(at.total_threats) },
                        { label: 'Avg Threats / Review',     period: fmt(m.avg_threats_per_review, 1),   alltime: fmt(at.avg_threats_per_review, 1) },
                        { label: 'ASVS Test Cases',          period: fmt(m.total_test_cases),            alltime: fmt(at.total_test_cases) },
                        { label: 'ASVS Coverage',            period: `${m.tc_coverage_pct}%`,            alltime: `${at.tc_coverage_pct}%` },
                        { label: 'E2E Completion Rate',      period: `${m.e2e_completion_rate}%`,        alltime: `${at.e2e_completion_rate}%` },
                        { label: 'Auto-Trigger Success',     period: `${m.auto_trigger_success_rate}%`,  alltime: `${at.auto_trigger_success_rate}%` },
                        { label: 'Diagram Generation Rate',  period: `${m.diagram_success_rate}%`,       alltime: `${at.diagram_success_rate}%` },
                        { label: 'Total LLM Cost',           period: fmtCost(m.total_cost),              alltime: fmtCost(at.total_cost) },
                        { label: 'Avg Cost / Review',        period: fmtCost(m.avg_cost_per_review),     alltime: fmtCost(at.avg_cost_per_review) },
                        { label: 'Cost / Threat',            period: fmtCost(m.cost_per_threat),         alltime: fmtCost(at.cost_per_threat) },
                        { label: 'Total Tokens',             period: fmtTokens(m.total_input_tokens + m.total_output_tokens), alltime: fmtTokens(at.total_input_tokens + at.total_output_tokens) },
                        { label: 'Avg Tokens / Review',      period: fmtTokens(m.avg_tokens_per_review), alltime: fmtTokens(at.avg_tokens_per_review) },
                      ].map((row, i) => (
                        <tr key={row.label} className={`hover:bg-slate-50 dark:hover:bg-white/3 transition-colors ${i % 2 === 0 ? '' : 'bg-slate-50/50 dark:bg-white/1'}`}>
                          <td className="px-5 py-2.5 text-[12px] text-slate-600 dark:text-slate-400">{row.label}</td>
                          <td className="px-5 py-2.5 text-right text-[12px] font-semibold tabular-nums text-slate-800 dark:text-slate-100">{row.period}</td>
                          <td className="px-5 py-2.5 text-right text-[12px] tabular-nums text-slate-400 dark:text-slate-500">{row.alltime}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}
          </>
        )}

        {!loading && !m && !error && (
          <div className="flex flex-col items-center justify-center py-24 gap-3 text-slate-400">
            <svg className="w-10 h-10 text-slate-300 dark:text-slate-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M16 8v8m-4-5v5m-4-2v2M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
            <p className="text-sm text-slate-500">No metrics data available yet.</p>
            <p className="text-xs text-slate-400 dark:text-slate-600">Run some threat models to start collecting data.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Metrics;
