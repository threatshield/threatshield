import React, { useState, useEffect, useRef } from 'react';
import { apiService } from '../services/api';
import { ReportMetadata, DreadAssessmentItem } from '../types/reportTypes';

// ─── Helpers ──────────────────────────────────────────────────────────────────
const getDreadItems = (result: any): DreadAssessmentItem[] => {
  try {
    if (result?.raw_response?.['Risk Assessment']) return result.raw_response['Risk Assessment'];
    if (result?.result?.raw_response?.['Risk Assessment']) return result.result.raw_response['Risk Assessment'];
    if (result?.result?.result?.raw_response?.['Risk Assessment']) return result.result.result.raw_response['Risk Assessment'];
    return [];
  } catch { return []; }
};

const calculateDreadScore = (item: DreadAssessmentItem): number =>
  (item['Damage Potential'] + item['Reproducibility'] + item['Exploitability'] + item['Affected Users'] + item['Discoverability']) / 5;

// ─── Sub-components ───────────────────────────────────────────────────────────
const SectionLabel: React.FC<{ label: string; icon: React.ReactNode }> = ({ label, icon }) => (
  <div className="flex items-center gap-2 mb-4">
    <span className="text-[#0052cc] dark:text-blue-400/70">{icon}</span>
    <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400 dark:text-blue-300/50">{label}</span>
    <div className="flex-1 h-px bg-slate-200 dark:bg-white/5 ml-1" />
  </div>
);

type AccentKey = 'blue' | 'emerald' | 'amber' | 'rose' | 'violet' | 'cyan' | 'orange';

const accentMap: Record<AccentKey, { border: string; val: string; bar: string }> = {
  blue:    { border: 'border-blue-200 dark:border-blue-500/30',       val: 'text-[#0052cc] dark:text-blue-300',      bar: 'bg-blue-500' },
  emerald: { border: 'border-emerald-200 dark:border-emerald-500/30', val: 'text-emerald-600 dark:text-emerald-300', bar: 'bg-emerald-500' },
  amber:   { border: 'border-amber-200 dark:border-amber-500/30',     val: 'text-amber-600 dark:text-amber-300',     bar: 'bg-amber-500' },
  rose:    { border: 'border-rose-200 dark:border-rose-500/30',       val: 'text-rose-600 dark:text-rose-300',       bar: 'bg-rose-500' },
  violet:  { border: 'border-violet-200 dark:border-violet-500/30',   val: 'text-violet-600 dark:text-violet-300',   bar: 'bg-violet-500' },
  cyan:    { border: 'border-cyan-200 dark:border-cyan-500/30',       val: 'text-cyan-600 dark:text-cyan-300',       bar: 'bg-cyan-500' },
  orange:  { border: 'border-orange-200 dark:border-orange-500/30',   val: 'text-orange-600 dark:text-orange-300',   bar: 'bg-orange-500' },
};

const MetricCard: React.FC<{
  label: string;
  value: string | number;
  sub?: string;
  accent?: AccentKey;
  bar?: number;
}> = ({ label, value, sub, accent = 'blue', bar }) => {
  const a = accentMap[accent];
  return (
    <div className={`relative rounded-xl border ${a.border} bg-white dark:bg-gray-900/80 p-4 flex flex-col gap-1 overflow-hidden`}>
      <div className={`absolute top-0 left-0 w-1 h-full rounded-l-xl ${a.bar}`} />
      <p className="text-[11px] font-medium text-slate-500 dark:text-slate-400 pl-3 leading-tight">{label}</p>
      <p className={`text-2xl font-bold tabular-nums tracking-tight pl-3 ${a.val}`}>{value}</p>
      {sub && <span className="text-[11px] text-slate-400 dark:text-slate-500 pl-3">{sub}</span>}
      {bar != null && (
        <div className="pl-3 pr-1 mt-2">
          <div className="h-1 w-full bg-slate-100 dark:bg-white/5 rounded-full overflow-hidden">
            <div className={`h-full rounded-full transition-all duration-700 ${a.bar}`} style={{ width: `${Math.min(Math.max(bar, 0), 100)}%` }} />
          </div>
        </div>
      )}
    </div>
  );
};

const HorizBarChart: React.FC<{
  items: { label: string; count: number; color: string }[];
  total: number;
  emptyText?: string;
}> = ({ items, total, emptyText = 'No data available' }) => {
  if (total === 0) return <p className="text-xs text-slate-400 dark:text-slate-500">{emptyText}</p>;
  const sorted = [...items].sort((a, b) => b.count - a.count);
  return (
    <div className="flex flex-col gap-2.5">
      {sorted.map(item => (
        item.count > 0 && (
          <div key={item.label} className="flex items-center gap-3">
            <span className="text-[11px] text-slate-500 dark:text-slate-400 w-36 flex-shrink-0 truncate" title={item.label}>{item.label}</span>
            <div className="flex-1 h-2 bg-slate-100 dark:bg-white/5 rounded-full overflow-hidden">
              <div className={`h-full rounded-full ${item.color} transition-all duration-700`} style={{ width: `${(item.count / total) * 100}%` }} />
            </div>
            <span className="text-[12px] font-bold tabular-nums text-slate-700 dark:text-slate-200 w-7 text-right">{item.count}</span>
            <span className="text-[10px] text-slate-400 dark:text-slate-500 w-8">({Math.round((item.count / total) * 100)}%)</span>
          </div>
        )
      ))}
    </div>
  );
};

const StrideBar: React.FC<{ counts: Record<string, number> }> = ({ counts }) => {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return <p className="text-xs text-slate-400 dark:text-slate-500">No STRIDE data yet</p>;
  const segs = [
    { label: 'Spoofing',              count: counts['Spoofing'] || 0,               color: 'bg-rose-500' },
    { label: 'Tampering',             count: counts['Tampering'] || 0,              color: 'bg-amber-400' },
    { label: 'Repudiation',           count: counts['Repudiation'] || 0,            color: 'bg-yellow-400' },
    { label: 'Info Disclosure',       count: counts['Information Disclosure'] || 0, color: 'bg-blue-500' },
    { label: 'Denial of Service',     count: counts['Denial of Service'] || 0,      color: 'bg-violet-500' },
    { label: 'Elevation of Privilege',count: counts['Elevation of Privilege'] || 0, color: 'bg-emerald-500' },
  ];
  return (
    <div className="flex flex-col gap-3">
      <div className="flex h-3 rounded-full overflow-hidden w-full gap-0.5">
        {segs.map(s => s.count > 0 && (
          <div key={s.label} className={`${s.color} h-full rounded-full`} style={{ width: `${(s.count / total) * 100}%` }} title={`${s.label}: ${s.count}`} />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1.5">
        {segs.map(s => (
          <div key={s.label} className="flex items-center gap-1.5">
            <span className={`w-2.5 h-2.5 rounded-full ${s.color} flex-shrink-0`} />
            <span className="text-[11px] text-slate-500 dark:text-slate-400">{s.label}</span>
            <span className="text-[12px] font-bold tabular-nums text-slate-700 dark:text-slate-200">{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ─── Main Page ────────────────────────────────────────────────────────────────
const Analytics: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [reportData, setReportData] = useState<ReportMetadata[]>([]);
  const [highRiskIssues, setHighRiskIssues] = useState<DreadAssessmentItem[]>([]);
  const [duration, setDuration] = useState<string>('all');
  const [dateFrom, setDateFrom] = useState<string>('');
  const [dateTo, setDateTo] = useState<string>('');
  const [customOpen, setCustomOpen] = useState(false);
  const [isHighIssuesExpanded, setIsHighIssuesExpanded] = useState<boolean>(false);
  const [categoryHighIssues, setCategoryHighIssues] = useState<Record<string, number>>({});
  const [strideModelCount, setStrideModelCount] = useState<number>(0);
  const [pastaModelCount, setPastaModelCount] = useState<number>(0);
  const [pastaBusinessImpacts, setPastaBusinessImpacts] = useState<Record<string, number>>({});
  const [pastaStages, setPastaStages] = useState<Record<string, number>>({});
  const [totalPastaThreats, setTotalPastaThreats] = useState<number>(0);
  const [totalAttackPaths, setTotalAttackPaths] = useState<number>(0);
  const [strideCounts, setStrideCounts] = useState<Record<string, number>>({});
  const [departmentCounts, setDepartmentCounts] = useState<Record<string, number>>({});
  const [threatTypeCounts, setThreatTypeCounts] = useState<Record<string, number>>({});

  const customRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (customRef.current && !customRef.current.contains(e.target as Node)) setCustomOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  useEffect(() => {
    const fetchData = async () => {
      const now = new Date();
      let startDate = new Date();

      switch (duration) {
        case 'week':    startDate.setDate(now.getDate() - 7); break;
        case 'month':   startDate.setMonth(now.getMonth() - 1); break;
        case 'quarter': startDate.setMonth(now.getMonth() - 3); break;
        case 'year':    startDate.setFullYear(now.getFullYear() - 1); break;
        case 'custom':  startDate = dateFrom ? new Date(dateFrom) : new Date(0); break;
        default:        startDate = new Date(0);
      }
      const endDate = duration === 'custom' && dateTo ? new Date(dateTo + 'T23:59:59') : now;

      try {
        setLoading(true);
        const response = await apiService.getAnalyticsData();

        if (!response.data || !Array.isArray(response.data) || response.data.length === 0) {
          setError('No threat models found. Generate a threat model to view analytics.');
          setLoading(false);
          return;
        }

        const filteredReports = response.data.filter((report: any) => {
          if (!report?.threat_model?.timestamp) return false;
          if (duration === 'all') return true;
          const reportDate = new Date(report.threat_model.timestamp);
          return reportDate >= startDate && reportDate <= endDate;
        });

        setReportData(filteredReports);
        processReportData(filteredReports);
        setLoading(false);
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Unknown error occurred';
        setError(`Failed to load analytics data: ${msg}`);
        setLoading(false);
      }
    };

    fetchData();
  }, [duration, dateFrom, dateTo]);

  const processReportData = (reports: ReportMetadata[]) => {
    const highRiskItems: DreadAssessmentItem[] = [];
    const threatTypeCountsLocal: Record<string, number> = {};
    const strideCountsLocal: Record<string, number> = {
      'Spoofing': 0, 'Tampering': 0, 'Repudiation': 0,
      'Information Disclosure': 0, 'Denial of Service': 0, 'Elevation of Privilege': 0,
    };
    const departmentCountsLocal: Record<string, number> = {};
    const categoryHighIssuesLocal: Record<string, number> = {};
    const pastaBusinessImpactsLocal: Record<string, number> = {};
    const pastaStagesLocal: Record<string, number> = {};
    let totalPastaThreatsLocal = 0;
    let strideModelCountLocal = 0;
    let pastaModelCountLocal = 0;
    let totalAttackPathsLocal = 0;

    reports.forEach(report => {
      if (report.dread_assessment?.result) {
        const dreadItems = getDreadItems(report.dread_assessment.result);
        if (dreadItems && Array.isArray(dreadItems)) {
          dreadItems.forEach((item: DreadAssessmentItem) => {
            const score = calculateDreadScore(item);
            const department = report.details?.department || 'Unknown';
            if (!item['TEAM']) item['TEAM'] = department;
            if (score >= 8) {
              highRiskItems.push(item);
              categoryHighIssuesLocal[department] = (categoryHighIssuesLocal[department] || 0) + 1;
            }
          });
        }
      }

      const department = report.details?.department || 'Unknown';
      departmentCountsLocal[department] = (departmentCountsLocal[department] || 0) + 1;

      if (report.threat_model?.result?.raw_response?.threat_model) {
        const threats = report.threat_model.result.raw_response.threat_model;
        let isPasta = false;

        if (report.details?.threatModelingMethodology) {
          isPasta = report.details.threatModelingMethodology.toUpperCase() === 'PASTA';
        } else {
          isPasta = threats.length > 0 && (
            'Business Risk Type' in threats[0] || 'PASTA Stage' in threats[0] || 'Business Impact' in threats[0]
          );
        }

        if (isPasta) { pastaModelCountLocal++; totalPastaThreatsLocal += threats.length; }
        else { strideModelCountLocal++; }

        threats.forEach((threat: any) => {
          const threatType = 'Threat Type' in threat ? threat['Threat Type'] : threat['Threat Category'];
          if (threatType) {
            threatTypeCountsLocal[threatType] = (threatTypeCountsLocal[threatType] || 0) + 1;

            if (!isPasta) {
              Object.keys(strideCountsLocal).forEach(category => {
                if (threatType.includes(category)) strideCountsLocal[category]++;
              });
            }

            if (isPasta) {
              let businessImpact: string | string[] = '';
              if ('Business Risk Type' in threat) businessImpact = (threat as any)['Business Risk Type'];
              else if ('Business Impact' in threat) businessImpact = (threat as any)['Business Impact'];

              if (businessImpact) {
                if (Array.isArray(businessImpact)) {
                  businessImpact.forEach(i => { pastaBusinessImpactsLocal[i] = (pastaBusinessImpactsLocal[i] || 0) + 1; });
                } else if (typeof businessImpact === 'string') {
                  if (businessImpact.includes(',')) {
                    businessImpact.split(',').map(s => s.trim()).forEach(i => { pastaBusinessImpactsLocal[i] = (pastaBusinessImpactsLocal[i] || 0) + 1; });
                  } else {
                    pastaBusinessImpactsLocal[businessImpact] = (pastaBusinessImpactsLocal[businessImpact] || 0) + 1;
                  }
                }
              }

              if ('PASTA Stage' in threat && typeof threat['PASTA Stage'] === 'string') {
                pastaStagesLocal[threat['PASTA Stage']] = (pastaStagesLocal[threat['PASTA Stage']] || 0) + 1;
              }
            }
          }
        });
      }

      if (report.attack_tree?.result?.attack_tree) {
        const attackTree = report.attack_tree.result.attack_tree;
        if (attackTree.total_paths !== undefined) {
          totalAttackPathsLocal += attackTree.total_paths;
        } else if (attackTree.nodes) {
          const nodes = attackTree.nodes;
          const leafNodes = nodes.filter((node: any) => !nodes.some((n: any) => n.children?.some((c: any) => c.id === node.id)));
          const uniquePaths = new Set(leafNodes.map((node: any) => {
            const path = [];
            let current = node;
            while (current) {
              path.push(current.label);
              const parent = nodes.find((n: any) => n.children?.some((c: any) => c.id === current.id));
              if (!parent) break;
              current = parent;
            }
            return path.join('->');
          }));
          totalAttackPathsLocal += uniquePaths.size;
        }
      }
    });

    highRiskItems.sort((a, b) => calculateDreadScore(b) - calculateDreadScore(a));
    setHighRiskIssues(highRiskItems);

    setThreatTypeCounts(threatTypeCountsLocal);
    setDepartmentCounts(departmentCountsLocal);
    setStrideCounts(strideCountsLocal);
    setCategoryHighIssues(categoryHighIssuesLocal);
    setStrideModelCount(strideModelCountLocal);
    setPastaModelCount(pastaModelCountLocal);
    setPastaBusinessImpacts(pastaBusinessImpactsLocal);
    setPastaStages(pastaStagesLocal);
    setTotalPastaThreats(totalPastaThreatsLocal);
    setTotalAttackPaths(totalAttackPathsLocal);
  };

  const totalThreats = Object.values(threatTypeCounts).reduce((a, b) => a + b, 0);
  const totalDepartments = Object.values(departmentCounts).reduce((a, b) => a + b, 0);
  const totalBusinessImpacts = Object.values(pastaBusinessImpacts).reduce((a, b) => a + b, 0);
  const totalPastaStages = Object.values(pastaStages).reduce((a, b) => a + b, 0);

  const departmentColors = ['bg-blue-500', 'bg-violet-500', 'bg-emerald-500', 'bg-amber-400', 'bg-rose-500', 'bg-cyan-500', 'bg-orange-500', 'bg-yellow-500', 'bg-pink-500', 'bg-indigo-500'];
  const pastaColors = ['bg-orange-500', 'bg-amber-400', 'bg-rose-500', 'bg-violet-500', 'bg-cyan-500', 'bg-blue-500'];

  const inputCls = "w-full bg-white dark:bg-gray-800 border border-slate-200 dark:border-gray-700 rounded-lg px-2.5 py-1.5 text-[12px] text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc]";

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center gap-3 text-slate-400">
        <svg className="w-5 h-5 animate-spin text-[#0052cc]" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        <span className="text-sm">Loading analytics…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center p-6">
        <div className="bg-white border border-red-100 dark:bg-gray-900/80 dark:border-red-800/40 rounded-2xl p-10 text-center max-w-md shadow-sm">
          <div className="w-14 h-14 rounded-2xl bg-red-50 border border-red-100 dark:bg-red-900/20 dark:border-red-800/40 flex items-center justify-center mx-auto mb-4">
            <svg className="h-7 w-7 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
            </svg>
          </div>
          <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100 mb-2">No Analytics Data</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">

      {/* ── Sticky header ── */}
      <div className="sticky top-0 z-20 bg-white/95 dark:bg-gray-900/95 backdrop-blur border-b border-slate-200 dark:border-white/5">
        <div className="px-6 py-3 flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
              <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            </div>
            <div>
              <h1 className="text-[15px] font-bold text-slate-800 dark:text-slate-100 tracking-tight">Risk Analytics</h1>
              <p className="text-[10px] text-slate-400 dark:text-slate-500 leading-none mt-0.5">Aggregated insights across all threat models</p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            {/* Threat count chip */}
            <div className="flex items-center gap-1.5 bg-blue-50 dark:bg-blue-950/60 border border-blue-200 dark:border-blue-500/25 rounded-lg px-3 py-1.5">
              <svg className="w-3 h-3 text-[#0052cc] dark:text-blue-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <span className="text-[11px] text-blue-600/70 dark:text-blue-300/70">Threats</span>
              <span className="text-[12px] font-bold text-[#0052cc] dark:text-blue-200 tabular-nums">{totalThreats}</span>
            </div>

            {/* High risk chip */}
            {highRiskIssues.length > 0 && (
              <div className="flex items-center gap-1.5 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-500/25 rounded-lg px-3 py-1.5">
                <svg className="w-3 h-3 text-rose-600 dark:text-rose-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <span className="text-[11px] text-rose-600/70 dark:text-rose-300/70">High risk</span>
                <span className="text-[12px] font-bold text-rose-700 dark:text-rose-200 tabular-nums">{highRiskIssues.length}</span>
              </div>
            )}

            <div className="h-5 w-px bg-slate-200 dark:bg-white/10 flex-shrink-0" />

            {/* Duration picker */}
            <div className="relative" ref={customRef}>
              <div className="flex items-center bg-slate-100 dark:bg-white/5 border border-slate-200 dark:border-white/8 rounded-lg p-0.5 gap-0.5">
                {(['all', 'week', 'month', 'quarter', 'year'] as const).map(p => (
                  <button
                    key={p}
                    onClick={() => { setDuration(p); setCustomOpen(false); }}
                    className={`px-2.5 py-1.5 rounded-md text-[11px] font-semibold transition-all duration-150 capitalize ${
                      duration === p
                        ? 'bg-[#0052cc] text-white shadow-sm'
                        : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-white hover:bg-white dark:hover:bg-white/8'
                    }`}
                  >
                    {p === 'all' ? 'All' : p === 'week' ? '7d' : p === 'month' ? '30d' : p === 'quarter' ? '90d' : '1yr'}
                  </button>
                ))}
                <button
                  onClick={() => { setDuration('custom'); setCustomOpen(o => !o); }}
                  className={`px-2.5 py-1.5 rounded-md text-[11px] font-semibold transition-all duration-150 flex items-center gap-1 ${
                    duration === 'custom'
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

              {customOpen && (
                <div className="absolute right-0 top-full mt-2 z-50 bg-white dark:bg-gray-900 border border-slate-200 dark:border-gray-700 rounded-xl shadow-lg p-4 flex flex-col gap-3 min-w-[240px]">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">Custom date range</p>
                  <div className="flex flex-col gap-2">
                    <div>
                      <label className="text-[11px] text-slate-500 dark:text-slate-400 block mb-1">From</label>
                      <input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)} className={inputCls} />
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-500 dark:text-slate-400 block mb-1">To</label>
                      <input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)} className={inputCls} />
                    </div>
                  </div>
                  <button
                    onClick={() => setCustomOpen(false)}
                    disabled={!dateFrom || !dateTo}
                    className="w-full py-2 rounded-lg bg-[#0052cc] text-white text-[12px] font-semibold hover:bg-blue-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    Apply
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Body ── */}
      <div className="px-6 py-6 space-y-8">

        {/* ── 1. Overview Stats ── */}
        <section>
          <SectionLabel
            label="Risk Overview"
            icon={
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
              </svg>
            }
          />
          <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
            <MetricCard label="Threat Models" value={reportData.length} accent="blue" />
            <MetricCard
              label="High Risk Issues"
              value={highRiskIssues.length}
              accent="rose"
              bar={reportData.length > 0 ? Math.min((highRiskIssues.length / reportData.length) * 10, 100) : 0}
            />
            <MetricCard label="Total Threats" value={totalThreats} sub={reportData.length > 0 ? `${(totalThreats / reportData.length).toFixed(1)} avg/model` : undefined} accent="amber" />
            <MetricCard label="Attack Paths" value={totalAttackPaths} accent="violet" />
            <MetricCard
              label="STRIDE Models"
              value={strideModelCount}
              sub={reportData.length > 0 ? `${Math.round((strideModelCount / reportData.length) * 100)}% of total` : undefined}
              accent="cyan"
              bar={reportData.length > 0 ? (strideModelCount / reportData.length) * 100 : 0}
            />
            <MetricCard
              label="PASTA Models"
              value={pastaModelCount}
              sub={reportData.length > 0 ? `${Math.round((pastaModelCount / reportData.length) * 100)}% of total` : undefined}
              accent="orange"
              bar={reportData.length > 0 ? (pastaModelCount / reportData.length) * 100 : 0}
            />
          </div>
        </section>

        {/* ── 2. High Risk Issues ── */}
        <section>
          <div
            className="flex items-center gap-2 mb-4 cursor-pointer group select-none"
            onClick={() => setIsHighIssuesExpanded(!isHighIssuesExpanded)}
          >
            <span className="text-rose-500">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </span>
            <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400 dark:text-blue-300/50">
              High Risk Issues
            </span>
            {highRiskIssues.length > 0 && (
              <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-rose-50 text-rose-600 border border-rose-200 dark:bg-rose-900/20 dark:text-rose-400 dark:border-rose-800/40">
                {highRiskIssues.length}
              </span>
            )}
            <div className="flex-1 h-px bg-slate-200 dark:bg-white/5 ml-1" />
            <svg
              className={`h-3.5 w-3.5 text-slate-400 dark:text-slate-500 group-hover:text-slate-600 transform transition-transform duration-200 ${isHighIssuesExpanded ? 'rotate-180' : ''}`}
              fill="none" viewBox="0 0 24 24" stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </div>

          <div className={`overflow-hidden transition-all duration-300 ease-in-out ${isHighIssuesExpanded ? 'max-h-[2000px] opacity-100' : 'max-h-0 opacity-0'}`}>
            {highRiskIssues.length > 0 ? (
              <div className="rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 shadow-sm overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-100 dark:border-white/5 bg-slate-50 dark:bg-white/2">
                        <th className="text-left text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5">Threat Type</th>
                        <th className="text-left text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5">Methodology</th>
                        <th className="text-left text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5">Scenario</th>
                        <th className="text-left text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5">Assessment</th>
                        <th className="text-right text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5 w-28">DREAD Score</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-white/4">
                      {highRiskIssues.map((issue, index) => (
                        <tr key={index} className={`hover:bg-slate-50 dark:hover:bg-white/3 transition-colors ${index % 2 !== 0 ? 'bg-slate-50/50 dark:bg-white/1' : ''}`}>
                          <td className="px-5 py-2.5 text-[12px] font-medium text-slate-700 dark:text-slate-300">{issue['Threat Type']}</td>
                          <td className="px-5 py-2.5 text-[12px] text-slate-500 dark:text-slate-400">
                            {(() => {
                              const report = reportData.find(r => {
                                if (!r.dread_assessment?.result) return false;
                                const items = getDreadItems(r.dread_assessment.result);
                                return items?.some(item => item['Threat Type'] === issue['Threat Type'] && item['Scenario'] === issue['Scenario']);
                              });
                              if (report?.details?.threatModelingMethodology) return report.details.threatModelingMethodology.toUpperCase();
                              if ('Business Risk Type' in issue || 'PASTA Stage' in issue || 'Business Impact' in issue) return 'PASTA';
                              return 'STRIDE';
                            })()}
                          </td>
                          <td className="px-5 py-2.5 text-[12px] text-slate-600 dark:text-slate-400">{issue['Scenario']}</td>
                          <td className="px-5 py-2.5 text-[11px] text-slate-500 dark:text-slate-400">
                            {(() => {
                              const report = reportData.find(r => {
                                if (!r.dread_assessment?.result) return false;
                                const items = getDreadItems(r.dread_assessment.result);
                                return items?.some(item => item['Threat Type'] === issue['Threat Type'] && item['Scenario'] === issue['Scenario']);
                              });
                              return `[${report?.details?.department || 'N/A'}] — ${report?.details?.projectName || 'Unknown'} — ${new Date(report?.details?.timestamp || Date.now()).toLocaleDateString()}`;
                            })()}
                          </td>
                          <td className="px-5 py-2.5 text-right">
                            <span className="inline-flex items-center justify-center px-2.5 py-1 rounded-lg text-[11px] font-bold bg-rose-50 text-rose-600 border border-rose-200 dark:bg-rose-900/20 dark:text-rose-400 dark:border-rose-800/40">
                              {calculateDreadScore(issue).toFixed(1)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 p-8 text-center shadow-sm">
                <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-200 dark:bg-emerald-900/20 dark:border-emerald-800/40 flex items-center justify-center mx-auto mb-3">
                  <svg className="w-5 h-5 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <p className="text-sm font-medium text-slate-600 dark:text-slate-400">No high risk issues identified</p>
              </div>
            )}
          </div>
        </section>

        {/* ── 3. Coverage by Team ── */}
        <section>
          <SectionLabel
            label="Coverage by Team"
            icon={
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
            }
          />
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {/* TEAM distribution bar chart */}
            <div className="rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 p-5 shadow-sm">
              <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400 dark:text-slate-500 mb-4">
                Threat Models by TEAM
              </p>
              <HorizBarChart
                items={Object.entries(departmentCounts).map(([label, count], i) => ({ label, count, color: departmentColors[i % departmentColors.length] }))}
                total={totalDepartments}
                emptyText="No TEAM data available"
              />
            </div>

            {/* TEAM risk table */}
            <div className="rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 shadow-sm overflow-hidden">
              <div className="px-5 py-3.5 border-b border-slate-100 dark:border-white/5">
                <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400 dark:text-slate-500">Risk by Team</p>
              </div>
              {Object.keys(departmentCounts).length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-100 dark:border-white/5 bg-slate-50 dark:bg-white/2">
                      <th className="text-left text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5">Team</th>
                      <th className="text-right text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5">Models</th>
                      <th className="text-right text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 px-5 py-2.5">High Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-white/4">
                    {Object.entries(departmentCounts).map(([department, count], i) => (
                      <tr key={i} className="hover:bg-slate-50 dark:hover:bg-white/3 transition-colors">
                        <td className="px-5 py-2.5 text-[12px] font-medium text-slate-700 dark:text-slate-300">{department}</td>
                        <td className="px-5 py-2.5 text-right text-[12px] font-semibold tabular-nums text-slate-800 dark:text-slate-100">{count}</td>
                        <td className="px-5 py-2.5 text-right">
                          {(categoryHighIssues[department] || 0) > 0 ? (
                            <span className="inline-flex items-center justify-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-50 text-rose-600 border border-rose-200 dark:bg-rose-900/20 dark:text-rose-400 dark:border-rose-800/40">
                              {categoryHighIssues[department]}
                            </span>
                          ) : (
                            <span className="text-[12px] text-slate-400 dark:text-slate-500">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="p-8 text-center">
                  <p className="text-xs text-slate-400 dark:text-slate-500">No TEAM data available</p>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ── 4. STRIDE Analysis ── */}
        <section>
          <SectionLabel
            label="STRIDE Analysis"
            icon={
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            }
          />
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            {/* Stacked bar + legend */}
            <div className="xl:col-span-2 rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 p-5 shadow-sm">
              <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400 dark:text-slate-500 mb-4">
                Distribution by STRIDE Category
              </p>
              <StrideBar counts={strideCounts} />
              <div className="mt-5 pt-4 border-t border-slate-100 dark:border-white/5">
                <HorizBarChart
                  items={[
                    { label: 'Spoofing',               count: strideCounts['Spoofing'] || 0,               color: 'bg-rose-500' },
                    { label: 'Tampering',              count: strideCounts['Tampering'] || 0,              color: 'bg-amber-400' },
                    { label: 'Repudiation',            count: strideCounts['Repudiation'] || 0,            color: 'bg-yellow-400' },
                    { label: 'Information Disclosure', count: strideCounts['Information Disclosure'] || 0, color: 'bg-blue-500' },
                    { label: 'Denial of Service',      count: strideCounts['Denial of Service'] || 0,      color: 'bg-violet-500' },
                    { label: 'Elevation of Privilege', count: strideCounts['Elevation of Privilege'] || 0, color: 'bg-emerald-500' },
                  ]}
                  total={Object.values(strideCounts).reduce((a, b) => a + b, 0)}
                  emptyText="No STRIDE threats found"
                />
              </div>
            </div>

            {/* STRIDE stats panel */}
            <div className="rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 p-5 shadow-sm">
              <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400 dark:text-slate-500 mb-4">STRIDE Statistics</p>
              <div className="grid grid-cols-2 gap-3 mb-4">
                {[
                  { label: 'Spoofing',    count: strideCounts['Spoofing'] || 0,               color: 'text-rose-600 dark:text-rose-300' },
                  { label: 'Tampering',   count: strideCounts['Tampering'] || 0,              color: 'text-amber-600 dark:text-amber-300' },
                  { label: 'Repudiation', count: strideCounts['Repudiation'] || 0,            color: 'text-yellow-600 dark:text-yellow-300' },
                  { label: 'Info Disc.',  count: strideCounts['Information Disclosure'] || 0, color: 'text-blue-600 dark:text-blue-300' },
                  { label: 'DoS',         count: strideCounts['Denial of Service'] || 0,      color: 'text-violet-600 dark:text-violet-300' },
                  { label: 'EoP',         count: strideCounts['Elevation of Privilege'] || 0, color: 'text-emerald-600 dark:text-emerald-300' },
                ].map(s => (
                  <div key={s.label} className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-2.5 border border-slate-200 dark:border-gray-700/60">
                    <p className="text-[10px] text-slate-400 dark:text-slate-500 mb-0.5">{s.label}</p>
                    <p className={`text-lg font-bold tabular-nums ${s.color}`}>{s.count}</p>
                  </div>
                ))}
              </div>
              <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-3 border border-blue-100 dark:border-blue-800/40">
                <p className="text-[10px] font-semibold text-[#0052cc] dark:text-blue-400 uppercase tracking-wider mb-0.5">Total STRIDE Models</p>
                <p className="text-xl font-bold text-[#0052cc] dark:text-blue-400 tabular-nums">{strideModelCount}</p>
              </div>
            </div>
          </div>
        </section>

        {/* ── 6. PASTA Analysis ── */}
        <section>
          <SectionLabel
            label="PASTA Analysis"
            icon={
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            }
          />
          {pastaModelCount > 0 ? (
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
              {/* Business impacts */}
              <div className="xl:col-span-2 rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 p-5 shadow-sm">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                  {totalBusinessImpacts > 0 && (
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400 dark:text-slate-500 mb-4">Business Impact Types</p>
                      <HorizBarChart
                        items={Object.entries(pastaBusinessImpacts).map(([label, count], i) => ({ label, count, color: pastaColors[i % pastaColors.length] }))}
                        total={totalBusinessImpacts}
                        emptyText="No business impact data"
                      />
                    </div>
                  )}
                  {totalPastaStages > 0 && (
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400 dark:text-slate-500 mb-4">PASTA Stages</p>
                      <HorizBarChart
                        items={Object.entries(pastaStages).map(([label, count], i) => ({ label, count, color: pastaColors[i % pastaColors.length] }))}
                        total={totalPastaStages}
                        emptyText="No PASTA stage data"
                      />
                    </div>
                  )}
                  {totalBusinessImpacts === 0 && totalPastaStages === 0 && (
                    <p className="text-xs text-slate-400 dark:text-slate-500">No detailed PASTA breakdown available</p>
                  )}
                </div>
              </div>

              {/* PASTA stats */}
              <div className="rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 p-5 shadow-sm flex flex-col gap-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400 dark:text-slate-500">PASTA Statistics</p>
                <div className="bg-orange-50 dark:bg-orange-900/20 rounded-xl p-4 border border-orange-100 dark:border-orange-800/40">
                  <p className="text-[10px] font-semibold text-orange-600 dark:text-orange-400 uppercase tracking-wider mb-1">Total PASTA Models</p>
                  <p className="text-2xl font-bold text-orange-600 dark:text-orange-400 tabular-nums">{pastaModelCount}</p>
                </div>
                <div className="bg-slate-50 dark:bg-gray-800/60 rounded-xl p-4 border border-slate-200 dark:border-gray-700/60">
                  <p className="text-[10px] font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Total Threats Identified</p>
                  <p className="text-2xl font-bold text-slate-800 dark:text-slate-100 tabular-nums">{totalPastaThreats}</p>
                </div>
                {pastaModelCount > 0 && (
                  <div className="bg-slate-50 dark:bg-gray-800/60 rounded-xl p-4 border border-slate-200 dark:border-gray-700/60">
                    <p className="text-[10px] font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Avg Threats / Model</p>
                    <p className="text-2xl font-bold text-slate-800 dark:text-slate-100 tabular-nums">{(totalPastaThreats / pastaModelCount).toFixed(1)}</p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 p-8 text-center shadow-sm">
              <p className="text-xs text-slate-400 dark:text-slate-500">No PASTA threat models found in the selected period</p>
            </div>
          )}
        </section>

      </div>
    </div>
  );
};

export default Analytics;
