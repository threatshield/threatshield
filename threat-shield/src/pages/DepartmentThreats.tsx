import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { API_BASE_URL } from '../services/api';
import {
  AssessmentData,
  ConsolidatedThreat,
  isPastaAssessment,
  consolidateThreats,
  formatDate,
} from '../utils/threatConsolidation';

// ── STRIDE color map ──────────────────────────────────────────────────────────

interface ThreatColors {
  bg: string; text: string; border: string; dot: string;
  darkBg: string; darkText: string; darkBorder: string;
}

const STRIDE_COLORS: Record<string, ThreatColors> = {
  'Spoofing':               { bg: 'bg-violet-50', text: 'text-violet-700', border: 'border-violet-200', dot: 'bg-violet-500',  darkBg: 'dark:bg-violet-900/20', darkText: 'dark:text-violet-400', darkBorder: 'dark:border-violet-800/40' },
  'Tampering':              { bg: 'bg-orange-50', text: 'text-orange-700', border: 'border-orange-200', dot: 'bg-orange-500',  darkBg: 'dark:bg-orange-900/20', darkText: 'dark:text-orange-400', darkBorder: 'dark:border-orange-800/40' },
  'Repudiation':            { bg: 'bg-yellow-50', text: 'text-yellow-700', border: 'border-yellow-200', dot: 'bg-yellow-500',  darkBg: 'dark:bg-yellow-900/20', darkText: 'dark:text-yellow-400', darkBorder: 'dark:border-yellow-800/40' },
  'Information Disclosure': { bg: 'bg-sky-50',    text: 'text-sky-700',    border: 'border-sky-200',    dot: 'bg-sky-500',     darkBg: 'dark:bg-sky-900/20',    darkText: 'dark:text-sky-400',    darkBorder: 'dark:border-sky-800/40' },
  'Denial of Service':      { bg: 'bg-red-50',    text: 'text-red-700',    border: 'border-red-200',    dot: 'bg-red-500',     darkBg: 'dark:bg-red-900/20',    darkText: 'dark:text-red-400',    darkBorder: 'dark:border-red-800/40' },
  'Elevation of Privilege': { bg: 'bg-rose-50',   text: 'text-rose-700',   border: 'border-rose-200',   dot: 'bg-rose-500',    darkBg: 'dark:bg-rose-900/20',   darkText: 'dark:text-rose-400',   darkBorder: 'dark:border-rose-800/40' },
};
const DEFAULT_COLORS: ThreatColors = {
  bg: 'bg-slate-50', text: 'text-slate-700', border: 'border-slate-200', dot: 'bg-slate-400',
  darkBg: 'dark:bg-slate-800/40', darkText: 'dark:text-slate-300', darkBorder: 'dark:border-slate-700/60',
};
const getThreatColors = (type: string): ThreatColors => STRIDE_COLORS[type] ?? DEFAULT_COLORS;

const PASTA_BIZ_RISK_COLORS: Record<string, ThreatColors> = {
  'Financial':    { bg: 'bg-emerald-50',  text: 'text-emerald-700',  border: 'border-emerald-200',  dot: 'bg-emerald-500',  darkBg: 'dark:bg-emerald-900/20', darkText: 'dark:text-emerald-400', darkBorder: 'dark:border-emerald-800/40' },
  'Reputational': { bg: 'bg-violet-50',   text: 'text-violet-700',   border: 'border-violet-200',   dot: 'bg-violet-500',   darkBg: 'dark:bg-violet-900/20',  darkText: 'dark:text-violet-400',  darkBorder: 'dark:border-violet-800/40' },
  'Operational':  { bg: 'bg-orange-50',   text: 'text-orange-700',   border: 'border-orange-200',   dot: 'bg-orange-500',   darkBg: 'dark:bg-orange-900/20',  darkText: 'dark:text-orange-400',  darkBorder: 'dark:border-orange-800/40' },
  'Regulatory':   { bg: 'bg-sky-50',      text: 'text-sky-700',      border: 'border-sky-200',      dot: 'bg-sky-500',      darkBg: 'dark:bg-sky-900/20',     darkText: 'dark:text-sky-400',     darkBorder: 'dark:border-sky-800/40' },
  'Strategic':    { bg: 'bg-indigo-50',   text: 'text-indigo-700',   border: 'border-indigo-200',   dot: 'bg-indigo-500',   darkBg: 'dark:bg-indigo-900/20',  darkText: 'dark:text-indigo-400',  darkBorder: 'dark:border-indigo-800/40' },
  'Privacy':      { bg: 'bg-pink-50',     text: 'text-pink-700',     border: 'border-pink-200',     dot: 'bg-pink-500',     darkBg: 'dark:bg-pink-900/20',    darkText: 'dark:text-pink-400',    darkBorder: 'dark:border-pink-800/40' },
};
const getPastaRiskColors = (type: string): ThreatColors => PASTA_BIZ_RISK_COLORS[type] ?? DEFAULT_COLORS;

const RISK_BADGE: Record<string, string> = {
  Critical: 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800/40',
  High:     'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-900/20 dark:text-orange-400 dark:border-orange-800/40',
  Medium:   'bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800/40',
  Low:      'bg-green-100 text-green-700 border-green-200 dark:bg-green-900/20 dark:text-green-400 dark:border-green-800/40',
  Unknown:  'bg-slate-100 text-slate-500 border-slate-200 dark:bg-slate-800/40 dark:text-slate-400 dark:border-slate-700/60',
};

// ── Threat Card ───────────────────────────────────────────────────────────────

const ThreatCard: React.FC<{ threat: ConsolidatedThreat }> = ({ threat }) => {
  const [expanded, setExpanded] = useState(false);
  const colors = getThreatColors(threat.threatType);

  return (
    <div className={`rounded-xl border ${threat.isCommon ? 'border-amber-200 dark:border-amber-800/40' : 'border-slate-200 dark:border-gray-700/60'} bg-white dark:bg-gray-900/80 overflow-hidden shadow-sm hover:shadow-md transition-shadow`}>
      <div className="p-4">
        <div className="flex items-start gap-3 flex-wrap">
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold border flex-shrink-0 mt-0.5 ${colors.bg} ${colors.text} ${colors.border} ${colors.darkBg} ${colors.darkText} ${colors.darkBorder}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${colors.dot} flex-shrink-0`} />
            {threat.threatType}
          </span>
          <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-bold border flex-shrink-0 mt-1 ${RISK_BADGE[threat.riskLevel]}`}>
            {threat.riskLevel}
          </span>
          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border flex-shrink-0 mt-1 ${
            threat.methodology === 'PASTA'
              ? 'bg-purple-50 text-purple-600 border-purple-200 dark:bg-purple-900/20 dark:text-purple-400 dark:border-purple-800/40'
              : 'bg-blue-50 text-blue-600 border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800/40'
          }`}>{threat.methodology}</span>
          {threat.isCommon && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400 border border-amber-200 dark:border-amber-800/40 flex-shrink-0 mt-1">
              <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0" />
              </svg>
              {threat.occurrenceCount} sub-models
            </span>
          )}
        </div>

        <p className="mt-2.5 text-sm font-medium text-slate-800 dark:text-slate-100 leading-relaxed">
          {threat.scenario}
        </p>
        {threat.potentialImpact && (
          <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400 leading-relaxed line-clamp-2">
            {threat.potentialImpact}
          </p>
        )}

        <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-100 dark:border-gray-800/60">
          <div className="flex items-center gap-2">
            {threat.avgDreadScore > 0 && (
              <span className="text-xs text-slate-500 dark:text-slate-400">
                DREAD {threat.avgDreadScore.toFixed(1)}
                {threat.maxDreadScore !== threat.avgDreadScore && (
                  <span className="text-slate-400 dark:text-slate-500"> (max {threat.maxDreadScore.toFixed(1)})</span>
                )}
              </span>
            )}
          </div>
          <button
            onClick={() => setExpanded(v => !v)}
            className="flex items-center gap-1 text-xs font-medium text-[#0052cc] dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
          >
            {threat.contributingAssessments.length} sub-model{threat.contributingAssessments.length !== 1 ? 's' : ''}
            <svg className={`w-3.5 h-3.5 transition-transform duration-200 ${expanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-slate-100 dark:border-gray-800/60 bg-slate-50/70 dark:bg-gray-800/30">
          <div className="px-4 pt-3 pb-1">
            <p className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Contributing Sub-Models</p>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-gray-800/40">
            {threat.contributingAssessments.map(ca => (
              <div key={ca.id} className="flex items-center justify-between px-4 py-2.5 hover:bg-slate-100/50 dark:hover:bg-gray-700/20 transition-colors">
                <div className="flex-1 min-w-0 mr-4">
                  <p className="text-xs font-semibold text-slate-700 dark:text-slate-300 truncate">{ca.name}</p>
                  <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 line-clamp-1">{ca.originalScenario}</p>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <div className="text-right">
                    <p className="text-[10px] text-slate-500 dark:text-slate-400">{formatDate(ca.timestamp)}</p>
                    {ca.dreadScore > 0 && (
                      <p className={`text-[10px] font-semibold ${ca.dreadScore >= 8 ? 'text-red-500' : ca.dreadScore >= 5 ? 'text-amber-500' : 'text-slate-400'}`}>
                        DREAD {ca.dreadScore.toFixed(1)}
                      </p>
                    )}
                  </div>
                  <Link
                    to={`/view-threat-model/${ca.id}`}
                    onClick={e => e.stopPropagation()}
                    className="flex items-center gap-0.5 text-xs font-medium text-[#0052cc] dark:text-blue-400 hover:underline flex-shrink-0"
                  >
                    View
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// ── Main page ─────────────────────────────────────────────────────────────────

const RISK_LEVELS = ['Critical', 'High', 'Medium', 'Low', 'Unknown'] as const;

const DepartmentThreats: React.FC = () => {
  const { department: departmentParam, customId } = useParams<{ department?: string; customId?: string }>();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [raw, setRaw] = useState<AssessmentData[]>([]);
  const [customName, setCustomName] = useState('Custom Analysis');
  const [customSelectedIds, setCustomSelectedIds] = useState<Set<string>>(new Set());

  const [search, setSearch] = useState('');
  const [activeMethodology, setActiveMethodology] = useState<'all' | 'STRIDE' | 'PASTA'>('all');
  const [activeType, setActiveType] = useState('all');
  const [activeRisk, setActiveRisk] = useState('all');
  const [showCommonOnly, setShowCommonOnly] = useState(false);
  const [activeBusinessRiskType, setActiveBusinessRiskType] = useState('all');

  useEffect(() => {
    const token = localStorage.getItem('ts_auth_token') ?? '';
    const authHeaders: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};

    const analyticsPromise = fetch(`${API_BASE_URL}/analytics-data`)
      .then(r => { if (!r.ok) throw new Error('Failed to fetch'); return r.json(); });

    if (customId) {
      Promise.all([
        analyticsPromise,
        fetch(`${API_BASE_URL}/custom-threat-models/${customId}`, { headers: authHeaders })
          .then(r => { if (!r.ok) throw new Error('Custom analysis not found'); return r.json(); }),
      ])
        .then(([analytics, custom]) => {
          setRaw(analytics.data ?? []);
          setCustomName(custom.name ?? 'Custom Analysis');
          setCustomSelectedIds(new Set(custom.assessment_ids ?? []));
          setLoading(false);
        })
        .catch(e => { setError(e.message); setLoading(false); });
    } else {
      analyticsPromise
        .then(data => { setRaw(data.data ?? []); setLoading(false); })
        .catch(e => { setError(e.message); setLoading(false); });
    }
  }, [customId]);

  const departmentAssessments = useMemo(() => {
    if (customId) return raw.filter(a => customSelectedIds.has(a.id));
    if (!departmentParam) return [];
    return raw.filter(a =>
      (a.details?.department ?? '').toLowerCase() === decodeURIComponent(departmentParam).toLowerCase()
    );
  }, [raw, departmentParam, customId, customSelectedIds]);

  const displayName = useMemo(() => {
    if (customId) return customName;
    if (departmentAssessments.length > 0) {
      const name = departmentAssessments[0].details?.department ?? departmentParam ?? '';
      return name.toUpperCase() === name ? name : name.charAt(0).toUpperCase() + name.slice(1);
    }
    const name = decodeURIComponent(departmentParam ?? '');
    return name.charAt(0).toUpperCase() + name.slice(1);
  }, [departmentAssessments, departmentParam, customId, customName]);

  const strideThreats = useMemo(
    () => consolidateThreats(departmentAssessments.filter(a => !isPastaAssessment(a)), 'STRIDE'),
    [departmentAssessments],
  );
  const pastaThreats = useMemo(
    () => consolidateThreats(departmentAssessments.filter(a => isPastaAssessment(a)), 'PASTA'),
    [departmentAssessments],
  );
  const allThreats = useMemo(() => [...strideThreats, ...pastaThreats], [strideThreats, pastaThreats]);
  const allTypes = useMemo(() => Array.from(new Set(strideThreats.map(t => t.threatType))).sort(), [strideThreats]);
  const allPastaBusinessRiskTypes = useMemo(() =>
    Array.from(new Set(pastaThreats.flatMap(t => t.businessRiskTypes))).sort(),
    [pastaThreats],
  );

  const filtered = useMemo(() => {
    return allThreats.filter(t => {
      if (activeMethodology !== 'all' && t.methodology !== activeMethodology) return false;
      if (activeType !== 'all' && t.threatType !== activeType) return false;
      if (activeRisk !== 'all' && t.riskLevel !== activeRisk) return false;
      if (showCommonOnly && !t.isCommon) return false;
      if (activeBusinessRiskType !== 'all' && !t.businessRiskTypes.includes(activeBusinessRiskType)) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          t.scenario.toLowerCase().includes(q) ||
          t.threatType.toLowerCase().includes(q) ||
          t.potentialImpact.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [allThreats, activeMethodology, activeType, activeRisk, showCommonOnly, activeBusinessRiskType, search]);

  // ── Loading / error / empty ────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-[#0a1628]">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-14 h-14">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
          </div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Loading threats…</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-[#0a1628]">
        <div className="text-center">
          <p className="text-sm font-medium text-red-500">{error}</p>
          <button onClick={() => navigate(-1)} className="mt-3 text-sm text-[#0052cc] hover:underline">← Go back</button>
        </div>
      </div>
    );
  }

  const resetFilters = () => {
    setSearch('');
    setActiveMethodology('all');
    setActiveType('all');
    setActiveRisk('all');
    setShowCommonOnly(false);
    setActiveBusinessRiskType('all');
  };

  const hasFilters = search || activeMethodology !== 'all' || activeType !== 'all' || activeRisk !== 'all' || showCommonOnly || activeBusinessRiskType !== 'all';

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#0a1628] dark-grid-bg">
      <div className="px-6 sm:px-8 py-8">

        {/* Back navigation */}
        <button
          onClick={() => navigate(customId ? `/department-threat-models/custom/${customId}` : `/department-threat-models/${departmentParam}`)}
          className="flex items-center gap-1.5 text-sm font-medium text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 mb-6 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          {displayName} Overview
        </button>

        {/* Page header */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-slate-800 dark:text-slate-100">
            {displayName} — All Threats
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {allThreats.length} consolidated threats across {departmentAssessments.length} sub-model{departmentAssessments.length !== 1 ? 's' : ''}
          </p>
        </div>

        {/* Search + filters */}
        <div className="bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-2xl shadow-sm p-4 mb-6 space-y-4">

          {/* Search bar */}
          <div className="relative">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search threats by scenario, type, or impact…"
              className="w-full pl-9 pr-4 py-2.5 text-sm bg-slate-50 dark:bg-gray-800/60 border border-slate-200 dark:border-gray-700/60 rounded-xl text-slate-800 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc]/50 transition-all"
            />
            {search && (
              <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>

          {/* Filter pills row */}
          <div className="flex flex-wrap gap-2 items-center">
            {/* Methodology */}
            {(['all', 'STRIDE', 'PASTA'] as const).map(m => (
              <button
                key={m}
                onClick={() => {
                  setActiveMethodology(m);
                  if (m === 'PASTA') setActiveType('all');
                  else setActiveBusinessRiskType('all');
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150 ${
                  activeMethodology === m
                    ? m === 'PASTA'
                      ? 'bg-purple-600 text-white border-purple-600'
                      : m === 'STRIDE'
                      ? 'bg-[#0052cc] text-white border-[#0052cc]'
                      : 'bg-slate-700 text-white border-slate-700 dark:bg-slate-200 dark:text-slate-800'
                    : 'bg-white dark:bg-gray-800/60 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-gray-700/60 hover:bg-slate-50'
                }`}
              >
                {m === 'all' ? 'All Methods' : m}
              </button>
            ))}

            <div className="w-px h-5 bg-slate-200 dark:bg-gray-700 mx-1" />

            {/* Threat type / Business Risk Category pills */}
            {activeMethodology === 'PASTA' ? (
              <>
                <button
                  onClick={() => setActiveBusinessRiskType('all')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150 ${
                    activeBusinessRiskType === 'all'
                      ? 'bg-purple-600 text-white border-purple-600 shadow-sm'
                      : 'bg-white dark:bg-gray-800/60 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-gray-700/60 hover:bg-slate-50'
                  }`}
                >
                  All Business Risks
                </button>
                {allPastaBusinessRiskTypes.map(brt => {
                  const c = getPastaRiskColors(brt);
                  const isActive = activeBusinessRiskType === brt;
                  return (
                    <button
                      key={brt}
                      onClick={() => setActiveBusinessRiskType(brt)}
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150 ${
                        isActive
                          ? `${c.bg} ${c.text} ${c.border} ${c.darkBg} ${c.darkText} ${c.darkBorder} shadow-sm`
                          : 'bg-white dark:bg-gray-800/60 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-gray-700/60 hover:bg-slate-50'
                      }`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
                      {brt}
                    </button>
                  );
                })}
              </>
            ) : (
              <>
                <button
                  onClick={() => setActiveType('all')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150 ${
                    activeType === 'all'
                      ? 'bg-[#0052cc] text-white border-[#0052cc] shadow-sm'
                      : 'bg-white dark:bg-gray-800/60 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-gray-700/60 hover:bg-slate-50'
                  }`}
                >
                  All Types
                </button>
                {allTypes.map(type => {
                  const c = getThreatColors(type);
                  const isActive = activeType === type;
                  return (
                    <button
                      key={type}
                      onClick={() => setActiveType(type)}
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150 ${
                        isActive
                          ? `${c.bg} ${c.text} ${c.border} ${c.darkBg} ${c.darkText} ${c.darkBorder} shadow-sm`
                          : 'bg-white dark:bg-gray-800/60 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-gray-700/60 hover:bg-slate-50'
                      }`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
                      {type}
                    </button>
                  );
                })}
              </>
            )}

            <div className="w-px h-5 bg-slate-200 dark:bg-gray-700 mx-1" />

            {/* Risk level pills */}
            <button
              onClick={() => setActiveRisk('all')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150 ${
                activeRisk === 'all'
                  ? 'bg-[#0052cc] text-white border-[#0052cc] shadow-sm'
                  : 'bg-white dark:bg-gray-800/60 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-gray-700/60 hover:bg-slate-50'
              }`}
            >
              All Risk
            </button>
            {RISK_LEVELS.map(r => (
              <button
                key={r}
                onClick={() => setActiveRisk(r)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150 ${
                  activeRisk === r
                    ? `${RISK_BADGE[r]} shadow-sm`
                    : 'bg-white dark:bg-gray-800/60 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-gray-700/60 hover:bg-slate-50'
                }`}
              >
                {r}
              </button>
            ))}

            <div className="w-px h-5 bg-slate-200 dark:bg-gray-700 mx-1" />

            {/* Common only toggle */}
            <button
              onClick={() => setShowCommonOnly(v => !v)}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150 ${
                showCommonOnly
                  ? 'bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-400 dark:border-amber-800/40 shadow-sm'
                  : 'bg-white dark:bg-gray-800/60 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-gray-700/60 hover:bg-slate-50'
              }`}
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0" />
              </svg>
              Common only
            </button>

            {/* Reset */}
            {hasFilters && (
              <button
                onClick={resetFilters}
                className="ml-auto flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 border border-slate-200 dark:border-gray-700/60 hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-all"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
                Clear filters
              </button>
            )}
          </div>
        </div>

        {/* Results header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">
              {filtered.length === allThreats.length
                ? `${allThreats.length} threat${allThreats.length !== 1 ? 's' : ''}`
                : `${filtered.length} of ${allThreats.length} threats`}
            </span>
            {filtered.length !== allThreats.length && (
              <span className="text-xs text-slate-400 dark:text-slate-500">matching filters</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              {filtered.filter(t => t.isCommon).length} common
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-red-400" />
              {filtered.filter(t => t.maxDreadScore >= 8).length} high/critical
            </span>
          </div>
        </div>

        {/* Threats grid */}
        {filtered.length === 0 ? (
          <div className="text-center py-16">
            <div className="w-12 h-12 rounded-full bg-slate-100 dark:bg-gray-800 flex items-center justify-center mx-auto mb-3">
              <svg className="w-6 h-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            <p className="text-sm font-medium text-slate-600 dark:text-slate-400">No threats match your filters</p>
            <button onClick={resetFilters} className="mt-2 text-sm text-[#0052cc] dark:text-blue-400 hover:underline">
              Clear filters
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
            {filtered.map(threat => (
              <ThreatCard key={threat.key} threat={threat} />
            ))}
          </div>
        )}

        <p className="mt-8 text-xs text-slate-400 dark:text-slate-600 text-center">
          Threats consolidated via Jaccard similarity (≥ 0.28) with security synonym normalization. Phase 0 — computed in-browser.
        </p>
      </div>
    </div>
  );
};

export default DepartmentThreats;
