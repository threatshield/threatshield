import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL } from '../services/api';
import { useAuth } from '../context/AuthContext';
import {
  AssessmentData,
  DepartmentSummary,
  DepartmentColorScheme,
  computeDepartmentSummaries,
  getDepartmentColors,
  formatDate,
  isPastaAssessment,
} from '../utils/threatConsolidation';

// ── Types ─────────────────────────────────────────────────────────────────────

interface CustomRecord {
  id: string;
  name: string;
  assessment_ids: string[];
  created_by: string;
  created_at: string;
}

// ── Icons ─────────────────────────────────────────────────────────────────────

const ShieldIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className ?? 'w-5 h-5'} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

// ── DEPARTMENT Card ──────────────────────────────────────────────────────────────────

interface TeamCardProps {
  summary: DepartmentSummary;
  colors: DepartmentColorScheme;
  onClick: () => void;
}

const TeamCard: React.FC<TeamCardProps> = ({ summary, colors, onClick }) => (
  <button
    onClick={onClick}
    className="group w-full text-left bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-2xl shadow-sm hover:shadow-lg hover:-translate-y-0.5 transition-all duration-200 overflow-hidden focus:outline-none focus:ring-2 focus:ring-[#0052cc]/40"
  >
    <div className={`h-1 w-full bg-gradient-to-r ${colors.gradient}`} />
    <div className="p-5">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${colors.gradient} flex items-center justify-center flex-shrink-0 shadow-sm`}>
            <ShieldIcon className="w-5 h-5 text-white" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-800 dark:text-slate-100 leading-tight">{summary.displayName}</h3>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
              {summary.assessments.length} sub-model{summary.assessments.length !== 1 ? 's' : ''}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5 justify-end">
          {summary.methodologies.map(m => (
            <span key={m} className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
              m === 'PASTA'
                ? 'bg-purple-50 text-purple-600 border-purple-200 dark:bg-purple-900/20 dark:text-purple-400 dark:border-purple-800/40'
                : 'bg-blue-50 text-blue-600 border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800/40'
            }`}>{m}</span>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="bg-slate-50 dark:bg-gray-800/50 rounded-xl p-3 text-center">
          <p className={`text-xl font-bold ${colors.statHighlight}`}>{summary.totalThreats}</p>
          <p className="text-[10px] font-medium text-slate-500 dark:text-slate-400 mt-0.5 leading-tight">Unique Threats</p>
        </div>
        <div className="bg-amber-50 dark:bg-amber-900/10 rounded-xl p-3 text-center border border-amber-100 dark:border-amber-800/20">
          <p className="text-xl font-bold text-amber-600 dark:text-amber-400">{summary.commonThreats}</p>
          <p className="text-[10px] font-medium text-slate-500 dark:text-slate-400 mt-0.5 leading-tight">Common</p>
        </div>
        <div className={`rounded-xl p-3 text-center ${summary.highRiskThreats > 0 ? 'bg-red-50 dark:bg-red-900/10 border border-red-100 dark:border-red-800/20' : 'bg-slate-50 dark:bg-gray-800/50'}`}>
          <p className={`text-xl font-bold ${summary.highRiskThreats > 0 ? 'text-red-600 dark:text-red-400' : 'text-slate-400 dark:text-slate-500'}`}>
            {summary.highRiskThreats}
          </p>
          <p className="text-[10px] font-medium text-slate-500 dark:text-slate-400 mt-0.5 leading-tight">High Risk</p>
        </div>
      </div>
      <div className="flex items-center justify-between pt-3 border-t border-slate-100 dark:border-gray-800/60">
        <span className="text-xs text-slate-400 dark:text-slate-500">Last analyzed {formatDate(summary.latestTimestamp)}</span>
        <span className="flex items-center gap-1 text-xs font-semibold text-[#0052cc] dark:text-blue-400 group-hover:gap-2 transition-all duration-150">
          View
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
        </span>
      </div>
    </div>
  </button>
);

// ── Custom analysis card ──────────────────────────────────────────────────────

interface CustomCardProps {
  record: CustomRecord;
  assessments: AssessmentData[];
  currentUserEmail: string;
  onClick: () => void;
}

const CustomCard: React.FC<CustomCardProps> = ({ record, assessments, currentUserEmail, onClick }) => {
  const colors = getDepartmentColors(record.id);
  const mine   = record.created_by === currentUserEmail;

  const subModels = useMemo(
    () => assessments.filter(a => record.assessment_ids.includes(a.id)),
    [assessments, record.assessment_ids],
  );

  const preview = subModels.slice(0, 3).map(a => a.name);
  const extra   = subModels.length - preview.length;

  return (
    <button
      onClick={onClick}
      className="group w-full text-left bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-2xl shadow-sm hover:shadow-lg hover:-translate-y-0.5 transition-all duration-200 overflow-hidden focus:outline-none focus:ring-2 focus:ring-[#0052cc]/40 flex flex-col"
    >
      <div className={`h-1 w-full bg-gradient-to-r ${colors.gradient} flex-shrink-0`} />
      <div className="p-5 flex-1">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${colors.gradient} flex items-center justify-center flex-shrink-0 shadow-sm`}>
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z" />
              </svg>
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-800 dark:text-slate-100 leading-tight">{record.name}</h3>
              <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
                {record.assessment_ids.length} sub-model{record.assessment_ids.length !== 1 ? 's' : ''}
              </p>
            </div>
          </div>
          {mine && (
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-blue-50 text-blue-600 border border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800/40 flex-shrink-0">
              Mine
            </span>
          )}
        </div>

        {/* Sub-model preview */}
        <div className="flex flex-wrap gap-1.5 mb-4">
          {preview.map(name => (
            <span key={name} className="text-[10px] font-medium px-2 py-0.5 rounded-md bg-slate-100 dark:bg-gray-800 text-slate-600 dark:text-slate-400 truncate max-w-[120px]">{name}</span>
          ))}
          {extra > 0 && (
            <span className="text-[10px] font-medium px-2 py-0.5 rounded-md bg-slate-100 dark:bg-gray-800 text-slate-400">+{extra} more</span>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between pt-3 border-t border-slate-100 dark:border-gray-800/60">
          <div>
            <p className="text-[10px] text-slate-400 dark:text-slate-500">{formatDate(record.created_at)}</p>
            <p className="text-[10px] text-slate-400 dark:text-slate-500 truncate max-w-[140px]">{record.created_by}</p>
          </div>
          <span className="flex items-center gap-1 text-xs font-semibold text-[#0052cc] dark:text-blue-400 group-hover:gap-2 transition-all duration-150">
            View
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
          </span>
        </div>
      </div>
    </button>
  );
};

// ── Custom sub-model selector (create view) ───────────────────────────────────

interface CustomSelectorProps {
  assessments: AssessmentData[];
  onBack: () => void;
  onCreated: (record: CustomRecord) => void;
}

const CustomSelector: React.FC<CustomSelectorProps> = ({ assessments, onBack, onCreated }) => {
  const navigate = useNavigate();
  const [search, setSearch]           = useState('');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [customName, setCustomName]   = useState('');
  const [saving, setSaving]           = useState(false);
  const [nameError, setNameError]     = useState(false);

  const sorted = useMemo(() =>
    [...assessments].sort((a, b) => {
      const departmentA = (a.details?.department ?? '').toLowerCase();
      const departmentB = (b.details?.department ?? '').toLowerCase();
      return departmentA !== departmentB ? departmentA.localeCompare(departmentB) : a.name.localeCompare(b.name);
    }),
  [assessments]);

  const filtered = useMemo(() => {
    if (!search.trim()) return sorted;
    const q = search.toLowerCase();
    return sorted.filter(a =>
      a.name.toLowerCase().includes(q) ||
      (a.details?.department ?? '').toLowerCase().includes(q) ||
      (a.details?.threatModelingMethodology ?? '').toLowerCase().includes(q)
    );
  }, [sorted, search]);

  const toggle    = (id: string) => setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const selectAll = () => setSelectedIds(new Set(filtered.map(a => a.id)));
  const clearAll  = () => setSelectedIds(new Set());

  const analyze = async () => {
    if (!customName.trim()) { setNameError(true); return; }
    if (selectedIds.size === 0) return;
    setSaving(true);
    setNameError(false);
    try {
      const token = localStorage.getItem('ts_auth_token') ?? '';
      const res = await fetch(`${API_BASE_URL}/custom-threat-models`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ name: customName.trim(), assessment_ids: Array.from(selectedIds) }),
      });
      if (!res.ok) throw new Error('Failed to save');
      const { id, record } = await res.json();
      onCreated(record);
      navigate(`/department-threat-models/custom/${id}`);
    } catch {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Back + title */}
      <div className="flex items-center gap-3">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-sm font-medium text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Saved analyses
        </button>
      </div>

      {/* Name field — mandatory */}
      <div>
        <input
          value={customName}
          onChange={e => { setCustomName(e.target.value); if (e.target.value.trim()) setNameError(false); }}
          placeholder="Analysis name (required)…"
          className={`w-full px-4 py-2.5 text-sm bg-white dark:bg-gray-900/80 border rounded-xl focus:outline-none focus:ring-2 text-slate-800 dark:text-slate-100 placeholder-slate-400 ${
            nameError
              ? 'border-red-400 focus:ring-red-300'
              : 'border-slate-200 dark:border-gray-700/60 focus:ring-[#0052cc]/30'
          }`}
        />
        {nameError && <p className="mt-1 text-xs text-red-500">Please enter a name before analyzing.</p>}
      </div>

      {/* Search + select-all row */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search sub-models…"
            className="w-full pl-9 pr-4 py-2.5 text-sm bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 text-slate-800 dark:text-slate-100 placeholder-slate-400"
          />
        </div>
        <button onClick={selectAll} className="text-xs font-semibold text-[#0052cc] dark:text-blue-400 hover:underline whitespace-nowrap">Select all</button>
        <button onClick={clearAll}  className="text-xs font-semibold text-slate-400 hover:underline whitespace-nowrap">Clear</button>
      </div>

      {/* Sub-model list */}
      <div className="bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl overflow-hidden shadow-sm">
        {filtered.length === 0 ? (
          <p className="px-5 py-8 text-sm text-slate-400 text-center">No sub-models match your search.</p>
        ) : (
          <div className="divide-y divide-slate-100 dark:divide-gray-800/40">
            {filtered.map(a => {
              const isPasta    = isPastaAssessment(a);
              const checked    = selectedIds.has(a.id);
              const threatCount = a.threat_model?.result?.raw_response?.threat_model?.length ?? 0;
              return (
                <label
                  key={a.id}
                  className={`flex items-center gap-4 px-5 py-3.5 cursor-pointer transition-colors ${checked ? 'bg-blue-50/60 dark:bg-blue-900/10' : 'hover:bg-slate-50 dark:hover:bg-gray-800/30'}`}
                >
                  <input type="checkbox" checked={checked} onChange={() => toggle(a.id)} className="w-4 h-4 rounded accent-[#0052cc] flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-slate-800 dark:text-slate-100 truncate">{a.name}</p>
                    <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                      {a.details?.department && (
                        <span className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-gray-800 px-1.5 py-0.5 rounded-full">
                          {a.details.department}
                        </span>
                      )}
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${
                        isPasta
                          ? 'bg-purple-50 text-purple-600 border-purple-200 dark:bg-purple-900/20 dark:text-purple-400 dark:border-purple-800/40'
                          : 'bg-blue-50 text-blue-600 border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800/40'
                      }`}>{isPasta ? 'PASTA' : 'STRIDE'}</span>
                      <span className="text-[10px] text-slate-400 dark:text-slate-500">{formatDate(a.timestamp)}</span>
                    </div>
                  </div>
                  <span className="text-xs text-slate-400 dark:text-slate-500 flex-shrink-0">{threatCount} threats</span>
                </label>
              );
            })}
          </div>
        )}
      </div>

      {/* Action bar */}
      {selectedIds.size > 0 && (
        <div className="sticky bottom-4 flex items-center justify-between bg-slate-800 dark:bg-gray-900 text-white px-5 py-3.5 rounded-xl shadow-xl">
          <span className="text-sm font-semibold">{selectedIds.size} sub-model{selectedIds.size !== 1 ? 's' : ''} selected</span>
          <button
            onClick={analyze}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#0052cc] hover:bg-blue-700 text-white text-sm font-semibold transition-colors disabled:opacity-60"
          >
            {saving ? 'Saving…' : 'Analyse & Save'}
            {!saving && <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>}
          </button>
        </div>
      )}
    </div>
  );
};

// ── Custom list view ──────────────────────────────────────────────────────────

interface CustomListProps {
  records: CustomRecord[];
  assessments: AssessmentData[];
  currentUserEmail: string;
  onNew: () => void;
  onSelect: (id: string) => void;
}

const CustomList: React.FC<CustomListProps> = ({ records, assessments, currentUserEmail, onNew, onSelect }) => {
  const [nameSearch, setNameSearch]         = useState('');
  const [subModelFilter, setSubModelFilter] = useState('');
  const [creatorFilter, setCreatorFilter]   = useState<'all' | 'mine'>('all');

  const filtered = useMemo(() => {
    return records.filter(r => {
      if (nameSearch.trim() && !r.name.toLowerCase().includes(nameSearch.toLowerCase())) return false;
      if (subModelFilter) {
        const match = assessments.find(a => a.id === subModelFilter);
        if (!match || !r.assessment_ids.includes(match.id)) return false;
      }
      if (creatorFilter === 'mine' && r.created_by !== currentUserEmail) return false;
      return true;
    });
  }, [records, nameSearch, subModelFilter, creatorFilter, assessments, currentUserEmail]);

  const hasFilters = nameSearch.trim() !== '' || subModelFilter !== '' || creatorFilter !== 'all';

  return (
    <div className="space-y-5">
      {/* Header row: title + '+' button */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">Saved Analyses</h2>
          <span className="bg-slate-200 dark:bg-gray-700 text-slate-600 dark:text-slate-300 text-xs font-semibold px-2 py-0.5 rounded-full">{records.length}</span>
        </div>
        <button
          onClick={onNew}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#0052cc] hover:bg-blue-700 text-white text-sm font-semibold shadow-sm transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" />
          </svg>
          New
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Name search */}
        <div className="relative flex-1 min-w-[180px]">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            value={nameSearch}
            onChange={e => setNameSearch(e.target.value)}
            placeholder="Search by name…"
            className="w-full pl-9 pr-4 py-2 text-sm bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 text-slate-800 dark:text-slate-100 placeholder-slate-400"
          />
        </div>

        {/* Sub-model filter */}
        <select
          value={subModelFilter}
          onChange={e => setSubModelFilter(e.target.value)}
          className="px-3 py-2 text-sm bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 text-slate-700 dark:text-slate-300"
        >
          <option value="">All sub-models</option>
          {assessments.sort((a,b) => a.name.localeCompare(b.name)).map(a => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </select>

        {/* Creator filter */}
        <div className="flex items-center gap-1 bg-slate-100 dark:bg-gray-800/70 rounded-xl p-1 border border-slate-200 dark:border-gray-700/60">
          {(['all', 'mine'] as const).map(f => (
            <button
              key={f}
              onClick={() => setCreatorFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 ${
                creatorFilter === f
                  ? 'bg-white dark:bg-[#0d1e38] text-[#0052cc] dark:text-blue-400 shadow-sm'
                  : 'text-slate-500 dark:text-slate-400 hover:bg-white/60 dark:hover:bg-gray-700/50'
              }`}
            >
              {f === 'all' ? 'All' : 'Mine'}
            </button>
          ))}
        </div>

        {hasFilters && (
          <button
            onClick={() => { setNameSearch(''); setSubModelFilter(''); setCreatorFilter('all'); }}
            className="text-xs font-semibold text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 flex items-center gap-1"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
            Clear filters
          </button>
        )}
      </div>

      {/* Cards grid or empty states */}
      {records.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="w-14 h-14 rounded-2xl bg-slate-100 dark:bg-gray-800 flex items-center justify-center mx-auto mb-4">
            <svg className="w-7 h-7 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z" />
            </svg>
          </div>
          <h3 className="text-base font-semibold text-slate-700 dark:text-slate-300 mb-1">No saved analyses yet</h3>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">Click <strong>New</strong> to combine sub-models and create a custom analysis.</p>
          <button onClick={onNew} className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[#0052cc] hover:bg-blue-700 text-white text-sm font-semibold transition-colors">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" /></svg>
            Create first analysis
          </button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-sm text-slate-400 dark:text-slate-500">No analyses match your filters.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {filtered.map(record => (
            <CustomCard
              key={record.id}
              record={record}
              assessments={assessments}
              currentUserEmail={currentUserEmail}
              onClick={() => onSelect(record.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
};

// ── Main page ─────────────────────────────────────────────────────────────────

const TeamThreatModels: React.FC = () => {
  const navigate     = useNavigate();
  const { user }     = useAuth();

  const [loading, setLoading]               = useState(true);
  const [error, setError]                   = useState<string | null>(null);
  const [raw, setRaw]                       = useState<AssessmentData[]>([]);
  const [activeSection, setActiveSection]   = useState<'team' | 'custom'>('team');
  const [customView, setCustomView]         = useState<'list' | 'create'>('list');
  const [customRecords, setCustomRecords]   = useState<CustomRecord[]>([]);
  const [customLoading, setCustomLoading]   = useState(false);

  useEffect(() => {
    fetch(`${API_BASE_URL}/analytics-data`)
      .then(r => { if (!r.ok) throw new Error('Failed to fetch'); return r.json(); })
      .then(data => { setRaw(data.data ?? []); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, []);

  // Fetch saved custom analyses when Custom tab is opened
  useEffect(() => {
    if (activeSection !== 'custom') return;
    setCustomLoading(true);
    const token = localStorage.getItem('ts_auth_token') ?? '';
    fetch(`${API_BASE_URL}/custom-threat-models`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then(r => r.ok ? r.json() : { records: [] })
      .then(data => { setCustomRecords(data.records ?? []); setCustomLoading(false); })
      .catch(() => setCustomLoading(false));
  }, [activeSection]);

  const summaries    = useMemo(() => computeDepartmentSummaries(raw), [raw]);
  const globalStats  = useMemo(() => ({
    departments: summaries.length,
    assessments: summaries.reduce((s, l) => s + l.assessments.length, 0),
    threats:     summaries.reduce((s, l) => s + l.totalThreats, 0),
    common:      summaries.reduce((s, l) => s + l.commonThreats, 0),
  }), [summaries]);

  const handleCreated = (record: CustomRecord) => {
    setCustomRecords(prev => [record, ...prev]);
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-[#0a1628]">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-14 h-14">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
          </div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Loading threat models…</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-[#0a1628]">
        <div className="text-center">
          <div className="w-12 h-12 rounded-full bg-red-100 dark:bg-red-900/20 flex items-center justify-center mx-auto mb-3">
            <svg className="w-6 h-6 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <p className="text-sm font-medium text-slate-700 dark:text-slate-300">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#0a1628] dark-grid-bg">
      <div className="px-6 sm:px-8 py-8">

        {/* Page header */}
        <div className="flex items-start justify-between mb-1">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#0052cc] to-blue-700 flex items-center justify-center shadow-sm">
                <ShieldIcon className="w-4 h-4 text-white" />
              </div>
              <h1 className="text-2xl font-bold text-slate-800 dark:text-slate-100">Threat Models</h1>
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-400 ml-12">
              Consolidated security threat landscape across all Teams
            </p>
          </div>

          {/* Section tabs */}
          <div className="flex items-center gap-1 bg-slate-100 dark:bg-gray-800/70 rounded-xl p-1 border border-slate-200 dark:border-gray-700/60 shadow-sm">
            {(['team', 'custom'] as const).map(section => (
              <button
                key={section}
                onClick={() => { setActiveSection(section); if (section === 'custom') setCustomView('list'); }}
                className={`px-5 py-2 rounded-lg text-sm font-semibold transition-all duration-150 ${
                  activeSection === section
                    ? 'bg-white dark:bg-[#0d1e38] text-[#0052cc] dark:text-blue-400 shadow-sm'
                    : 'text-slate-500 dark:text-slate-400 hover:bg-white/60 dark:hover:bg-gray-700/50'
                }`}
              >
                {section === 'team' ? 'Teams' : 'Custom'}
              </button>
            ))}
          </div>
        </div>

        <p className="mb-6 text-xs text-slate-400 dark:text-slate-600 text-right">
          Unique and common threats are computed via semantic similarity analysis across sub-models.
        </p>

        {/* Global stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
          {[
            { label: 'Teams',             value: globalStats.departments,  color: 'text-[#0052cc] dark:text-blue-400',  bg: 'bg-blue-50 dark:bg-blue-900/10 border-blue-100 dark:border-blue-800/20' },
            { label: 'Sub-Models',        value: globalStats.assessments,  color: 'text-slate-700 dark:text-slate-200', bg: 'bg-white dark:bg-gray-900/80 border-slate-200 dark:border-gray-700/60' },
            { label: 'Unique Threats',    value: globalStats.threats,      color: 'text-slate-700 dark:text-slate-200', bg: 'bg-white dark:bg-gray-900/80 border-slate-200 dark:border-gray-700/60' },
            { label: 'Common Threats',    value: globalStats.common,       color: 'text-amber-600 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-900/10 border-amber-100 dark:border-amber-800/20' },
          ].map(stat => (
            <div key={stat.label} className={`${stat.bg} border rounded-xl p-4 shadow-sm`}>
              <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
              <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mt-1">{stat.label}</p>
            </div>
          ))}
        </div>

        {/* Teams */}
        {activeSection === 'team' && (
          summaries.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <div className="w-14 h-14 rounded-2xl bg-slate-100 dark:bg-gray-800 flex items-center justify-center mx-auto mb-4">
                <ShieldIcon className="w-7 h-7 text-slate-400" />
              </div>
              <h3 className="text-base font-semibold text-slate-700 dark:text-slate-300 mb-1">No threat models yet</h3>
              <p className="text-sm text-slate-500 dark:text-slate-400">Complete an assessment to see team-level threat models here.</p>
            </div>
          ) : (
            <>
              <div className="flex items-center gap-2 mb-4">
                <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">Teams</h2>
                <span className="bg-slate-200 dark:bg-gray-700 text-slate-600 dark:text-slate-300 text-xs font-semibold px-2 py-0.5 rounded-full">{summaries.length}</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {summaries.map(summary => (
                  <TeamCard
                    key={summary.department}
                    summary={summary}
                    colors={getDepartmentColors(summary.department)}
                    onClick={() => navigate(`/department-threat-models/${encodeURIComponent(summary.department.toLowerCase())}`)}
                  />
                ))}
              </div>
            </>
          )
        )}

        {/* Custom */}
        {activeSection === 'custom' && (
          customLoading ? (
            <div className="flex items-center justify-center py-16">
              <div className="relative w-10 h-10">
                <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
                <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
              </div>
            </div>
          ) : customView === 'list' ? (
            <CustomList
              records={customRecords}
              assessments={raw}
              currentUserEmail={user?.email ?? ''}
              onNew={() => setCustomView('create')}
              onSelect={id => navigate(`/department-threat-models/custom/${id}`)}
            />
          ) : (
            <CustomSelector
              assessments={raw}
              onBack={() => setCustomView('list')}
              onCreated={handleCreated}
            />
          )
        )}

      </div>
    </div>
  );
};

export default TeamThreatModels;
