import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { Link, Navigate, useSearchParams } from 'react-router-dom';
import { API_BASE_URL, apiService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { ReportMetadata } from '../types/reportTypes';
import { WORLD_CLOCK_ZONES, DEFAULT_TIMEZONE } from '../utils/timezones';

// ─── Types ───────────────────────────────────────────────────────────────────

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

type FeedbackAnswers = FeedbackEntry['answers'];

type ScoreKey =
  | 'threat_coverage'
  | 'threat_accuracy'
  | 'dread_accuracy'
  | 'mitigation_quality'
  | 'test_case_relevance'
  | 'overall_usefulness';

// Optional helper if ReportMetadata doesn't already define these fields
type ReportStatus =
  | 'completed'
  | 'processing'
  | 'queued'
  | 'pending'
  | 'failed'
  | 'cancelled'
  | 'unknown';

// ─── Helpers ─────────────────────────────────────────────────────────────────

const formatDate = (iso: string) =>
  new Date(iso).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });

const avg = (nums: number[]): number | null => {
  if (!nums.length) return null;
  return Math.round((nums.reduce((a, b) => a + b, 0) / nums.length) * 10) / 10;
};

const SCORE_DIMS: ReadonlyArray<{
  key: ScoreKey;
  label: string;
  color: string;
}> = [
  { key: 'threat_coverage', label: 'Threat Coverage', color: 'bg-blue-500' },
  { key: 'threat_accuracy', label: 'Threat Accuracy', color: 'bg-indigo-500' },
  { key: 'dread_accuracy', label: 'DREAD Accuracy', color: 'bg-amber-500' },
  { key: 'mitigation_quality', label: 'Mitigation Quality', color: 'bg-rose-500' },
  { key: 'test_case_relevance', label: 'Test Case Relevance', color: 'bg-violet-500' },
  { key: 'overall_usefulness', label: 'Overall Usefulness', color: 'bg-emerald-500' },
] as const;

const scoreColor = (v: number) =>
  v >= 4.5 ? 'text-emerald-400' : v >= 3.5 ? 'text-blue-400' : v >= 2.5 ? 'text-amber-400' : 'text-red-400';

const scoreBg = (v: number) =>
  v >= 4.5 ? 'bg-emerald-500' : v >= 3.5 ? 'bg-blue-500' : v >= 2.5 ? 'bg-amber-500' : 'bg-red-500';

// ─── Sub-components ───────────────────────────────────────────────────────────

const OUTPUTS = [
  {
    key: 'threat_model',
    short: 'TM',
    label: 'Threat Model',
    check: (r: ReportMetadata) => !!r.threat_model?.result,
    color: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/50',
  },
  {
    key: 'dread_assessment',
    short: 'DREAD',
    label: 'DREAD',
    check: (r: ReportMetadata) => !!r.dread_assessment?.result,
    color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400 border-amber-200 dark:border-amber-800/50',
  },
  {
    key: 'mitigation',
    short: 'Mitig.',
    label: 'Mitigation',
    check: (r: ReportMetadata) => !!r.mitigation?.result,
    color: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400 border-rose-200 dark:border-rose-800/50',
  },
  {
    key: 'attack_tree',
    short: 'Tree',
    label: 'Attack Tree',
    check: (r: ReportMetadata) => !!r.attack_tree?.result,
    color: 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-400 border-sky-200 dark:border-sky-800/50',
  },
  {
    key: 'test_cases',
    short: 'Tests',
    label: 'Test Cases',
    check: (r: ReportMetadata) =>
      Array.isArray(r.test_cases?.result?.test_cases) &&
      (r.test_cases?.result?.test_cases?.length ?? 0) > 0,
    color: 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-400 border-violet-200 dark:border-violet-800/50',
  },
] as const;

const STATUS_STYLES: Record<ReportStatus, string> = {
  completed: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400',
  processing: 'bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400',
  queued: 'bg-violet-50 text-violet-700 dark:bg-violet-900/20 dark:text-violet-400',
  pending: 'bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-400',
  failed: 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-400',
  cancelled: 'bg-slate-100 text-slate-500 dark:bg-gray-800 dark:text-slate-400',
  unknown: 'bg-slate-100 text-slate-500 dark:bg-gray-800 dark:text-slate-400',
};

// ─── Confirm Dialog ───────────────────────────────────────────────────────────

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  confirmClass: string;
  onConfirm: () => void;
  onCancel: () => void;
}

const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open, title, description, confirmLabel, confirmClass, onConfirm, onCancel,
}) => {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={onCancel} />
      <div className="relative bg-white dark:bg-gray-900 rounded-2xl border border-slate-200 dark:border-gray-700/60 shadow-2xl w-full max-w-md p-6 flex flex-col gap-4">
        <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">{title}</h2>
        <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{description}</p>
        <div className="flex items-center justify-end gap-3 pt-1">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-lg text-sm font-medium text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-gray-800 hover:bg-slate-200 dark:hover:bg-gray-700 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className={`px-4 py-2 rounded-lg text-sm font-semibold text-white transition-colors ${confirmClass}`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};

// ─── Multi-select dropdown ─────────────────────────────────────────────────────

interface MultiSelectDropdownProps {
  label: string;
  items: { key: string; label: string }[];
  selected: string[];
  onToggle: (key: string) => void;
}

const MultiSelectDropdown: React.FC<MultiSelectDropdownProps> = ({ label, items, selected, onToggle }) => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(o => !o)}
        className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg border transition-all ${
          selected.length
            ? 'bg-blue-50 border-blue-200 text-blue-700 dark:bg-blue-900/20 dark:border-blue-700 dark:text-blue-300'
            : 'bg-slate-50 border-slate-200 text-slate-600 dark:bg-gray-800/60 dark:border-gray-700 dark:text-slate-400 hover:border-slate-300 dark:hover:border-gray-600'
        }`}
      >
        {label}
        {selected.length > 0 && (
          <span className="bg-[#0052cc] text-white text-xs rounded-full px-1.5 py-0.5 leading-none">{selected.length}</span>
        )}
        <svg className={`w-3 h-3 transition-transform duration-150 ${open ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="absolute top-full left-0 mt-1.5 z-50 bg-white dark:bg-gray-900 border border-slate-200 dark:border-gray-700 rounded-xl shadow-lg min-w-[160px] py-1.5 overflow-hidden">
          {items.length === 0 && <p className="px-3 py-2 text-xs text-slate-400">No options</p>}
          {items.map(item => (
            <button
              key={item.key}
              onClick={() => onToggle(item.key)}
              className="flex items-center gap-2.5 w-full px-3 py-1.5 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-gray-800 transition-colors"
            >
              <span className={`w-4 h-4 rounded flex items-center justify-center flex-shrink-0 border transition-colors ${
                selected.includes(item.key) ? 'bg-[#0052cc] border-[#0052cc]' : 'border-slate-300 dark:border-gray-600'
              }`}>
                {selected.includes(item.key) && (
                  <svg className="w-2.5 h-2.5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                  </svg>
                )}
              </span>
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

// ─── Threat Model Manager Tab ─────────────────────────────────────────────────

const ROUTE_FOR_OUTPUT: Record<string, string> = {
  threat_model: 'view-threat-model',
  dread_assessment: 'view-dread',
  mitigation: 'view-mitigation',
  attack_tree: 'view-attack-tree',
  test_cases: 'view-security-test-cases',
};

type PendingAction = { type: 'retrigger' | 'delete'; id: string; name: string } | null;

const STEP_LABELS: Record<string, string> = {
  rag: 'Processing documents (RAG)…',
  threat_model: 'Generating threat model…',
  parallel_analysis: 'Generating Attack Tree, DREAD, Mitigations & Test Cases…',
  attack_tree: 'Generating attack tree…',
  dread: 'Calculating DREAD scores…',
  mitigation: 'Generating mitigations…',
  test_cases: 'Generating test cases…',
  completed: 'Completed',
};

const STEP_PERCENT: Record<string, number> = {
  rag: 10,
  threat_model: 30,
  parallel_analysis: 65,
  attack_tree: 50,
  dread: 65,
  mitigation: 80,
  test_cases: 95,
  completed: 100,
};

const ThreatModelManager: React.FC = () => {
  const [reports, setReports] = useState<ReportMetadata[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [triggeringId, setTriggeringId] = useState<string | null>(null);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [filterDepartment, setFilterDepartment] = useState<string[]>([]);
  const [filterMethodology, setFilterMethodology] = useState<string[]>([]);
  const [filterOutputs, setFilterOutputs] = useState<string[]>([]);
  const [filterStatus, setFilterStatus] = useState<string[]>([]);
  const [filterDateFrom, setFilterDateFrom] = useState('');
  const [filterDateTo, setFilterDateTo] = useState('');

  // Sort
  const [sortField, setSortField] = useState<'date' | 'name'>('date');
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc');

  useEffect(() => {
    const fetchReports = async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const res = await apiService.getStorageHistory() as { data?: ReportMetadata[] };
        if (!res?.data || !Array.isArray(res.data)) throw new Error('Invalid response');
        setReports(res.data);
      } catch {
        if (!silent) setError('Failed to load threat models.');
      } finally {
        if (!silent) setLoading(false);
      }
    };
    fetchReports();
  }, []);

  // Poll every 5s while any item is queued or processing
  useEffect(() => {
    const hasActive = reports.some(r => {
      const s = ((r as any).details?.status ?? (r as any).status) as string | undefined;
      return s === 'processing' || s === 'queued';
    });
    if (!hasActive) return;
    const poll = async () => {
      try {
        const res = await apiService.getStorageHistory() as { data?: ReportMetadata[] };
        if (res?.data && Array.isArray(res.data)) setReports(res.data);
      } catch { /* silent */ }
    };
    const interval = setInterval(poll, 5000);
    return () => clearInterval(interval);
  }, [reports]);

  const allDepartments = useMemo(() =>
    Array.from(new Set(reports.map(r => r.details?.department).filter(Boolean) as string[])).sort(),
    [reports]
  );

  const filtered = useMemo(() => {
    let list = [...reports];
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(r =>
        (r.details?.projectName ?? r.name).toLowerCase().includes(q) ||
        (r.details?.department ?? '').toLowerCase().includes(q) ||
        r.id.toLowerCase().includes(q)
      );
    }
    if (filterDepartment.length) list = list.filter(r => filterDepartment.includes(r.details?.department ?? ''));
    if (filterMethodology.length) list = list.filter(r => filterMethodology.includes(r.details?.threatModelingMethodology ?? ''));
    if (filterOutputs.length) list = list.filter(r => filterOutputs.every(key => OUTPUTS.find(o => o.key === key)?.check(r)));
    if (filterStatus.length) {
      list = list.filter(r => {
        const s = (((r as any).details?.status) ?? (r as any).status ?? 'unknown') as string;
        return filterStatus.includes(s);
      });
    }
    if (filterDateFrom) list = list.filter(r => new Date(r.timestamp) >= new Date(filterDateFrom));
    if (filterDateTo) {
      const to = new Date(filterDateTo);
      to.setHours(23, 59, 59, 999);
      list = list.filter(r => new Date(r.timestamp) <= to);
    }
    list.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'date') cmp = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      else cmp = (a.details?.projectName ?? a.name).localeCompare(b.details?.projectName ?? b.name);
      return sortDir === 'desc' ? -cmp : cmp;
    });
    return list;
  }, [reports, search, filterDepartment, filterMethodology, filterOutputs, filterStatus, filterDateFrom, filterDateTo, sortField, sortDir]);

  const hasFilters = search || filterDepartment.length || filterMethodology.length || filterOutputs.length || filterStatus.length || filterDateFrom || filterDateTo;

  const clearFilters = () => {
    setSearch(''); setFilterDepartment([]); setFilterMethodology([]); setFilterOutputs([]); setFilterStatus([]); setFilterDateFrom(''); setFilterDateTo('');
  };

  const toggleSort = (field: 'date' | 'name') => {
    if (sortField === field) setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    else { setSortField(field); setSortDir('desc'); }
  };

  const SortIcon = ({ field }: { field: 'date' | 'name' }) => (
    <svg className="w-3 h-3 ml-1 inline-block opacity-60" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      {sortField === field
        ? sortDir === 'desc'
          ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M19 9l-7 7-7-7" />
          : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 15l7-7 7 7" />
        : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l4-4 4 4M16 15l-4 4-4-4" />
      }
    </svg>
  );

  const confirmRetrigger = async () => {
    if (!pendingAction || pendingAction.type !== 'retrigger') return;
    const id = pendingAction.id;
    setPendingAction(null);
    setTriggeringId(id);
    try {
      await apiService.retriggerThreatModel(id);
      setReports(prev => prev.map(r => r.id === id ? { ...r, details: { ...r.details, status: 'queued' } as any } : r));
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Unknown error';
      alert(`Failed to retrigger: ${message}`);
    } finally {
      setTriggeringId(null);
    }
  };

  const handleCancel = async (id: string) => {
    setCancellingId(id);
    try {
      const res = await fetch(`${API_BASE_URL}/cancel-assessment/${id}`, { method: 'POST' });
      if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(data?.error || 'Failed to cancel');
      }
      setReports(prev => prev.map(r => r.id === id ? { ...r, details: { ...r.details, status: 'cancelled' } as any } : r));
    } catch (e: unknown) {
      alert(`Cancel failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    } finally {
      setCancellingId(null);
    }
  };

  const confirmDelete = async () => {
    if (!pendingAction || pendingAction.type !== 'delete') return;
    const id = pendingAction.id;
    setPendingAction(null);
    setDeletingId(id);
    try {
      await apiService.deleteThreatModel(id);
      setReports(prev => prev.filter(r => r.id !== id));
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Unknown error';
      alert(`Failed to delete: ${message}`);
    } finally {
      setDeletingId(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="relative w-8 h-8">
          <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
          <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
        </div>
      </div>
    );
  }

  if (error) return <p className="text-sm text-red-500">{error}</p>;

  return (
    <>
      {/* Confirm dialogs */}
      <ConfirmDialog
        open={pendingAction?.type === 'retrigger'}
        title="Re-trigger threat model?"
        description={`This will clear all existing results for "${pendingAction?.name}" and re-run the full pipeline from scratch. This cannot be undone.`}
        confirmLabel="Yes, retrigger"
        confirmClass="bg-blue-600 hover:bg-blue-700"
        onConfirm={confirmRetrigger}
        onCancel={() => setPendingAction(null)}
      />
      <ConfirmDialog
        open={pendingAction?.type === 'delete'}
        title="Delete threat model?"
        description={`"${pendingAction?.name}" and all its associated data will be permanently deleted. This cannot be undone.`}
        confirmLabel="Yes, delete"
        confirmClass="bg-red-600 hover:bg-red-700"
        onConfirm={confirmDelete}
        onCancel={() => setPendingAction(null)}
      />

      <div className="space-y-4">
        {/* Filter bar */}
        <div className="relative z-20 bg-white dark:bg-gray-900/80 backdrop-blur-sm rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm px-4 py-3">
          <div className="flex flex-wrap items-center gap-2.5">

            {/* Search */}
            <div className="relative flex-1 min-w-[200px]">
              <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search by project name, TEAM or ID..."
                className="w-full pl-8 pr-3 py-1.5 text-sm bg-slate-50 dark:bg-gray-800/60 border border-slate-200 dark:border-gray-700 rounded-lg text-slate-700 dark:text-slate-300 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/25 focus:border-[#0052cc] transition-all"
              />
              {search && (
                <button onClick={() => setSearch('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              )}
            </div>

            {/* TEAM */}
            <MultiSelectDropdown
              label="TEAM"
              items={allDepartments.map(department => ({ key: department, label: department }))}
              selected={filterDepartment}
              onToggle={key => setFilterDepartment(prev => prev.includes(key) ? prev.filter(l => l !== key) : [...prev, key])}
            />

            {/* Methodology */}
            <MultiSelectDropdown
              label="Methodology"
              items={[
                { key: 'STRIDE', label: 'STRIDE' },
                { key: 'PASTA', label: 'PASTA' },
                { key: 'OCTAVE', label: 'OCTAVE' },
              ]}
              selected={filterMethodology}
              onToggle={key => setFilterMethodology(prev => prev.includes(key) ? prev.filter(m => m !== key) : [...prev, key])}
            />

            {/* Completeness */}
            <MultiSelectDropdown
              label="Completeness"
              items={OUTPUTS.map(o => ({ key: o.key, label: o.label }))}
              selected={filterOutputs}
              onToggle={key => setFilterOutputs(prev => prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key])}
            />

            {/* Status */}
            <MultiSelectDropdown
              label="Status"
              items={(['completed', 'processing', 'queued', 'pending', 'failed', 'cancelled'] as const).map(s => ({ key: s, label: s.charAt(0).toUpperCase() + s.slice(1) }))}
              selected={filterStatus}
              onToggle={key => setFilterStatus(prev => prev.includes(key) ? prev.filter(s => s !== key) : [...prev, key])}
            />

            {/* Date range */}
            <div className="flex items-center gap-1.5">
              <input
                type="date"
                value={filterDateFrom}
                onChange={e => setFilterDateFrom(e.target.value)}
                className="px-2 py-1.5 text-xs bg-slate-50 dark:bg-gray-800/60 border border-slate-200 dark:border-gray-700 rounded-lg text-slate-600 dark:text-slate-400 focus:outline-none focus:ring-1 focus:ring-[#0052cc]/30 transition-all"
              />
              <span className="text-slate-400 dark:text-slate-600 text-xs">–</span>
              <input
                type="date"
                value={filterDateTo}
                onChange={e => setFilterDateTo(e.target.value)}
                className="px-2 py-1.5 text-xs bg-slate-50 dark:bg-gray-800/60 border border-slate-200 dark:border-gray-700 rounded-lg text-slate-600 dark:text-slate-400 focus:outline-none focus:ring-1 focus:ring-[#0052cc]/30 transition-all"
              />
            </div>

            {/* Clear */}
            {hasFilters && (
              <button
                onClick={clearFilters}
                className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 hover:text-[#0052cc] dark:hover:text-blue-400 transition-colors"
              >
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
                Clear all
              </button>
            )}

            <span className="ml-auto text-xs text-slate-400">{filtered.length} of {reports.length}</span>
          </div>
        </div>

        {/* Table */}
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-slate-50 dark:bg-gray-800/60 border-b border-slate-200 dark:border-gray-700/60">
                  <th className="px-4 py-3 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    <button onClick={() => toggleSort('name')} className="flex items-center hover:text-slate-700 dark:hover:text-slate-200 transition-colors">
                      Assessment <SortIcon field="name" />
                    </button>
                  </th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap">TEAM</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap">Methodology</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap">Status</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap">Completeness</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    <button onClick={() => toggleSort('date')} className="flex items-center hover:text-slate-700 dark:hover:text-slate-200 transition-colors">
                      Date <SortIcon field="date" />
                    </button>
                  </th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap">Retrigger</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap">Delete</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-gray-800">
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-10 text-center text-slate-400">
                      {hasFilters ? 'No threat models match the current filters.' : 'No threat models found.'}
                    </td>
                  </tr>
                ) : filtered.map(r => {
                  const status = (((r as any).details?.status ?? (r as any).status ?? 'unknown') as ReportStatus);
                  const department = r.details?.department ?? (r as { department?: string }).department ?? '—';
                  const methodology = r.details?.threatModelingMethodology ?? (r as { threat_modeling_methodology?: string }).threat_modeling_methodology ?? '—';
                  const isTriggering = triggeringId === r.id;
                  const isDeleting = deletingId === r.id;
                  const inProgress = ['queued', 'processing'].includes(status);
                  const dateStr = r.timestamp ? new Date(r.timestamp).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';

                  return (
                    <tr key={r.id} className="hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors">
                      {/* Assessment */}
                      <td className="px-4 py-3 max-w-[220px]">
                        <Link
                          to={`/view-threat-model/${r.id}`}
                          className="font-medium text-blue-600 dark:text-blue-400 hover:underline truncate block max-w-[200px]"
                          title={r.name}
                        >
                          {r.name}
                        </Link>
                        <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">{r.id.slice(0, 8)}…</span>
                      </td>

                      {/* TEAM */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        {department !== '—' ? (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-violet-50 text-violet-600 border border-violet-200 dark:bg-violet-900/20 dark:text-violet-400 dark:border-violet-800/40">{department}</span>
                        ) : <span className="text-slate-400">—</span>}
                      </td>

                      {/* Methodology */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        {methodology !== '—' ? (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-sky-50 text-sky-600 border border-sky-200 dark:bg-sky-900/20 dark:text-sky-400 dark:border-sky-800/40">{methodology}</span>
                        ) : <span className="text-slate-400">—</span>}
                      </td>

                      {/* Status */}
                      <td className="px-4 py-3">
                        {(status === 'processing' || status === 'queued') ? (
                          <div className="min-w-[168px] space-y-1.5">
                            <div className="flex items-center gap-1.5">
                              <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${STATUS_STYLES[status]}`}>{status}</span>
                              {status === 'processing' && (
                                <svg className="animate-spin w-3 h-3 text-blue-500" fill="none" viewBox="0 0 24 24">
                                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                </svg>
                              )}
                            </div>
                            {status === 'processing' && (r as any).details?.current_step && (
                              <>
                                <p className="text-[10px] text-slate-500 dark:text-slate-400 leading-tight">
                                  {STEP_LABELS[(r as any).details.current_step] ?? (r as any).details.current_step}
                                </p>
                                <div className="h-1.5 w-full bg-slate-100 dark:bg-gray-800 rounded-full overflow-hidden">
                                  <div
                                    className="h-full bg-blue-500 rounded-full transition-all duration-700"
                                    style={{ width: `${STEP_PERCENT[(r as any).details.current_step] ?? 5}%` }}
                                  />
                                </div>
                              </>
                            )}
                            {status === 'queued' && (
                              <p className="text-[10px] text-slate-400 dark:text-slate-500 italic">Waiting in queue…</p>
                            )}
                          </div>
                        ) : (
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${STATUS_STYLES[status] ?? STATUS_STYLES.unknown}`}>
                            {status}
                          </span>
                        )}
                      </td>

                      {/* Completeness */}
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {OUTPUTS.map(o => {
                            const present = o.check(r);
                            return present ? (
                              <Link
                                key={o.key}
                                to={`/${ROUTE_FOR_OUTPUT[o.key]}/${r.id}`}
                                className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold ${o.color}`}
                                title={o.label}
                              >{o.short}</Link>
                            ) : (
                              <span
                                key={o.key}
                                className="px-1.5 py-0.5 rounded border text-[10px] font-semibold bg-slate-100 text-slate-400 dark:bg-gray-800 dark:text-slate-600 border-slate-200 dark:border-gray-700"
                                title={`${o.label} (missing)`}
                              >{o.short}</span>
                            );
                          })}
                        </div>
                      </td>

                      {/* Date */}
                      <td className="px-4 py-3 whitespace-nowrap text-slate-500 dark:text-slate-400">{dateStr}</td>

                      {/* Retrigger / Cancel */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        {inProgress ? (
                          <button
                            onClick={() => handleCancel(r.id)}
                            disabled={cancellingId === r.id || isDeleting}
                            title="Cancel processing"
                            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium bg-orange-50 text-orange-700 border border-orange-200 hover:bg-orange-100 dark:bg-orange-900/20 dark:text-orange-300 dark:border-orange-800/40 dark:hover:bg-orange-900/40 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                          >
                            {cancellingId === r.id ? (
                              <svg className="animate-spin w-3 h-3" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                              </svg>
                            ) : (
                              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                              </svg>
                            )}
                            {cancellingId === r.id ? 'Cancelling…' : 'Cancel'}
                          </button>
                        ) : (
                          <button
                            onClick={() => setPendingAction({ type: 'retrigger', id: r.id, name: r.name })}
                            disabled={isTriggering || isDeleting}
                            title="Re-run full pipeline"
                            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium bg-blue-50 text-blue-700 border border-blue-200 hover:bg-blue-100 dark:bg-blue-900/20 dark:text-blue-300 dark:border-blue-800/40 dark:hover:bg-blue-900/40 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                          >
                            {isTriggering ? (
                              <svg className="animate-spin w-3 h-3" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                              </svg>
                            ) : (
                              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                              </svg>
                            )}
                            {isTriggering ? 'Queuing…' : 'Retrigger'}
                          </button>
                        )}
                      </td>

                      {/* Delete */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <button
                          onClick={() => setPendingAction({ type: 'delete', id: r.id, name: r.name })}
                          disabled={isDeleting || isTriggering || cancellingId === r.id || inProgress}
                          title={inProgress ? 'Cannot delete while processing' : 'Delete permanently'}
                          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium bg-red-50 text-red-700 border border-red-200 hover:bg-red-100 dark:bg-red-900/20 dark:text-red-300 dark:border-red-800/40 dark:hover:bg-red-900/40 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                        >
                          {isDeleting ? (
                            <svg className="animate-spin w-3 h-3" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                            </svg>
                          ) : (
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          )}
                          {isDeleting ? 'Deleting…' : 'Delete'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
};

const KpiCard: React.FC<{
  label: string;
  value: string | number;
  sub?: string;
  accent: string;
  icon: React.ReactNode;
}> = ({ label, value, sub, accent, icon }) => (
  <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 px-5 py-4 shadow-sm flex items-start gap-4">
    <div className={`w-10 h-10 rounded-xl ${accent} flex items-center justify-center flex-shrink-0 shadow-sm`}>
      {icon}
    </div>
    <div>
      <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-0.5">{label}</p>
      <p className="text-2xl font-bold text-slate-800 dark:text-slate-100 leading-none">{value}</p>
      {sub && <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{sub}</p>}
    </div>
  </div>
);

const HBar: React.FC<{ label?: string; count: number; total: number; color: string }> = ({ label, count, total, color }) => {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <div className="flex items-center gap-3">
      {label !== undefined && (
        <span className="text-xs text-slate-600 dark:text-slate-300 w-32 truncate flex-shrink-0" title={label}>
          {label}
        </span>
      )}
      <div className="flex-1 h-2 bg-slate-100 dark:bg-gray-800 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-semibold text-slate-600 dark:text-slate-300 w-8 text-right">{count}</span>
      <span className="text-xs text-slate-400 dark:text-slate-500 w-10 text-right">{pct}%</span>
    </div>
  );
};

// ─── Feedback Analytics Tab ───────────────────────────────────────────────────

const TIME_OPTS = [
  { value: 'all', label: 'All time' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: '6m', label: 'Last 6 months' },
  { value: '1y', label: 'Last year' },
] as const;

const getTimeCutoff = (period: string): Date | null => {
  const now = new Date();
  if (period === '7d') { const d = new Date(now); d.setDate(d.getDate() - 7); return d; }
  if (period === '30d') { const d = new Date(now); d.setDate(d.getDate() - 30); return d; }
  if (period === '90d') { const d = new Date(now); d.setDate(d.getDate() - 90); return d; }
  if (period === '6m') { const d = new Date(now); d.setMonth(d.getMonth() - 6); return d; }
  if (period === '1y') { const d = new Date(now); d.setFullYear(d.getFullYear() - 1); return d; }
  return null;
};

const FilterChip: React.FC<{ label: string; value: string; onRemove: () => void }> = ({ label, value, onRemove }) => (
  <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-[10px] font-medium bg-blue-50 text-blue-700 border border-blue-200 dark:bg-blue-900/20 dark:text-blue-300 dark:border-blue-800/40">
    <span className="opacity-60">{label}:</span> {value}
    <button onClick={onRemove} className="ml-0.5 text-blue-400 hover:text-blue-600 dark:hover:text-blue-200 leading-none">×</button>
  </span>
);

const FeedbackAnalytics: React.FC<{ feedbacks: FeedbackEntry[] }> = ({ feedbacks }) => {
  const [filterDepartment, setFilterDepartment] = useState('all');
  const [filterMeth, setFilterMeth] = useState('all');
  const [filterUser, setFilterUser] = useState('all');
  const [filterTime, setFilterTime] = useState('all');
  const [filterRecommend, setFilterRecommend] = useState('all');

  const uniqueDepartments = Array.from(new Set(feedbacks.map(f => f.department).filter(Boolean))) as string[];
  const uniqueMeths = Array.from(new Set(feedbacks.map(f => f.threat_modeling_methodology).filter(Boolean))) as string[];
  const uniqueUsers = Array.from(new Set(feedbacks.map(f => f.created_for).filter(Boolean))) as string[];

  const activeFilters = [filterDepartment, filterMeth, filterUser, filterTime, filterRecommend].filter(v => v !== 'all').length;
  const clearFilters = () => {
    setFilterDepartment('all');
    setFilterMeth('all');
    setFilterUser('all');
    setFilterTime('all');
    setFilterRecommend('all');
  };

  const filtered = feedbacks.filter(f => {
    if (filterDepartment !== 'all' && (f.department ?? '') !== filterDepartment) return false;
    if (filterMeth !== 'all' && (f.threat_modeling_methodology ?? '') !== filterMeth) return false;
    if (filterUser !== 'all' && f.created_for !== filterUser) return false;
    if (filterTime !== 'all') {
      const cutoff = getTimeCutoff(filterTime);
      if (cutoff && new Date(f.created_at) < cutoff) return false;
    }
    if (filterRecommend !== 'all') {
      if (!f.submitted) return false;
      if (f.answers.would_recommend !== (filterRecommend === 'yes' ? 1 : 0)) return false;
    }
    return true;
  });

  const submitted = filtered.filter(f => f.submitted);
  const responseRate = filtered.length > 0 ? Math.round((submitted.length / filtered.length) * 100) : 0;

  const overallAvg = avg(submitted.map(f => f.answers.overall_usefulness ?? 0).filter(v => v > 0));

  const dimAvgs = SCORE_DIMS.map(d => {
    const vals = submitted.map(f => (f.answers[d.key] as number) ?? 0).filter(v => v > 0);
    return { ...d, avg: avg(vals) };
  });

  const wouldRecommend = submitted.filter(f => f.answers.would_recommend === 1).length;
  const wouldNotRecommend = submitted.filter(f => f.answers.would_recommend === 0).length;
  const recommendPct = submitted.length > 0 ? Math.round((wouldRecommend / submitted.length) * 100) : 0;

  const fpAvg = avg(submitted.map(f => f.answers.false_positive_count ?? -1).filter(v => v >= 0));
  const mtAvg = avg(submitted.map(f => f.answers.missing_threats_count ?? -1).filter(v => v >= 0));

  const departmentMap: Record<string, { total: number; submitted: number; scores: number[] }> = {};
  filtered.forEach(f => {
    const department = f.department || 'Unknown';
    if (!departmentMap[department]) departmentMap[department] = { total: 0, submitted: 0, scores: [] };
    departmentMap[department].total++;
    if (f.submitted) {
      departmentMap[department].submitted++;
      const ov = f.answers.overall_usefulness ?? 0;
      if (ov > 0) departmentMap[department].scores.push(ov);
    }
  });
  const departmentEntries = Object.entries(departmentMap).sort((a, b) => b[1].total - a[1].total);

  const methMap: Record<string, { total: number; submitted: number }> = {};
  filtered.forEach(f => {
    const m = f.threat_modeling_methodology || 'Unknown';
    if (!methMap[m]) methMap[m] = { total: 0, submitted: 0 };
    methMap[m].total++;
    if (f.submitted) methMap[m].submitted++;
  });
  const methEntries = Object.entries(methMap).sort((a, b) => b[1].total - a[1].total);

  const monthMap: Record<string, number> = {};
  submitted.forEach(f => {
    const d = new Date(f.submitted_at || f.created_at);
    const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    monthMap[key] = (monthMap[key] || 0) + 1;
  });
  const months = Object.entries(monthMap).sort((a, b) => a[0].localeCompare(b[0])).slice(-12);
  const maxMonth = Math.max(...months.map(m => m[1]), 1);

  const scoreDist = [1, 2, 3, 4, 5].map(s => ({
    score: s,
    count: submitted.filter(f => f.answers.overall_usefulness === s).length,
  }));
  const maxDist = Math.max(...scoreDist.map(d => d.count), 1);

  const suggestions = submitted
    .filter(f => f.answers.improvement_suggestions?.trim())
    .map(f => ({ text: f.answers.improvement_suggestions!, name: f.assessment_name, id: f.assessment_id, date: f.submitted_at || f.created_at }));

  const scored = submitted
    .filter(f => f.answers.overall_usefulness && f.answers.overall_usefulness > 0)
    .sort((a, b) => (b.answers.overall_usefulness ?? 0) - (a.answers.overall_usefulness ?? 0));
  const top3 = scored.slice(0, 3);
  const bottom3 = scored.slice(-3).reverse();

  const selCls =
    'px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80 text-slate-600 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/40 transition-all';

  return (
    <div className="space-y-8">

      {/* ── Filter bar ── */}
      <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm px-4 py-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest flex-shrink-0">Filters</span>

          <select value={filterDepartment} onChange={e => setFilterDepartment(e.target.value)} className={selCls}>
            <option value="all">All Teams</option>
            {uniqueDepartments.map(v => <option key={v} value={v}>{v}</option>)}
          </select>

          <select value={filterMeth} onChange={e => setFilterMeth(e.target.value)} className={selCls}>
            <option value="all">All Methodologies</option>
            {uniqueMeths.map(v => <option key={v} value={v}>{v}</option>)}
          </select>

          <select value={filterUser} onChange={e => setFilterUser(e.target.value)} className={selCls}>
            <option value="all">All Users</option>
            {uniqueUsers.map(v => <option key={v} value={v}>{v}</option>)}
          </select>

          <select value={filterTime} onChange={e => setFilterTime(e.target.value)} className={selCls}>
            {TIME_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>

          <select value={filterRecommend} onChange={e => setFilterRecommend(e.target.value)} className={selCls}>
            <option value="all">All Responses</option>
            <option value="yes">Would Recommend</option>
            <option value="no">Would Not Recommend</option>
          </select>

          <div className="ml-auto flex items-center gap-3 flex-shrink-0">
            <span className="text-xs text-slate-400 dark:text-slate-500">
              {filtered.length} / {feedbacks.length} entries
            </span>
            {activeFilters > 0 && (
              <button
                onClick={clearFilters}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-red-500 border border-red-200 dark:border-red-800/40 bg-red-50 dark:bg-red-900/10 hover:bg-red-100 dark:hover:bg-red-900/20 transition-all"
              >
                Clear {activeFilters} ×
              </button>
            )}
          </div>
        </div>

        {activeFilters > 0 && (
          <div className="flex flex-wrap gap-2 mt-2.5 pt-2.5 border-t border-slate-100 dark:border-gray-800">
            {filterDepartment !== 'all' && <FilterChip label="Team" value={filterDepartment} onRemove={() => setFilterDepartment('all')} />}
            {filterMeth !== 'all' && <FilterChip label="Methodology" value={filterMeth} onRemove={() => setFilterMeth('all')} />}
            {filterUser !== 'all' && <FilterChip label="User" value={filterUser} onRemove={() => setFilterUser('all')} />}
            {filterTime !== 'all' && (
              <FilterChip
                label="Time"
                value={TIME_OPTS.find(o => o.value === filterTime)?.label ?? filterTime}
                onRemove={() => setFilterTime('all')}
              />
            )}
            {filterRecommend !== 'all' && (
              <FilterChip
                label="Recommend"
                value={filterRecommend === 'yes' ? 'Yes' : 'No'}
                onRemove={() => setFilterRecommend('all')}
              />
            )}
          </div>
        )}
      </div>

      {/* ── KPI Row ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <KpiCard
          label="Total Feedback"
          value={filtered.length}
          accent="bg-blue-600/20"
          icon={<svg className="w-5 h-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" /></svg>}
        />
        <KpiCard
          label="Submitted"
          value={submitted.length}
          sub={`${filtered.length - submitted.length} pending`}
          accent="bg-emerald-600/20"
          icon={<svg className="w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
        />
        <KpiCard
          label="Response Rate"
          value={`${responseRate}%`}
          accent="bg-violet-600/20"
          icon={<svg className="w-5 h-5 text-violet-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>}
        />
        <KpiCard
          label="Avg Overall Score"
          value={overallAvg !== null ? `${overallAvg}/5` : '—'}
          accent="bg-amber-600/20"
          icon={<svg className="w-5 h-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" /></svg>}
        />
      </div>

      {/* ── Score Dimensions + Would Recommend ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Score averages */}
        <div className="lg:col-span-2 bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-4">Average Scores by Dimension</h3>
          {submitted.length === 0 ? (
            <p className="text-xs text-slate-400">No submitted feedback yet.</p>
          ) : (
            <div className="space-y-4">
              {dimAvgs.map(d => (
                <div key={d.key}>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-medium text-slate-600 dark:text-slate-300">{d.label}</span>
                    <span className={`text-sm font-bold ${d.avg !== null ? scoreColor(d.avg) : 'text-slate-400'}`}>
                      {d.avg !== null ? `${d.avg}/5` : '—'}
                    </span>
                  </div>
                  <div className="h-2 bg-slate-100 dark:bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${d.avg !== null ? scoreBg(d.avg) : 'bg-slate-300'} rounded-full transition-all duration-700`}
                      style={{ width: d.avg !== null ? `${(d.avg / 5) * 100}%` : '0%' }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Would recommend + FP/MT */}
        <div className="space-y-4">
          <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3">Would Recommend</h3>
            {submitted.length === 0 ? (
              <p className="text-xs text-slate-400">No data yet.</p>
            ) : (
              <div className="flex flex-col items-center gap-3">
                <div className="relative w-24 h-24">
                  <svg viewBox="0 0 36 36" className="w-24 h-24 -rotate-90">
                    <circle cx="18" cy="18" r="15.9155" fill="none" stroke="currentColor" strokeWidth="2.5" className="text-slate-100 dark:text-gray-800" />
                    <circle
                      cx="18" cy="18" r="15.9155" fill="none"
                      stroke="currentColor" strokeWidth="2.5"
                      strokeDasharray={`${recommendPct} ${100 - recommendPct}`}
                      strokeDashoffset="0"
                      className={recommendPct >= 70 ? 'text-emerald-500' : recommendPct >= 40 ? 'text-amber-500' : 'text-red-500'}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className={`text-xl font-bold ${recommendPct >= 70 ? 'text-emerald-500' : recommendPct >= 40 ? 'text-amber-500' : 'text-red-500'}`}>{recommendPct}%</span>
                    <span className="text-[9px] text-slate-400 dark:text-slate-500">recommend</span>
                  </div>
                </div>
                <div className="flex gap-3 text-xs">
                  <span className="flex items-center gap-1 text-emerald-600 dark:text-emerald-400 font-medium">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" />
                    Yes: {wouldRecommend}
                  </span>
                  <span className="flex items-center gap-1 text-red-500 dark:text-red-400 font-medium">
                    <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
                    No: {wouldNotRecommend}
                  </span>
                </div>
              </div>
            )}
          </div>

          <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3">Noise Metrics</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between bg-slate-50 dark:bg-gray-800/60 rounded-lg px-3 py-2.5 border border-slate-200 dark:border-gray-700/40">
                <span className="text-xs text-slate-500 dark:text-slate-400">Avg False Positives</span>
                <span className="text-sm font-bold text-orange-500">{fpAvg !== null ? fpAvg : '—'}</span>
              </div>
              <div className="flex items-center justify-between bg-slate-50 dark:bg-gray-800/60 rounded-lg px-3 py-2.5 border border-slate-200 dark:border-gray-700/40">
                <span className="text-xs text-slate-500 dark:text-slate-400">Avg Missing Threats</span>
                <span className="text-sm font-bold text-amber-500">{mtAvg !== null ? mtAvg : '—'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Overall Score Distribution + Monthly Trend ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-4">Overall Score Distribution</h3>
          {submitted.length === 0 ? <p className="text-xs text-slate-400">No data yet.</p> : (
            <div className="flex items-end gap-3 h-28">
              {scoreDist.map(d => {
                const heightPct = maxDist > 0 ? (d.count / maxDist) * 100 : 0;
                const cols = ['', 'bg-red-500', 'bg-orange-500', 'bg-amber-400', 'bg-blue-500', 'bg-emerald-500'];
                return (
                  <div key={d.score} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">{d.count}</span>
                    <div className="w-full flex flex-col justify-end" style={{ height: 80 }}>
                      <div
                        className={`w-full ${cols[d.score]} rounded-t-md transition-all duration-700 opacity-85`}
                        style={{ height: `${heightPct}%`, minHeight: d.count > 0 ? 4 : 0 }}
                      />
                    </div>
                    <span className="text-xs text-slate-400">{d.score}/5</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-4">Monthly Submissions</h3>
          {months.length === 0 ? <p className="text-xs text-slate-400">No data yet.</p> : (
            <div className="flex items-end gap-1.5 h-28">
              {months.map(([month, count]) => {
                const heightPct = (count / maxMonth) * 100;
                const label = new Date(month + '-01').toLocaleDateString('en-IN', { month: 'short', year: '2-digit' });
                return (
                  <div key={month} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-[10px] font-semibold text-slate-500 dark:text-slate-400">{count}</span>
                    <div className="w-full flex flex-col justify-end" style={{ height: 72 }}>
                      <div
                        className="w-full bg-blue-500 rounded-t-md transition-all duration-700 opacity-80"
                        style={{ height: `${heightPct}%`, minHeight: count > 0 ? 4 : 0 }}
                      />
                    </div>
                    <span className="text-[9px] text-slate-400 leading-none">{label}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* ── By Team + By Methodology ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-4">By Team</h3>
          {departmentEntries.length === 0 ? <p className="text-xs text-slate-400">No data.</p> : (
            <div className="space-y-2">
              {departmentEntries.map(([department, data]) => (
                <div key={department}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-slate-600 dark:text-slate-300 truncate max-w-[180px]">{department}</span>
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <span>{data.submitted}/{data.total}</span>
                      {data.scores.length > 0 && (
                        <span className={`font-bold ${scoreColor(avg(data.scores)!)}`}>
                          {avg(data.scores)}/5
                        </span>
                      )}
                    </div>
                  </div>
                  <HBar label="" count={data.submitted} total={data.total} color="bg-blue-500" />
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-4">By Methodology</h3>
          {methEntries.length === 0 ? <p className="text-xs text-slate-400">No data.</p> : (
            <div className="space-y-4">
              {methEntries.map(([meth, data]) => (
                <div key={meth}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-slate-600 dark:text-slate-300">{meth}</span>
                    <span className="text-xs text-slate-400">{data.submitted}/{data.total} submitted</span>
                  </div>
                  <HBar label="" count={data.submitted} total={data.total} color="bg-violet-500" />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Top & Bottom Performers ── */}
      {scored.length >= 3 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
            <h3 className="text-sm font-semibold text-emerald-600 dark:text-emerald-400 mb-4 flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" /></svg>
              Top Performing Assessments
            </h3>
            <div className="space-y-3">
              {top3.map((f, i) => (
                <div key={f.uuid} className="flex items-center gap-3 bg-slate-50 dark:bg-gray-800/60 rounded-lg px-3 py-2.5 border border-slate-200 dark:border-gray-700/40">
                  <span className="text-xs font-bold text-emerald-500 w-5">#{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-semibold text-slate-700 dark:text-slate-200 truncate">{f.assessment_name}</p>
                    <p className="text-[10px] text-slate-400 dark:text-slate-500">{f.department} · {f.threat_modeling_methodology}</p>
                  </div>
                  <span className="text-sm font-bold text-emerald-500">{f.answers.overall_usefulness}/5</span>
                  <Link to={`/view-threat-model/${f.assessment_id}`} className="text-[10px] text-blue-400 hover:underline">View</Link>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
            <h3 className="text-sm font-semibold text-rose-500 dark:text-rose-400 mb-4 flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" /></svg>
              Needs Improvement
            </h3>
            <div className="space-y-3">
              {bottom3.map((f, i) => (
                <div key={f.uuid} className="flex items-center gap-3 bg-slate-50 dark:bg-gray-800/60 rounded-lg px-3 py-2.5 border border-slate-200 dark:border-gray-700/40">
                  <span className="text-xs font-bold text-rose-400 w-5">#{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-semibold text-slate-700 dark:text-slate-200 truncate">{f.assessment_name}</p>
                    <p className="text-[10px] text-slate-400 dark:text-slate-500">{f.department} · {f.threat_modeling_methodology}</p>
                  </div>
                  <span className={`text-sm font-bold ${scoreColor(f.answers.overall_usefulness ?? 0)}`}>{f.answers.overall_usefulness}/5</span>
                  <Link to={`/view-threat-model/${f.assessment_id}`} className="text-[10px] text-blue-400 hover:underline">View</Link>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Improvement Suggestions ── */}
      {suggestions.length > 0 && (
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-4 flex items-center gap-2">
            <svg className="w-4 h-4 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" /></svg>
            Improvement Suggestions ({suggestions.length})
          </h3>
          <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
            {suggestions.map((s, i) => (
              <div key={i} className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-3.5 border border-slate-200 dark:border-gray-700/40">
                <p className="text-sm text-slate-700 dark:text-slate-200 whitespace-pre-wrap leading-relaxed">{s.text}</p>
                <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-2 flex items-center gap-1.5 flex-wrap">
                  <Link to={`/view-threat-model/${s.id}`} className="text-blue-500 hover:underline font-medium">{s.name}</Link>
                  <span>·</span>
                  <span>{formatDate(s.date)}</span>
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Full Feedback Table ── */}
      <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 dark:border-gray-700/60">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">All Feedback Entries ({filtered.length})</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-slate-50 dark:bg-gray-800/60">
                {['Assessment', 'User', 'Team', 'Methodology', 'Status', 'Overall', 'Coverage', 'Accuracy', 'DREAD', 'Mitigation', 'Test Cases', 'FP', 'MT', 'Recommend', 'Date'].map(h => (
                  <th key={h} className="px-3 py-2.5 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-gray-800">
              {filtered.map(f => {
                const a = f.answers;
                return (
                  <tr key={f.uuid} className="hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors">
                    <td className="px-3 py-2.5 max-w-[200px]">
                      <Link to={`/view-threat-model/${f.assessment_id}`} className="text-blue-500 hover:underline font-medium truncate block max-w-[180px]">{f.assessment_name}</Link>
                    </td>
                    <td className="px-3 py-2.5 text-slate-500 dark:text-slate-400 whitespace-nowrap">{f.created_for}</td>
                    <td className="px-3 py-2.5">
                      {f.department && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-violet-50 text-violet-600 border border-violet-200 dark:bg-violet-900/20 dark:text-violet-400 dark:border-violet-800/40">
                          {f.department}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      {f.threat_modeling_methodology && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-sky-50 text-sky-600 border border-sky-200 dark:bg-sky-900/20 dark:text-sky-400 dark:border-sky-800/40">
                          {f.threat_modeling_methodology}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${f.submitted ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400' : 'bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-400'}`}>
                        {f.submitted ? 'Submitted' : 'Pending'}
                      </span>
                    </td>
                    {[a.overall_usefulness, a.threat_coverage, a.threat_accuracy, a.dread_accuracy, a.mitigation_quality, a.test_case_relevance].map((v, idx) => (
                      <td key={idx} className={`px-3 py-2.5 font-bold ${v ? scoreColor(v) : 'text-slate-400'}`}>{v ?? '—'}</td>
                    ))}
                    <td className="px-3 py-2.5 text-orange-500 font-medium">{a.false_positive_count ?? '—'}</td>
                    <td className="px-3 py-2.5 text-amber-500 font-medium">{a.missing_threats_count ?? '—'}</td>
                    <td className="px-3 py-2.5">
                      {a.would_recommend === 1 ? <span className="text-emerald-500 font-bold">✓</span> : a.would_recommend === 0 ? <span className="text-red-500 font-bold">✗</span> : <span className="text-slate-400">—</span>}
                    </td>
                    <td className="px-3 py-2.5 text-slate-400 whitespace-nowrap">{formatDate(f.created_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};


// ─── StatusBanner (shared) ───────────────────────────────────────────────────

const StatusBanner: React.FC<{ msg: string | null }> = ({ msg }) =>
  msg ? (
    <div className={`mb-4 px-4 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 ${
      msg.startsWith('Error')
        ? 'bg-red-50 text-red-700 border border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800'
        : 'bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800'
    }`}>{msg}</div>
  ) : null;

// ─── UserManagement ───────────────────────────────────────────────────────────

const UserManagement: React.FC = () => {
  const [admins, setAdmins] = useState<string[]>([]);
  const [newEmail, setNewEmail] = useState('');
  const [loading, setLoading] = useState(true);
  const [adminSaving, setAdminSaving] = useState(false);
  const [adminStatus, setAdminStatus] = useState<string | null>(null);

  const flashStatus = (setter: (v: string | null) => void, msg: string) => {
    setter(msg);
    setTimeout(() => setter(null), 3000);
  };

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const adminsRes = await apiService.getAdminList();
        if (adminsRes?.admins) setAdmins(adminsRes.admins);
      } catch (e) {
        console.error('Error loading admin list:', e);
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  const saveAdminsHandler = async () => {
    if (admins.length === 0) {
      flashStatus(setAdminStatus, 'At least one admin must remain.');
      return;
    }
    setAdminSaving(true);
    try {
      const res = await apiService.saveAdminList(admins);
      setAdmins(res.admins);
      flashStatus(setAdminStatus, 'Admin list saved.');
    } catch (e) {
      flashStatus(setAdminStatus, 'Error saving admin list.');
    } finally {
      setAdminSaving(false);
    }
  };

  const addAdmin = () => {
    const email = newEmail.trim().toLowerCase();
    if (!email || admins.includes(email)) return;
    setAdmins(prev => [...prev, email]);
    setNewEmail('');
  };

  const removeAdmin = (email: string) => {
    if (admins.length <= 1) return;
    setAdmins(prev => prev.filter(e => e !== email));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="relative w-10 h-10">
          <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
          <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Admin Management</h2>
        </div>
        <div className="px-6 py-5 space-y-4">
          <StatusBanner msg={adminStatus} />
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Admins can access this dashboard, configure settings, and manage threat models. Changes take effect immediately — no server restart required.
          </p>

          {/* Add new admin */}
          <div className="flex gap-2">
            <input
              type="email"
              value={newEmail}
              onChange={e => setNewEmail(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addAdmin()}
              placeholder="email@example.com"
              className="flex-1 px-3 py-2 text-sm border border-slate-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc]"
            />
            <button
              onClick={addAdmin}
              className="px-4 py-2 bg-slate-800 dark:bg-slate-700 text-white text-sm font-semibold rounded-lg hover:bg-slate-700 dark:hover:bg-slate-600 transition-all shadow-sm flex items-center gap-1.5"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Add
            </button>
          </div>

          {/* Admin list */}
          <div className="space-y-2">
            {admins.length === 0 && (
              <p className="text-sm text-slate-400 dark:text-slate-500 italic">No admins configured. Add at least one.</p>
            )}
            {admins.map(email => (
              <div key={email} className="flex items-center justify-between px-3 py-2 rounded-lg bg-slate-50 dark:bg-gray-800/60 border border-slate-200 dark:border-gray-700/60">
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{email}</span>
                <button
                  onClick={() => removeAdmin(email)}
                  disabled={admins.length <= 1}
                  className="p-1 rounded transition-all disabled:opacity-30 disabled:cursor-not-allowed text-slate-400 hover:text-red-500 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20"
                  title={admins.length <= 1 ? 'At least one admin must remain' : 'Remove admin'}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            ))}
          </div>

          <div className="flex justify-end">
            <button
              onClick={() => void saveAdminsHandler()}
              disabled={adminSaving}
              className="px-4 py-2 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm"
            >
              {adminSaving ? 'Saving…' : 'Save Admin List'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── AdminSettings ────────────────────────────────────────────────────────────

interface ThreatFilterConfig {
  enabled: boolean;
  criticPassEnabled: boolean;
  infrastructureControls: {
    apiGateway: { vendor: string; trustedHeaders: string[]; description: string };
    waf: { vendor: string; capabilities: string[]; description: string };
    serviceMesh: { protocol: string; description: string };
  };
  falsePositiveKeywords: string[];
  sensitiveAssets: string[];
  qualityConfig: {
    requireSpecificEntryPoint: boolean;
    requireAssetSpecificity: boolean;
    minScenarioLength: number;
  };
}

interface LLMConfig {
  method: 'OPENAI' | 'BEDROCK';
  model: string;
  large_output_model?: string;
  base_url?: string;
  api_key_configured?: boolean;
  tested?: boolean;
}

interface PreContextSettings {
  preContext: string;
  darkMode?: boolean;
}

const AdminSettings: React.FC = () => {
  const [llmConfig, setLlmConfig] = useState<LLMConfig>({ method: 'BEDROCK', model: '' });
  const [isTested, setIsTested] = useState(false);
  // Cleared on any field change, set true only after a successful save.
  const [configuredAndSaved, setConfiguredAndSaved] = useState(false);
  const [preCtx, setPreCtx] = useState<PreContextSettings>({ preContext: '' });
  const [loading, setLoading] = useState(true);
  const [llmSaving, setLlmSaving] = useState(false);
  const [llmTesting, setLlmTesting] = useState(false);
  const [llmTestResult, setLlmTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [ctxSaving, setCtxSaving] = useState(false);
  const [llmStatus, setLlmStatus] = useState<string | null>(null);
  const [ctxStatus, setCtxStatus] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const [llmRes, settingsRes] = await Promise.all([
          apiService.getAdminLlmConfig(),
          apiService.getSettings(),
        ]);
        if (llmRes?.llmConfig) {
          setLlmConfig(llmRes.llmConfig);
          setIsTested(llmRes.llmConfig.tested === true);
          setConfiguredAndSaved(llmRes.llmConfig.tested === true);
        }
        if (settingsRes?.data) setPreCtx(settingsRes.data as PreContextSettings);
      } catch (e) {
        console.error('Error loading admin settings:', e);
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  const flashStatus = (setter: (v: string | null) => void, msg: string) => {
    setter(msg);
    setTimeout(() => setter(null), 3000);
  };

  const saveLlm = async () => {
    if (!isTested) return;
    setLlmSaving(true);
    try {
      await apiService.saveAdminLlmConfig({ ...llmConfig, tested: true });
      setConfiguredAndSaved(true);
      flashStatus(setLlmStatus, 'Model config saved.');
    } catch (e) {
      flashStatus(setLlmStatus, 'Error saving model config.');
    } finally {
      setLlmSaving(false);
    }
  };

  const updateLlmField = (patch: Partial<LLMConfig>) => {
    setLlmConfig(prev => ({ ...prev, ...patch }));
    setIsTested(false);
    setConfiguredAndSaved(false);
    setLlmTestResult(null);
  };

  const testLlm = async () => {
    setLlmTesting(true);
    setLlmTestResult(null);
    try {
      const res = await apiService.testAdminLlm(llmConfig);
      setLlmTestResult({
        success: res.success,
        message: res.success
          ? `✓ Connected — model responded: "${res.response}" (${res.model})`
          : `✗ ${res.error}`,
      });
      if (res.success) setIsTested(true);
    } catch (e) {
      setLlmTestResult({ success: false, message: 'Request failed. Check backend logs.' });
    } finally {
      setLlmTesting(false);
    }
  };

  const saveCtx = async () => {
    setCtxSaving(true);
    try {
      await apiService.saveSettings(preCtx);
      flashStatus(setCtxStatus, 'Pre-context saved.');
    } catch (e) {
      flashStatus(setCtxStatus, 'Error saving pre-context.');
    } finally {
      setCtxSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="relative w-10 h-10">
          <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
          <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">

      {/* ── Model Configuration ── */}
      <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Model Configuration</h2>
          <span className="text-xs text-slate-400 dark:text-slate-500">API keys stay in <code className="bg-slate-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">.env</code></span>
        </div>
        {!configuredAndSaved && (
          <div className="flex items-center gap-2 px-4 py-2 bg-amber-50 dark:bg-amber-900/20 border-b border-amber-200 dark:border-amber-800/40 text-amber-700 dark:text-amber-400 text-xs font-medium">
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Model configuration not verified — run Test Connection before saving.
          </div>
        )}
        <div className="px-6 py-5 space-y-4">
          <StatusBanner msg={llmStatus} />

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* LLM Method */}
            <div>
              <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">LLM Method</label>
              <select
                value={llmConfig.method}
                onChange={e => updateLlmField({ method: e.target.value as 'OPENAI' | 'BEDROCK' })}
                className="w-full px-3 py-2 text-sm border border-slate-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc]"
              >
                <option value="BEDROCK">AWS Bedrock</option>
                <option value="OPENAI">OpenAI</option>
              </select>
            </div>

            {/* Model name */}
            <div>
              <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">Model</label>
              <input
                type="text"
                value={llmConfig.model}
                onChange={e => updateLlmField({ model: e.target.value })}
                placeholder="e.g. claude-3.7-sonnet"
                className="w-full px-3 py-2 text-sm border border-slate-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc] font-mono"
              />
            </div>

            {/* Large output model */}
            <div>
              <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">
                Large Output Model
                <span className="ml-1 text-slate-400 normal-case font-normal">(attack tree / long outputs)</span>
              </label>
              <input
                type="text"
                value={llmConfig.large_output_model ?? ''}
                onChange={e => updateLlmField({ large_output_model: e.target.value })}
                placeholder="Leave blank to use Model above"
                className="w-full px-3 py-2 text-sm border border-slate-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc] font-mono"
              />
            </div>

            {/* Endpoint (Bedrock only) */}
            {llmConfig.method === 'BEDROCK' && (
              <div>
                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">Endpoint URL</label>
                <input
                  type="text"
                  value={llmConfig.base_url ?? ''}
                  onChange={e => updateLlmField({ base_url: e.target.value })}
                  placeholder="http://localhost:42069"
                  className="w-full px-3 py-2 text-sm border border-slate-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc] font-mono"
                />
              </div>
            )}
          </div>

          <div className="flex flex-col gap-3">
            {llmTestResult && (
              <div className={`px-3 py-2 rounded-lg text-sm font-medium ${
                llmTestResult.success
                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800'
                  : 'bg-red-50 text-red-700 border border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800'
              }`}>{llmTestResult.message}</div>
            )}
            <div className="flex justify-end gap-2">
              <button
                onClick={testLlm}
                disabled={llmTesting || llmSaving}
                className="px-4 py-2 bg-slate-700 dark:bg-slate-600 text-white text-sm font-semibold rounded-lg hover:bg-slate-600 dark:hover:bg-slate-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm flex items-center gap-2"
              >
                {llmTesting ? (
                  <>
                    <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Testing…
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                    Test Connection
                  </>
                )}
              </button>
              <button
                onClick={saveLlm}
                disabled={llmSaving || llmTesting || !isTested}
                title={!isTested ? 'Run Test Connection first' : undefined}
                className="px-4 py-2 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm"
              >
                {llmSaving ? 'Saving…' : 'Save Model Config'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── Pre-Context Configuration ── */}
      <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Pre-Context Configuration</h2>
        </div>
        <div className="px-6 py-6 space-y-4">
          <StatusBanner msg={ctxStatus} />
          <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
            Document existing security mechanisms. This prevents false positives during threat modeling by acknowledging implemented controls.
          </p>
          <div>
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Security Controls and Mechanisms</label>
            <textarea
              rows={10}
              value={preCtx.preContext}
              onChange={e => setPreCtx(prev => ({ ...prev, preContext: e.target.value }))}
              placeholder="Describe existing security controls, authentication mechanisms, encryption standards, etc."
              className="w-full px-3 py-2.5 text-sm border rounded-lg text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc] transition-all resize-none bg-white dark:bg-gray-800 border-slate-200 dark:border-gray-700"
            />
          </div>
          <div className="flex justify-end">
            <button
              onClick={saveCtx}
              disabled={ctxSaving}
              className="px-4 py-2 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm"
            >
              {ctxSaving ? 'Saving…' : 'Save Pre-Context'}
            </button>
          </div>
        </div>
      </div>

    </div>
  );
};

// ─── Logs Tab ────────────────────────────────────────────────────────────────

interface LogEntry {
  ts: string;
  level: 'INFO' | 'WARNING' | 'ERROR';
  step: string;
  message: string;
}

interface AssessmentLogSummary {
  assessment_id: string;
  name: string;
  status: string;
  current_step: string;
  timestamp: string;
  department: string;
  has_logs: boolean;
  log_count: number;
  has_errors: boolean;
  error_message: string;
}

interface AssessmentLogDetail {
  assessment_id: string;
  name: string;
  status: string;
  current_step: string;
  error_message: string;
  logs: LogEntry[];
}

const STEP_DISPLAY: Record<string, string> = {
  pipeline: 'Pipeline',
  rag: 'RAG',
  threat_model: 'Threat Model',
  parallel_analysis: 'Parallel Analysis',
  attack_tree: 'Attack Tree',
  dread: 'DREAD',
  mitigation: 'Mitigation',
  test_cases: 'Test Cases',
};

const LOG_STATUS_COLORS: Record<string, string> = {
  completed: 'text-emerald-400 bg-emerald-900/20 border-emerald-800/40',
  processing: 'text-blue-400 bg-blue-900/20 border-blue-800/40',
  queued: 'text-amber-400 bg-amber-900/20 border-amber-800/40',
  pending: 'text-slate-400 bg-slate-800/40 border-slate-700/40',
  failed: 'text-red-400 bg-red-900/20 border-red-800/40',
  cancelled: 'text-slate-400 bg-slate-800/40 border-slate-700/40',
};

const LogsTab: React.FC = () => {
  const [assessments, setAssessments] = useState<AssessmentLogSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [logDetail, setLogDetail] = useState<AssessmentLogDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [logsLoading, setLogsLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [autoScroll, setAutoScroll] = useState(true);
  const logEndRef = useRef<HTMLDivElement>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const getToken = () => localStorage.getItem('ts_auth_token');

  const fetchAssessments = useCallback(async () => {
    try {
      const token = getToken();
      const res = await fetch(`${API_BASE_URL}/admin/logs`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) return;
      const data = await res.json();
      setAssessments(data.assessments ?? []);
    } catch {
      // ignore
    }
  }, []);

  const fetchLogs = useCallback(async (id: string) => {
    setLogsLoading(true);
    try {
      const token = getToken();
      const res = await fetch(`${API_BASE_URL}/admin/logs/${id}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) return;
      const data: AssessmentLogDetail = await res.json();
      setLogDetail(data);
    } catch {
      // ignore
    } finally {
      setLogsLoading(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    setLoading(true);
    fetchAssessments().finally(() => setLoading(false));
  }, [fetchAssessments]);

  // Polling: refresh assessment list every 10s and logs every 3s when selected is processing
  useEffect(() => {
    const listInterval = setInterval(fetchAssessments, 10_000);
    return () => clearInterval(listInterval);
  }, [fetchAssessments]);

  useEffect(() => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    if (!selectedId) return;

    const selected = assessments.find(a => a.assessment_id === selectedId);
    const isActive = selected?.status === 'processing' || selected?.status === 'queued';

    if (isActive) {
      pollingRef.current = setInterval(() => fetchLogs(selectedId), 3_000);
    }
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [selectedId, assessments, fetchLogs]);

  // Auto-scroll log panel
  useEffect(() => {
    if (autoScroll && logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logDetail?.logs?.length, autoScroll]);

  const handleSelectAssessment = (id: string) => {
    setSelectedId(id);
    setLogDetail(null);
    fetchLogs(id);
  };

  const filteredAssessments = assessments.filter(a => {
    if (statusFilter !== 'all' && a.status !== statusFilter) return false;
    if (search && !a.name.toLowerCase().includes(search.toLowerCase()) &&
        !a.assessment_id.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const filteredLogs = (logDetail?.logs ?? []).filter(l => {
    if (levelFilter !== 'all' && l.level !== levelFilter) return false;
    return true;
  });

  return (
    <div className="flex gap-4 h-[calc(100vh-220px)] min-h-[500px]">
      {/* Left: Assessment List */}
      <div className="w-80 flex-shrink-0 flex flex-col bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 overflow-hidden">
        <div className="p-3 border-b border-slate-100 dark:border-gray-700/60 flex flex-col gap-2">
          <input
            type="text"
            placeholder="Search assessments…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full px-3 py-1.5 text-sm rounded-lg bg-slate-50 dark:bg-gray-800/60 border border-slate-200 dark:border-gray-700 text-slate-700 dark:text-slate-300 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-[#0052cc]"
          />
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="w-full px-3 py-1.5 text-xs rounded-lg bg-slate-50 dark:bg-gray-800/60 border border-slate-200 dark:border-gray-700 text-slate-600 dark:text-slate-400 focus:outline-none focus:ring-1 focus:ring-[#0052cc]"
          >
            <option value="all">All statuses</option>
            <option value="processing">Processing</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="queued">Queued</option>
            <option value="pending">Pending</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>

        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center h-32">
              <div className="relative w-7 h-7">
                <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
                <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
              </div>
            </div>
          ) : filteredAssessments.length === 0 ? (
            <p className="text-center text-xs text-slate-400 py-10">No assessments found</p>
          ) : (
            filteredAssessments.map(a => (
              <button
                key={a.assessment_id}
                onClick={() => handleSelectAssessment(a.assessment_id)}
                className={`w-full text-left px-3 py-2.5 border-b border-slate-100 dark:border-gray-800/60 transition-colors hover:bg-slate-50 dark:hover:bg-gray-800/40 ${
                  selectedId === a.assessment_id ? 'bg-blue-50 dark:bg-blue-900/20' : ''
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border ${LOG_STATUS_COLORS[a.status] ?? 'text-slate-400'}`}>
                    {a.status}
                  </span>
                  {a.has_errors && (
                    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-900/20 text-red-400 border border-red-800/40">
                      <svg className="w-2.5 h-2.5" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                      errors
                    </span>
                  )}
                </div>
                <p className="text-xs font-medium text-slate-700 dark:text-slate-200 truncate">{a.name}</p>
                <p className="text-[10px] text-slate-400 mt-0.5 truncate">{a.assessment_id.slice(0, 8)}… · {a.log_count} entries</p>
              </button>
            ))
          )}
        </div>
      </div>

      {/* Right: Log Detail */}
      <div className="flex-1 flex flex-col bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 overflow-hidden">
        {!selectedId ? (
          <div className="flex-1 flex items-center justify-center text-slate-400 text-sm">
            Select an assessment to view its logs
          </div>
        ) : (
          <>
            {/* Header */}
            <div className="px-4 py-3 border-b border-slate-100 dark:border-gray-700/60 flex items-center gap-3 flex-wrap">
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-slate-700 dark:text-slate-200 truncate">{logDetail?.name ?? '…'}</p>
                <p className="text-[10px] text-slate-400 truncate">{selectedId}</p>
              </div>
              {logDetail && (
                <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${LOG_STATUS_COLORS[logDetail.status] ?? 'text-slate-400'}`}>
                  {logDetail.status}
                  {logDetail.current_step && logDetail.status === 'processing' && ` · ${STEP_DISPLAY[logDetail.current_step] ?? logDetail.current_step}`}
                </span>
              )}
              <select
                value={levelFilter}
                onChange={e => setLevelFilter(e.target.value)}
                className="px-2 py-1 text-xs rounded-lg bg-slate-50 dark:bg-gray-800/60 border border-slate-200 dark:border-gray-700 text-slate-600 dark:text-slate-400 focus:outline-none"
              >
                <option value="all">All levels</option>
                <option value="INFO">INFO</option>
                <option value="WARNING">WARNING</option>
                <option value="ERROR">ERROR</option>
              </select>
              <label className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={e => setAutoScroll(e.target.checked)}
                  className="rounded"
                />
                Auto-scroll
              </label>
            </div>

            {/* Error banner */}
            {logDetail?.error_message && (
              <div className="mx-4 mt-3 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/40 text-red-700 dark:text-red-400 text-xs">
                <span className="font-semibold">Error: </span>{logDetail.error_message}
              </div>
            )}

            {/* Log entries */}
            <div className="flex-1 overflow-y-auto font-mono text-xs bg-slate-950 dark:bg-[#0d1117] m-3 rounded-lg p-3 space-y-0.5">
              {logsLoading && filteredLogs.length === 0 ? (
                <p className="text-slate-500 text-center py-8">Loading logs…</p>
              ) : filteredLogs.length === 0 ? (
                <p className="text-slate-500 text-center py-8">No log entries yet</p>
              ) : (
                filteredLogs.map((entry, i) => (
                  <div key={i} className={`flex gap-2 py-0.5 leading-5 ${
                    entry.level === 'ERROR'
                      ? 'text-red-400'
                      : entry.level === 'WARNING'
                      ? 'text-amber-400'
                      : 'text-slate-300'
                  }`}>
                    <span className="text-slate-600 flex-shrink-0 w-[155px]">
                      {new Date(entry.ts).toLocaleTimeString('en-IN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                    <span className={`flex-shrink-0 w-16 ${
                      entry.level === 'ERROR' ? 'text-red-500' : entry.level === 'WARNING' ? 'text-amber-500' : 'text-emerald-600'
                    }`}>[{entry.level}]</span>
                    <span className="flex-shrink-0 w-24 text-violet-400">[{STEP_DISPLAY[entry.step] ?? entry.step}]</span>
                    <span className="break-all">{entry.message}</span>
                  </div>
                ))
              )}
              <div ref={logEndRef} />
            </div>
          </>
        )}
      </div>
    </div>
  );
};

// ─── Custom Threat Model Manager Tab ─────────────────────────────────────────

interface CustomRecord {
  id: string;
  name: string;
  assessment_ids: string[];
  created_by: string;
  created_at: string;
}

const CustomThreatModelManager: React.FC = () => {
  const [records, setRecords]         = useState<CustomRecord[]>([]);
  const [assessmentMap, setAssessmentMap] = useState<Record<string, string>>({});
  const [loading, setLoading]         = useState(true);
  const [deletingId, setDeletingId]   = useState<string | null>(null);
  const [error, setError]             = useState<string | null>(null);
  const [nameSearch, setNameSearch]   = useState('');
  const [userSearch, setUserSearch]   = useState('');
  const [subModelFilter, setSubModelFilter] = useState('');

  const authHeaders = (): Record<string, string> => {
    const token = localStorage.getItem('ts_auth_token');
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  useEffect(() => {
    setLoading(true);
    Promise.all([
      fetch(`${API_BASE_URL}/custom-threat-models`, { headers: authHeaders() })
        .then(r => r.ok ? r.json() : { records: [] }),
      fetch(`${API_BASE_URL}/analytics-data`, { headers: authHeaders() })
        .then(r => r.ok ? r.json() : { data: [] }),
    ]).then(([customData, analyticsData]) => {
      setRecords(customData.records ?? []);
      const map: Record<string, string> = {};
      for (const a of (analyticsData.data ?? [])) map[a.id] = a.name;
      setAssessmentMap(map);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  const handleDelete = async (id: string, name: string) => {
    if (!window.confirm(`Delete "${name}"? This cannot be undone.`)) return;
    setDeletingId(id);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/custom-threat-models/${id}`, {
        method: 'DELETE',
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error('Delete failed');
      setRecords(prev => prev.filter(r => r.id !== id));
    } catch {
      setError('Failed to delete. Please try again.');
    } finally {
      setDeletingId(null);
    }
  };

  const allSubModels = useMemo(() => {
    const seen = new Map<string, string>();
    for (const r of records) {
      for (const aid of r.assessment_ids) {
        if (!seen.has(aid)) seen.set(aid, assessmentMap[aid] ?? aid);
      }
    }
    return Array.from(seen.entries()).sort((a, b) => a[1].localeCompare(b[1]));
  }, [records, assessmentMap]);

  const filtered = useMemo(() => {
    const name = nameSearch.trim().toLowerCase();
    const user = userSearch.trim().toLowerCase();
    return records.filter(r => {
      if (name && !r.name.toLowerCase().includes(name)) return false;
      if (user && !r.created_by.toLowerCase().includes(user)) return false;
      if (subModelFilter && !r.assessment_ids.includes(subModelFilter)) return false;
      return true;
    });
  }, [records, nameSearch, userSearch, subModelFilter]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="relative w-8 h-8">
          <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
          <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
        </div>
      </div>
    );
  }

  const inputCls = 'w-full px-3 py-2 text-xs rounded-lg border border-slate-200 dark:border-gray-700 bg-white dark:bg-gray-900 text-slate-700 dark:text-slate-300 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/40';

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">Custom Analyses</h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
            {filtered.length === records.length ? `${records.length} saved` : `${filtered.length} of ${records.length}`}
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="grid grid-cols-3 gap-3">
        <div className="relative">
          <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            placeholder="Search by name…"
            value={nameSearch}
            onChange={e => setNameSearch(e.target.value)}
            className={`${inputCls} pl-8`}
          />
        </div>
        <div className="relative">
          <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
          </svg>
          <input
            type="text"
            placeholder="Filter by user…"
            value={userSearch}
            onChange={e => setUserSearch(e.target.value)}
            className={`${inputCls} pl-8`}
          />
        </div>
        <select
          value={subModelFilter}
          onChange={e => setSubModelFilter(e.target.value)}
          className={inputCls}
        >
          <option value="">All sub-models</option>
          {allSubModels.map(([id, name]) => (
            <option key={id} value={id}>{name}</option>
          ))}
        </select>
      </div>

      {error && (
        <div className="px-4 py-2.5 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/40 text-red-700 dark:text-red-400 text-sm">
          {error}
        </div>
      )}

      {records.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-slate-400 dark:text-slate-500 gap-2">
          <svg className="w-10 h-10 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
          </svg>
          <p className="text-sm">No custom analyses saved yet</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-slate-400 dark:text-slate-500 gap-2">
          <p className="text-sm">No results match your filters</p>
          <button
            onClick={() => { setNameSearch(''); setUserSearch(''); setSubModelFilter(''); }}
            className="text-xs text-[#0052cc] hover:underline"
          >
            Clear filters
          </button>
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-900/60 rounded-xl border border-slate-200 dark:border-gray-700/60 overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-100 dark:border-gray-700/60 bg-slate-50 dark:bg-gray-800/40">
                <th className="text-left px-4 py-3 font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Name</th>
                <th className="text-left px-4 py-3 font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Created By</th>
                <th className="text-left px-4 py-3 font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Sub-models</th>
                <th className="text-left px-4 py-3 font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Created At</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {filtered.map((r, i) => (
                <tr
                  key={r.id}
                  className={`border-b border-slate-100 dark:border-gray-700/40 last:border-0 ${
                    i % 2 === 0 ? '' : 'bg-slate-50/50 dark:bg-gray-800/20'
                  }`}
                >
                  <td className="px-4 py-3 font-medium text-slate-800 dark:text-slate-200">{r.name}</td>
                  <td className="px-4 py-3 text-slate-500 dark:text-slate-400">{r.created_by}</td>
                  <td className="px-4 py-3 text-slate-500 dark:text-slate-400">
                    <span className="inline-flex items-center gap-1">
                      {r.assessment_ids.length}
                      {subModelFilter && r.assessment_ids.includes(subModelFilter) && (
                        <span className="px-1.5 py-0.5 rounded bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-800/40 text-[10px]">
                          match
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-500 dark:text-slate-400">
                    {new Date(r.created_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDelete(r.id, r.name)}
                      disabled={deletingId === r.id}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 border border-red-200 dark:border-red-800/40 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {deletingId === r.id ? (
                        <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                      ) : (
                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      )}
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// ─── ThreatQualityTab ─────────────────────────────────────────────────────────

const DEFAULT_FILTER_CFG: ThreatFilterConfig = {
  enabled: true,
  criticPassEnabled: true,
  infrastructureControls: {
    apiGateway: {
      vendor: 'Kong/Cloudflare',
      trustedHeaders: ['x-user-id', 'x-device-id', 'x-tenant-id', 'x-request-id', 'x-correlation-id', 'x-forwarded-for', 'x-real-ip', 'x-auth-token', 'x-service-name'],
      description: 'Headers are stripped and re-injected by the API gateway after authentication. Cannot be set by external users or attackers.',
    },
    waf: {
      vendor: 'Cloudflare',
      capabilities: ['rate-limiting', 'ddos-protection', 'ip-reputation'],
      description: 'Rate limiting and DDoS protection enforced at CDN layer, not application code.',
    },
    serviceMesh: {
      protocol: 'mTLS',
      description: 'Internal service-to-service calls use mutual TLS certificates. Not accessible from the internet.',
    },
  },
  falsePositiveKeywords: [],
  sensitiveAssets: ['PII', 'authentication tokens', 'payment card data', 'financial records', 'personal identification numbers', 'API keys', 'session tokens'],
  qualityConfig: { requireSpecificEntryPoint: true, requireAssetSpecificity: true, minScenarioLength: 60 },
};

type RuleId = 'api-gateway' | 'waf' | 'service-mesh' | string;

interface RuleItem {
  id: RuleId;
  type: 'builtin' | 'custom';
  label: string;
  summary: string;
  iconType: 'shield' | 'tag';
}

const CHIP_CLS = 'inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-full bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800/50';

const inputCls = (disabled = false) =>
  `w-full px-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 transition-all ${
    disabled
      ? 'bg-slate-50 dark:bg-gray-800/40 border-slate-200 dark:border-gray-700/60 text-slate-400 dark:text-slate-500 cursor-not-allowed'
      : 'bg-white dark:bg-gray-800 border-slate-200 dark:border-gray-700 text-slate-800 dark:text-slate-200'
  }`;

const AssetInput: React.FC<{ onAdd: (a: string) => void }> = ({ onAdd }) => {
  const [val, setVal] = useState('');
  const commit = () => { const v = val.trim(); if (v) { onAdd(v); setVal(''); } };
  return (
    <div className="flex gap-2">
      <input
        type="text"
        value={val}
        onChange={e => setVal(e.target.value)}
        onKeyDown={e => e.key === 'Enter' && commit()}
        placeholder="Add asset…"
        className={`flex-1 ${inputCls(false)}`}
      />
      <button onClick={commit} className="px-3 py-2 text-sm bg-slate-100 dark:bg-gray-700 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-200 dark:hover:bg-gray-600 transition-colors">+</button>
    </div>
  );
};

const ShieldIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const TagIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A2 2 0 013 12V7a4 4 0 014-4z" />
  </svg>
);

const ThreatQualityTab: React.FC = () => {
  const [cfg, setCfg] = useState<ThreatFilterConfig>(DEFAULT_FILTER_CFG);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [subTab, setSubTab] = useState<'rules' | 'config'>('rules');
  const [selectedId, setSelectedId] = useState<RuleId | null>('api-gateway');
  const [isAddingRule, setIsAddingRule] = useState(false);
  const [newPattern, setNewPattern] = useState('');
  const [newHeader, setNewHeader] = useState('');
  const [newCapability, setNewCapability] = useState('');

  const flashStatus = (msg: string) => {
    setStatus(msg);
    setTimeout(() => setStatus(null), 3500);
  };

  useEffect(() => {
    apiService.getThreatFilterConfig()
      .then(res => { if (res?.threatFilterConfig) setCfg(res.threatFilterConfig); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      await apiService.saveThreatFilterConfig(cfg);
      flashStatus('Configuration saved.');
    } catch {
      flashStatus('Error saving — check backend logs.');
    } finally {
      setSaving(false);
    }
  };

  const canEdit = cfg.enabled;

  const rules: RuleItem[] = [
    {
      id: 'api-gateway', type: 'builtin', iconType: 'shield',
      label: 'API Gateway',
      summary: `${cfg.infrastructureControls.apiGateway.vendor} — ${cfg.infrastructureControls.apiGateway.trustedHeaders.length} trusted headers`,
    },
    {
      id: 'waf', type: 'builtin', iconType: 'shield',
      label: 'CDN / WAF',
      summary: `${cfg.infrastructureControls.waf.vendor} — ${cfg.infrastructureControls.waf.capabilities.join(', ')}`,
    },
    {
      id: 'service-mesh', type: 'builtin', iconType: 'shield',
      label: 'Service Mesh',
      summary: `${cfg.infrastructureControls.serviceMesh.protocol} — internal channels blocked`,
    },
    ...cfg.falsePositiveKeywords.map((kw, i): RuleItem => ({
      id: `custom-${i}`, type: 'custom', iconType: 'tag',
      label: kw,
      summary: 'Custom keyword filter',
    })),
  ];

  const updateInfra = (section: keyof ThreatFilterConfig['infrastructureControls'], patch: Partial<any>) =>
    setCfg(prev => ({
      ...prev,
      infrastructureControls: { ...prev.infrastructureControls, [section]: { ...prev.infrastructureControls[section], ...patch } },
    }));

  const addCustomRule = () => {
    const kw = newPattern.trim();
    if (!kw) return;
    const nextIdx = cfg.falsePositiveKeywords.length;
    setCfg(prev => ({ ...prev, falsePositiveKeywords: [...prev.falsePositiveKeywords, kw] }));
    setNewPattern('');
    setIsAddingRule(false);
    setSelectedId(`custom-${nextIdx}`);
  };

  const deleteCustomRule = (idx: number) => {
    setCfg(prev => ({ ...prev, falsePositiveKeywords: prev.falsePositiveKeywords.filter((_, i) => i !== idx) }));
    setSelectedId('api-gateway');
  };

  // ── Right-panel detail render ─────────────────────────────────────────────
  const renderDetail = () => {
    if (isAddingRule) return (
      <div className="space-y-5">
        <div>
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100 mb-1">New Custom Rule</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            A keyword or phrase that, when present in a threat scenario, marks it as a false positive to suppress.
          </p>
        </div>
        <div className="space-y-2">
          <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Pattern / Keyword</label>
          <input
            type="text"
            autoFocus
            value={newPattern}
            onChange={e => setNewPattern(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && addCustomRule()}
            placeholder="e.g. internal-only, already-mitigated, …"
            className={inputCls(false)}
          />
        </div>
        <div className="flex gap-3">
          <button
            onClick={addCustomRule}
            disabled={!newPattern.trim()}
            className="px-4 py-2 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm"
          >
            Add Rule
          </button>
          <button
            onClick={() => { setIsAddingRule(false); setNewPattern(''); }}
            className="px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    );

    if (!selectedId) return (
      <div className="flex flex-col items-center justify-center h-full py-20 text-slate-400 dark:text-slate-500">
        <ShieldIcon className="w-10 h-10 mb-3 opacity-30" />
        <p className="text-sm">Select a rule to view its details</p>
      </div>
    );

    if (selectedId === 'api-gateway') {
      const gw = cfg.infrastructureControls.apiGateway;
      return (
        <div className="space-y-5">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300 uppercase tracking-wider">Built-in</span>
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">API Gateway — Trusted Headers</h3>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            Any threat that requires an attacker to control one of the listed headers is suppressed. These headers are stripped and re-injected by the gateway after authentication.
          </p>
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Vendor</label>
            <input type="text" value={gw.vendor} disabled={!canEdit} onChange={e => updateInfra('apiGateway', { vendor: e.target.value })} className={inputCls(!canEdit)} />
          </div>
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Trusted Headers</label>
            <div className="flex flex-wrap gap-2 p-3 min-h-[52px] rounded-lg border border-slate-200 dark:border-gray-700 bg-white dark:bg-gray-800">
              {gw.trustedHeaders.map(h => (
                <span key={h} className={CHIP_CLS}>
                  {h}
                  {canEdit && (
                    <button onClick={() => updateInfra('apiGateway', { trustedHeaders: gw.trustedHeaders.filter(x => x !== h) })} className="ml-0.5 text-blue-500 hover:text-red-500 leading-none">&times;</button>
                  )}
                </span>
              ))}
            </div>
            {canEdit && (
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newHeader}
                  onChange={e => setNewHeader(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && newHeader.trim()) { updateInfra('apiGateway', { trustedHeaders: [...gw.trustedHeaders, newHeader.trim()] }); setNewHeader(''); } }}
                  placeholder="Add header…"
                  className={`flex-1 ${inputCls(false)}`}
                />
                <button
                  onClick={() => { if (newHeader.trim()) { updateInfra('apiGateway', { trustedHeaders: [...gw.trustedHeaders, newHeader.trim()] }); setNewHeader(''); } }}
                  className="px-3 py-2 text-sm bg-slate-100 dark:bg-gray-700 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-200 dark:hover:bg-gray-600 transition-colors"
                >+</button>
              </div>
            )}
          </div>
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Description</label>
            <textarea rows={3} disabled={!canEdit} value={gw.description} onChange={e => updateInfra('apiGateway', { description: e.target.value })} className={`${inputCls(!canEdit)} resize-none`} />
          </div>
        </div>
      );
    }

    if (selectedId === 'waf') {
      const waf = cfg.infrastructureControls.waf;
      return (
        <div className="space-y-5">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300 uppercase tracking-wider">Built-in</span>
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">CDN / WAF — Rate Limiting &amp; DDoS</h3>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            Any threat that relies on bypassing rate limiting or volumetric DDoS protection is suppressed. These controls are enforced at the CDN layer upstream of the application.
          </p>
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Vendor</label>
            <input type="text" value={waf.vendor} disabled={!canEdit} onChange={e => updateInfra('waf', { vendor: e.target.value })} className={inputCls(!canEdit)} />
          </div>
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Capabilities</label>
            <div className="flex flex-wrap gap-2 p-3 min-h-[52px] rounded-lg border border-slate-200 dark:border-gray-700 bg-white dark:bg-gray-800">
              {waf.capabilities.map(c => (
                <span key={c} className={CHIP_CLS}>
                  {c}
                  {canEdit && (
                    <button onClick={() => updateInfra('waf', { capabilities: waf.capabilities.filter(x => x !== c) })} className="ml-0.5 text-blue-500 hover:text-red-500 leading-none">&times;</button>
                  )}
                </span>
              ))}
            </div>
            {canEdit && (
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newCapability}
                  onChange={e => setNewCapability(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && newCapability.trim()) { updateInfra('waf', { capabilities: [...waf.capabilities, newCapability.trim()] }); setNewCapability(''); } }}
                  placeholder="Add capability…"
                  className={`flex-1 ${inputCls(false)}`}
                />
                <button
                  onClick={() => { if (newCapability.trim()) { updateInfra('waf', { capabilities: [...waf.capabilities, newCapability.trim()] }); setNewCapability(''); } }}
                  className="px-3 py-2 text-sm bg-slate-100 dark:bg-gray-700 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-200 dark:hover:bg-gray-600 transition-colors"
                >+</button>
              </div>
            )}
          </div>
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Description</label>
            <textarea rows={3} disabled={!canEdit} value={waf.description} onChange={e => updateInfra('waf', { description: e.target.value })} className={`${inputCls(!canEdit)} resize-none`} />
          </div>
        </div>
      );
    }

    if (selectedId === 'service-mesh') {
      const mesh = cfg.infrastructureControls.serviceMesh;
      return (
        <div className="space-y-5">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300 uppercase tracking-wider">Built-in</span>
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Service Mesh — Internal Channels</h3>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            Any threat that requires access to internal service-to-service channels is suppressed. Internal microservice calls use mTLS or service tokens not reachable from the internet.
          </p>
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Protocol</label>
            <select disabled={!canEdit} value={mesh.protocol} onChange={e => updateInfra('serviceMesh', { protocol: e.target.value })} className={inputCls(!canEdit)}>
              <option value="mTLS">mTLS</option>
              <option value="JWT">JWT</option>
              <option value="Other">Other</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Description</label>
            <textarea rows={3} disabled={!canEdit} value={mesh.description} onChange={e => updateInfra('serviceMesh', { description: e.target.value })} className={`${inputCls(!canEdit)} resize-none`} />
          </div>
        </div>
      );
    }

    if (typeof selectedId === 'string' && selectedId.startsWith('custom-')) {
      const idx = parseInt(selectedId.replace('custom-', ''), 10);
      const kw = cfg.falsePositiveKeywords[idx];
      if (kw === undefined) return null;
      return (
        <div className="space-y-5">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 uppercase tracking-wider">Custom</span>
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Custom Keyword Rule</h3>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            Threat scenarios containing this keyword or phrase are treated as org-specific false positives and suppressed.
          </p>
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Pattern / Keyword</label>
            <input
              type="text"
              disabled={!canEdit}
              value={kw}
              onChange={e => {
                const updated = [...cfg.falsePositiveKeywords];
                updated[idx] = e.target.value;
                setCfg(prev => ({ ...prev, falsePositiveKeywords: updated }));
              }}
              className={inputCls(!canEdit)}
            />
          </div>
          {canEdit && (
            <button
              onClick={() => deleteCustomRule(idx)}
              className="flex items-center gap-2 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
              Delete Rule
            </button>
          )}
        </div>
      );
    }

    return null;
  };

  if (loading) return (
    <div className="flex items-center justify-center py-24">
      <div className="relative w-10 h-10">
        <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
        <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
      </div>
    </div>
  );

  return (
    <div className="space-y-5">

      {/* Sub-tab bar */}
      <div className="flex items-center gap-1 bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 p-1 w-fit shadow-sm">
        {(['rules', 'config'] as const).map(t => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-150 ${
              subTab === t
                ? 'bg-[#0052cc] text-white shadow-sm'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-gray-800/60'
            }`}
          >
            {t === 'rules' ? 'Rules' : 'General Config'}
          </button>
        ))}
      </div>

      {/* ── Rules sub-tab ── */}
      {subTab === 'rules' && (
        <div className="flex gap-5" style={{ minHeight: 540 }}>

          {/* Left panel — rule list */}
          <div className="w-72 flex-shrink-0 flex flex-col bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-100 dark:border-gray-800">
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">FP Filter Rules</p>
            </div>

            {!canEdit && (
              <div className="flex items-center gap-2 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border-b border-amber-200 dark:border-amber-800/40 text-amber-700 dark:text-amber-400 text-xs font-medium">
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                Enable FP Filtering to edit rules
              </div>
            )}

            <div className="flex-1 overflow-y-auto divide-y divide-slate-50 dark:divide-gray-800/60">
              {rules.map(rule => (
                <button
                  key={rule.id}
                  onClick={() => { setSelectedId(rule.id); setIsAddingRule(false); }}
                  className={`w-full text-left px-4 py-3 flex items-start gap-3 transition-colors border-l-2 ${
                    selectedId === rule.id && !isAddingRule
                      ? 'border-[#0052cc] bg-blue-50/60 dark:bg-blue-900/10'
                      : 'border-transparent hover:bg-slate-50 dark:hover:bg-gray-800/50'
                  }`}
                >
                  {rule.iconType === 'shield'
                    ? <ShieldIcon className="w-4 h-4 mt-0.5 flex-shrink-0 text-violet-500 dark:text-violet-400" />
                    : <TagIcon className="w-4 h-4 mt-0.5 flex-shrink-0 text-emerald-500 dark:text-emerald-400" />
                  }
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">{rule.label}</p>
                    <p className="text-xs text-slate-400 dark:text-slate-500 truncate mt-0.5">{rule.summary}</p>
                  </div>
                </button>
              ))}
            </div>

            <div className="px-3 py-3 border-t border-slate-100 dark:border-gray-800">
              <button
                disabled={!canEdit}
                onClick={() => { setIsAddingRule(true); setSelectedId(null); setNewPattern(''); }}
                className="w-full flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium rounded-lg border border-dashed border-slate-300 dark:border-gray-600 text-slate-500 dark:text-slate-400 hover:border-[#0052cc] hover:text-[#0052cc] disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
                Add Rule
              </button>
            </div>
          </div>

          {/* Right panel — rule detail / add form */}
          <div className="flex-1 bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-6 overflow-y-auto">
            {renderDetail()}
          </div>
        </div>
      )}

      {/* ── General Config sub-tab ── */}
      {subTab === 'config' && (
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">General Configuration</h2>
          </div>
          <div className="px-6 py-6 space-y-8">

            {/* Feature flags */}
            <div className="space-y-4">
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Feature Flags</p>
              <label className="flex items-start gap-3 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={cfg.enabled}
                  onChange={e => setCfg(prev => ({ ...prev, enabled: e.target.checked }))}
                  className="h-4 w-4 mt-0.5 text-[#0052cc] rounded border-slate-300 focus:ring-[#0052cc] dark:border-gray-600"
                />
                <div>
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-slate-100">Enable False Positive Filtering</p>
                  <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">Injects infrastructure context into the generation prompt and activates the rules defined in the Rules tab. Disabling this skips all FP suppression.</p>
                </div>
              </label>
              <label className="flex items-start gap-3 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={cfg.criticPassEnabled}
                  onChange={e => setCfg(prev => ({ ...prev, criticPassEnabled: e.target.checked }))}
                  className="h-4 w-4 mt-0.5 text-[#0052cc] rounded border-slate-300 focus:ring-[#0052cc] dark:border-gray-600"
                />
                <div>
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-slate-100">Enable 2nd-Pass LLM Critic</p>
                  <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">Runs a second LLM call after generation to filter false positives, deduplicate near-identical scenarios, and improve vague descriptions. Adds latency but significantly improves output quality.</p>
                </div>
              </label>
            </div>

            {/* Sensitive assets */}
            <div className="space-y-3">
              <div>
                <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Sensitive Assets</p>
                <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Assets the LLM is instructed to reference in threat scenarios. Each threat must name at least one when asset specificity is required.</p>
              </div>
              <div className="flex flex-wrap gap-2 p-3 min-h-[52px] rounded-lg border border-slate-200 dark:border-gray-700 bg-white dark:bg-gray-800">
                {cfg.sensitiveAssets.map(a => (
                  <span key={a} className={CHIP_CLS}>
                    {a}
                    <button onClick={() => setCfg(prev => ({ ...prev, sensitiveAssets: prev.sensitiveAssets.filter(x => x !== a) }))} className="ml-0.5 text-blue-500 hover:text-red-500 leading-none">&times;</button>
                  </span>
                ))}
              </div>
              <AssetInput onAdd={asset => setCfg(prev => ({ ...prev, sensitiveAssets: [...prev.sensitiveAssets, asset] }))} />
            </div>

            {/* Quality thresholds */}
            <div className="space-y-4">
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Quality Thresholds</p>
              <label className="flex items-start gap-3 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={cfg.qualityConfig.requireSpecificEntryPoint}
                  onChange={e => setCfg(prev => ({ ...prev, qualityConfig: { ...prev.qualityConfig, requireSpecificEntryPoint: e.target.checked } }))}
                  className="h-4 w-4 mt-0.5 text-[#0052cc] rounded border-slate-300 focus:ring-[#0052cc] dark:border-gray-600"
                />
                <div>
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-300">Require Specific Entry Point</p>
                  <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">Each threat must name a concrete entry point (API path, UI action, webhook) — generic phrases like "an API" are rejected.</p>
                </div>
              </label>
              <label className="flex items-start gap-3 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={cfg.qualityConfig.requireAssetSpecificity}
                  onChange={e => setCfg(prev => ({ ...prev, qualityConfig: { ...prev.qualityConfig, requireAssetSpecificity: e.target.checked } }))}
                  className="h-4 w-4 mt-0.5 text-[#0052cc] rounded border-slate-300 focus:ring-[#0052cc] dark:border-gray-600"
                />
                <div>
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-300">Require Asset Specificity</p>
                  <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">Each threat must reference at least one specific sensitive asset from the list above.</p>
                </div>
              </label>
              <div className="flex items-center gap-4 flex-wrap">
                <div>
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-0.5">Min Scenario Length</p>
                  <p className="text-xs text-slate-400 dark:text-slate-500">Threats shorter than this character count are rejected by the critic pass.</p>
                </div>
                <div className="flex items-center gap-2 ml-auto">
                  <input
                    type="number"
                    min={20}
                    max={500}
                    value={cfg.qualityConfig.minScenarioLength}
                    onChange={e => setCfg(prev => ({ ...prev, qualityConfig: { ...prev.qualityConfig, minScenarioLength: Number(e.target.value) } }))}
                    className="w-24 px-3 py-2 text-sm border border-slate-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30"
                  />
                  <span className="text-xs text-slate-500">chars</span>
                </div>
              </div>
            </div>

          </div>
        </div>
      )}

      {/* Save bar */}
      <div className="flex items-center justify-between px-1 pb-2">
        <span className={`text-sm font-medium transition-opacity duration-300 ${status ? 'opacity-100' : 'opacity-0'} ${status?.startsWith('Error') ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
          {status ?? '​'}
        </span>
        <button
          onClick={save}
          disabled={saving}
          className="px-5 py-2 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm"
        >
          {saving ? 'Saving…' : 'Save Configuration'}
        </button>
      </div>

    </div>
  );
};

// ─── Timestamp Config ─────────────────────────────────────────────────────────

const GeneralSettings: React.FC = () => {
  const [timeZone, setTimeZone] = useState<string>(DEFAULT_TIMEZONE);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<{ msg: string; ok: boolean } | null>(null);

  useEffect(() => {
    apiService.getGeneralConfig()
      .then(res => { if (res?.generalConfig?.timezone) setTimeZone(res.generalConfig.timezone); })
      .catch(() => { /* keep default */ })
      .finally(() => setLoading(false));
  }, []);

  const flash = (msg: string, ok: boolean) => {
    setStatus({ msg, ok });
    setTimeout(() => setStatus(null), 3000);
  };

  const save = async () => {
    setSaving(true);
    try {
      await apiService.saveGeneralConfig({ timezone: timeZone });
      flash('Timezone saved.', true);
    } catch (e) {
      flash('Error saving timezone.', false);
    } finally {
      setSaving(false);
    }
  };

  // Live preview of "now" in the selected timezone.
  const preview = (() => {
    try {
      return new Date().toLocaleString('en-US', {
        timeZone, month: 'short', day: 'numeric', year: 'numeric',
        hour: 'numeric', minute: '2-digit', timeZoneName: 'short',
      });
    } catch {
      return '—';
    }
  })();

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="relative w-10 h-10">
          <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
          <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Time Configuration</h2>
          <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">
            Timezone used to display timestamps for new and existing assessments across the app.
          </p>
        </div>

        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5">Display timezone</label>
            <select
              value={timeZone}
              onChange={e => setTimeZone(e.target.value)}
              className="w-full max-w-md px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-slate-700 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/40"
            >
              {WORLD_CLOCK_ZONES.map(z => (
                <option key={z.value} value={z.value}>
                  {z.label} ({z.offset})
                </option>
              ))}
            </select>
            <p className="mt-2 text-xs text-slate-400 dark:text-slate-500">
              Current time here: <span className="font-medium text-slate-600 dark:text-slate-300">{preview}</span>
            </p>
          </div>

          <div className="flex items-center gap-3 pt-1">
            <button
              onClick={save}
              disabled={saving}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-[#0052cc] text-white shadow-sm hover:bg-[#0047b3] disabled:opacity-50 transition-colors"
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
            {status && (
              <span className={`text-xs font-medium ${status.ok ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
                {status.msg}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── Tab definitions ──────────────────────────────────────────────────────────

type AdminTab = 'models' | 'custom-models' | 'feedback' | 'users' | 'settings' | 'logs' | 'threat-quality' | 'mcp' | 'teams' | 'general';

const ADMIN_TABS: { id: AdminTab; label: string; icon: React.ReactNode }[] = [
  {
    id: 'models',
    label: 'Threat Model Manager',
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
    ),
  },
  {
    id: 'custom-models' as const,
    label: 'Custom Analyses',
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z" />
      </svg>
    ),
  },
  {
    id: 'feedback',
    label: 'Feedback Analytics',
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    ),
  },
  {
    id: 'users' as const,
    label: 'User Management',
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
      </svg>
    ),
  },
  {
    id: 'logs' as const,
    label: 'Logs',
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 6h16M4 10h16M4 14h10M4 18h6" />
      </svg>
    ),
  },
  {
    id: 'threat-quality' as const,
    label: 'Threat Quality',
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
  {
    id: 'mcp' as const,
    label: 'Organization',
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-2 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
      </svg>
    ),
  },
  {
    id: 'teams' as const,
    label: 'Teams',
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-2 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
      </svg>
    ),
  },
  {
    id: 'settings' as const,
    label: 'Settings',
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      </svg>
    ),
  },
  {
    id: 'general' as const,
    label: 'Timestamp Config',
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
];

const OrganizationSection: React.FC = () => (
  <div className="space-y-6">
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
      {/* Config Github card */}
      <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-6 flex flex-col gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-slate-100 dark:bg-gray-800 border border-slate-200 dark:border-gray-700 flex items-center justify-center">
            <svg className="w-5 h-5 text-slate-600 dark:text-slate-400" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.009-.868-.013-1.703-2.782.604-3.369-1.342-3.369-1.342-.454-1.154-1.11-1.462-1.11-1.462-.908-.62.069-.608.069-.608 1.003.07 1.531 1.031 1.531 1.031.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.682-.103-.253-.446-1.27.098-2.646 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.376.203 2.393.1 2.646.64.698 1.028 1.591 1.028 2.682 0 3.841-2.337 4.687-4.565 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
            </svg>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Config Github</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Connect and configure GitHub integration</p>
          </div>
        </div>
        <div className="flex items-center gap-2 mt-auto">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800/40">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
            Coming Soon
          </span>
        </div>
      </div>

      {/* MCP card */}
      <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-6 flex flex-col gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-violet-50 dark:bg-violet-900/20 border border-violet-200 dark:border-violet-800/40 flex items-center justify-center">
            <svg className="w-5 h-5 text-violet-600 dark:text-violet-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">MCP</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Model Context Protocol server management</p>
          </div>
        </div>
        <div className="flex items-center gap-2 mt-auto">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800/40">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
            Coming Soon
          </span>
        </div>
      </div>
    </div>
  </div>
);

const TeamsSection: React.FC = () => {
  const [teams, setTeams] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [newName, setNewName] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch(`${API_BASE_URL}/teams`)
      .then(r => r.json())
      .then(d => setTeams(d.teams || []))
      .catch(() => setTeams([]))
      .finally(() => setLoading(false));
  }, []);

  const handleAdd = async () => {
    const name = newName.trim();
    if (!name) { setError('Team name cannot be empty.'); return; }
    setSaving(true);
    setError('');
    try {
      const token = localStorage.getItem('ts_auth_token');
      const res = await fetch(`${API_BASE_URL}/teams`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ name }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || 'Failed to add team'); return; }
      setTeams(data.teams);
      setNewName('');
    } catch {
      setError('Network error. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (name: string) => {
    try {
      const token = localStorage.getItem('ts_auth_token');
      const res = await fetch(`${API_BASE_URL}/teams/${encodeURIComponent(name)}`, {
        method: 'DELETE',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || 'Failed to delete team'); return; }
      setTeams(data.teams);
    } catch {
      setError('Network error. Please try again.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800 flex items-center justify-between">
          <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">Teams</h2>
          {teams.length > 0 && (
            <span className="text-xs font-semibold bg-slate-100 dark:bg-gray-800 text-slate-500 dark:text-slate-400 px-2 py-0.5 rounded-full">
              {teams.length}
            </span>
          )}
        </div>

        <div className="px-6 py-5 space-y-4">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Team names added here appear as options in the assessment form's Team dropdown.
          </p>

          {/* Add form */}
          <div className="flex gap-2">
            <input
              type="text"
              value={newName}
              onChange={e => { setNewName(e.target.value); setError(''); }}
              onKeyDown={e => e.key === 'Enter' && handleAdd()}
              placeholder="Team name"
              className="flex-1 px-3 py-2 text-sm border border-slate-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc] transition-all"
            />
            <button
              onClick={handleAdd}
              disabled={saving}
              className="px-4 py-2 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm"
            >
              {saving ? 'Adding…' : 'Add'}
            </button>
          </div>

          {error && <p className="text-xs text-red-600 dark:text-red-400">{error}</p>}

          {/* List */}
          {loading ? (
            <div className="flex items-center gap-2 py-4">
              <div className="w-4 h-4 rounded-full border-2 border-slate-200 border-t-[#0052cc] animate-spin" />
              <span className="text-sm text-slate-400">Loading…</span>
            </div>
          ) : teams.length === 0 ? (
            <p className="text-sm text-slate-400 dark:text-slate-500 py-4 text-center">No teams configured yet.</p>
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-gray-800 rounded-lg border border-slate-200 dark:border-gray-700 overflow-hidden">
              {teams.map(team => (
                <li key={team} className="flex items-center justify-between px-4 py-3 bg-white dark:bg-gray-900/60 hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors">
                  <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{team}</span>
                  <button
                    onClick={() => handleDelete(team)}
                    className="text-slate-400 hover:text-red-500 dark:hover:text-red-400 transition-colors p-1 rounded"
                    title="Remove"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
};

const AdminDashboard: React.FC = () => {
  const { isMcpAdmin, loading } = useAuth();
  const [searchParams] = useSearchParams();
  const initialTab = (['models', 'custom-models', 'feedback', 'users', 'settings', 'logs', 'threat-quality', 'mcp', 'teams', 'general'] as AdminTab[]).includes(searchParams.get('tab') as AdminTab)
    ? (searchParams.get('tab') as AdminTab)
    : 'models';
  const [activeTab, setActiveTab] = useState<AdminTab>(initialTab);
  const [feedbacks, setFeedbacks] = useState<FeedbackEntry[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isMcpAdmin || activeTab !== 'feedback') return;
    if (feedbacks.length > 0) return;

    const load = async () => {
      setDataLoading(true);
      try {
        const token = localStorage.getItem('ts_auth_token');
        const res = await fetch(`${API_BASE_URL}/admin/feedback`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });

        if (!res.ok) throw new Error('Failed to load admin feedback data');

        const data: { feedbacks?: FeedbackEntry[] } = await res.json();
        const sorted = (data.feedbacks ?? []).sort(
          (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
        );

        setFeedbacks(sorted);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Unknown error');
      } finally {
        setDataLoading(false);
      }
    };

    void load();
  }, [isMcpAdmin, activeTab, feedbacks.length]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="relative w-10 h-10">
          <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
          <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
        </div>
      </div>
    );
  }

  if (!isMcpAdmin) {
    return <Navigate to="/home" replace />;
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      <div className="px-6 py-8">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#0052cc] to-violet-600 flex items-center justify-center shadow-lg shadow-blue-900/30 flex-shrink-0">
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Admin</h1>
              <p className="text-xs text-slate-400 dark:text-slate-500">Admin Dashboard</p>
            </div>
            <span className="ml-auto px-2.5 py-1 rounded-full text-[10px] font-bold bg-violet-100 text-violet-700 border border-violet-200 dark:bg-violet-900/30 dark:text-violet-300 dark:border-violet-800/40 uppercase tracking-wider">
              Admin Access
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1 mb-6 bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 p-1 w-fit shadow-sm">
          {ADMIN_TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-150 ${
                activeTab === tab.id
                  ? 'bg-[#0052cc] text-white shadow-sm'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-gray-800/60'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {error && (
          <div className="mb-6 px-4 py-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/40 text-red-700 dark:text-red-400 text-sm">
            {error}
          </div>
        )}

        {activeTab === 'models' && <ThreatModelManager />}

        {activeTab === 'custom-models' && <CustomThreatModelManager />}

        {activeTab === 'feedback' &&
          (dataLoading ? (
            <div className="flex items-center justify-center py-24">
              <div className="flex flex-col items-center gap-4">
                <div className="relative w-10 h-10">
                  <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
                  <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
                </div>
                <p className="text-sm text-slate-400">Loading analytics…</p>
              </div>
            </div>
          ) : (
            <FeedbackAnalytics feedbacks={feedbacks} />
          ))}

        {activeTab === 'users' && <UserManagement />}

        {activeTab === 'logs' && <LogsTab />}

        {activeTab === 'threat-quality' && <ThreatQualityTab />}

        {activeTab === 'mcp' && <OrganizationSection />}

        {activeTab === 'teams' && <TeamsSection />}

        {activeTab === 'settings' && <AdminSettings />}

        {activeTab === 'general' && <GeneralSettings />}
      </div>
    </div>
  );
};

export default AdminDashboard;