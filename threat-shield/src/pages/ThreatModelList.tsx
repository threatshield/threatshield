import React, { useEffect, useMemo, useState, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import { useAssessment } from '../context/AssessmentContext';
import { apiService, API_BASE_URL } from '../services/api';
import { ReportMetadata } from '../types/reportTypes';
import { formatTimestamp, DEFAULT_TIMEZONE } from '../utils/timezones';

// ─── Badge config ────────────────────────────────────────────────────────────

const ROUTE_MAP: Record<string, (id: string) => string> = {
  threat_model: (id) => `/view-threat-model/${id}`,
  dread_assessment: (id) => `/view-dread/${id}`,
  mitigation: (id) => `/view-mitigation/${id}`,
  attack_tree: (id) => `/view-attack-tree/${id}`,
  test_cases: (id) => `/view-security-test-cases/${id}`,
};

const OUTPUTS = [
  {
    key: 'threat_model',
    label: 'Threat Model',
    short: 'TM',
    check: (r: ReportMetadata) => !!r.threat_model?.result,
    color: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400',
    borderColor: 'border-emerald-200 dark:border-emerald-800/50',
    dot: 'bg-emerald-500',
  },
  {
    key: 'dread_assessment',
    label: 'DREAD',
    short: 'DREAD',
    check: (r: ReportMetadata) => !!r.dread_assessment?.result,
    color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
    borderColor: 'border-amber-200 dark:border-amber-800/50',
    dot: 'bg-amber-500',
  },
  {
    key: 'mitigation',
    label: 'Mitigation',
    short: 'Mitig.',
    check: (r: ReportMetadata) => !!r.mitigation?.result,
    color: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400',
    borderColor: 'border-rose-200 dark:border-rose-800/50',
    dot: 'bg-rose-500',
  },
  {
    key: 'attack_tree',
    label: 'Attack Tree',
    short: 'Tree',
    check: (r: ReportMetadata) => !!r.attack_tree?.result,
    color: 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-400',
    borderColor: 'border-sky-200 dark:border-sky-800/50',
    dot: 'bg-sky-500',
  },
  {
    key: 'test_cases',
    label: 'Test Cases',
    short: 'Tests',
    check: (r: ReportMetadata) =>
      Array.isArray(r.test_cases?.result?.test_cases) && r.test_cases!.result.test_cases.length > 0,
    color: 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-400',
    borderColor: 'border-violet-200 dark:border-violet-800/50',
    dot: 'bg-violet-500',
  },
] as const;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatDate(dateString: string, timeZone?: string): { relative: string; full: string } {
  return formatTimestamp(dateString, timeZone);
}

function getTestStats(r: ReportMetadata) {
  if (!Array.isArray(r.test_cases?.result?.test_cases)) return { total: 0, validated: 0 };
  const tc = r.test_cases!.result.test_cases.filter((t: any) => t?.asvs_requirement !== 'Error');
  return { total: tc.length, validated: tc.filter((t: any) => t?.validated === true).length };
}

// ─── Multi-select dropdown ────────────────────────────────────────────────────

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
                selected.includes(item.key)
                  ? 'bg-[#0052cc] border-[#0052cc]'
                  : 'border-slate-300 dark:border-gray-600'
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

// ─── Component ───────────────────────────────────────────────────────────────

const ThreatModelList: React.FC = () => {
  const navigate = useNavigate();
  const { setAssessmentId } = useAssessment();

  const [reports, setReports] = useState<ReportMetadata[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [openDownloadId, setOpenDownloadId] = useState<string | null>(null);
  const [downloadMenuPos, setDownloadMenuPos] = useState<{ top: number; right: number } | null>(null);
  const [infoPopupId, setInfoPopupId] = useState<string | null>(null);
  const [infoFiles, setInfoFiles] = useState<{ name: string; size: number }[]>([]);
  const [timeZone, setTimeZone] = useState<string>(DEFAULT_TIMEZONE);

  // Filters
  const [search, setSearch] = useState('');
  const [filterDepartment, setFilterDepartment] = useState<string[]>([]);
  const [filterMethodology, setFilterMethodology] = useState<string[]>([]);
  const [filterOutputs, setFilterOutputs] = useState<string[]>([]);
  const [filterDateFrom, setFilterDateFrom] = useState('');
  const [filterDateTo, setFilterDateTo] = useState('');

  // Sort
  const [sortField, setSortField] = useState<'date' | 'name'>('date');
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc');

  useEffect(() => {
    apiService.getStorageHistory()
      .then((res: any) => {
        if (!res?.data) throw new Error('Invalid response');
        setReports(res.data);
      })
      .catch(() => setError('No threat models found.'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    apiService.getGeneralConfig()
      .then(res => { if (res?.generalConfig?.timezone) setTimeZone(res.generalConfig.timezone); })
      .catch(() => { /* fall back to default timezone */ });
  }, []);


  const fetchReportParts = async (reportId: string) => {
    const types = ['threat_model', 'dread_assessment', 'mitigation', 'attack_tree'] as const;
    const results = await Promise.all(
      types.map(async (type) => {
        const res = await fetch(`${API_BASE_URL}/storage?assessment_id=${reportId}&assessment_name=${type}`);
        if (!res.ok) return [type, null] as const;
        const data = await res.json();
        return [type, data] as const;
      })
    );
    return Object.fromEntries(results) as Record<typeof types[number], any>;
  };

  const handleDownload = async (reportId: string, type: 'pdf' | 'json' | 'markdown' | 'tmbom') => {
    setOpenDownloadId(null);
    setDownloadMenuPos(null);

    if (type === 'pdf') {
      try {
        const blob = await apiService.downloadPdf(reportId);
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `threatshield-report-${reportId}.pdf`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
      } catch (err) {
        alert('Failed to download PDF report. Please try from the full report page.');
      }
      return;
    }

    if (type === 'tmbom') {
      try {
        const blob = await apiService.downloadTmBom(reportId);
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `tmbom-${reportId}.json`;
        link.click();
        URL.revokeObjectURL(link.href);
      } catch (err) {
        alert('Failed to download TM-BOM. Please try from the threat model page.');
      }
      return;
    }

    try {
      const parts = await fetchReportParts(reportId);
      const reportMeta = reports.find(r => r.id === reportId);

      if (type === 'json') {
        const jsonData = {
          metadata: {
            id: reportId,
            name: reportMeta?.details ? `[${reportMeta.details.department}] - ${reportMeta.details.projectName}` : reportId,
            methodology: reportMeta?.details?.threatModelingMethodology || '',
            timestamp: new Date().toISOString(),
            generated: new Date().toLocaleDateString(),
          },
          threat_model: parts.threat_model?.result?.result?.raw_response || null,
          dread_assessment: parts.dread_assessment?.result?.result?.raw_response || null,
          mitigation: parts.mitigation?.result?.result?.raw_response || null,
          attack_tree: parts.attack_tree?.result?.result?.attack_tree || null,
        };
        const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `threat-shield-report-${reportId}.json`;
        link.click();
        URL.revokeObjectURL(url);
        return;
      }

      // markdown
      const name = reportMeta?.details
        ? `[${reportMeta.details.department}] - ${reportMeta.details.projectName}`
        : reportId;
      const methodology = reportMeta?.details?.threatModelingMethodology || '';

      let md = `# Threat Modelling Report\n\n`;
      md += `## Security Assessment Report\n\n`;
      md += `- **Name**: ${name}\n`;
      md += `- **Methodology**: ${methodology}\n`;
      md += `- **Assessment ID**: ${reportId}\n`;
      md += `- **Generated**: ${new Date().toLocaleDateString()}\n\n`;

      const tmRaw = parts.threat_model?.result?.result?.raw_response;
      if (tmRaw) {
        md += `## Threat Model Analysis\n\n`;
        md += `### Threats\n\n`;
        md += `| Threat Type | Scenario | Potential Impact |\n`;
        md += `| ----------- | -------- | ---------------- |\n`;
        (tmRaw.threat_model || []).forEach((t: any) => {
          md += `| ${t['Threat Type'] ?? ''} | ${t['Scenario'] ?? ''} | ${t['Potential Impact'] ?? ''} |\n`;
        });
        md += `\n`;

        if ((tmRaw.improvement_suggestions || []).length > 0) {
          md += `### Improvement Suggestions\n\n`;
          tmRaw.improvement_suggestions.forEach((s: string, i: number) => {
            md += `${i + 1}. ${s}\n`;
          });
          md += `\n`;
        }
      }

      const dreadRaw = parts.dread_assessment?.result?.result?.raw_response?.['Risk Assessment'];
      if (dreadRaw && dreadRaw.length > 0) {
        md += `## DREAD Risk Assessment\n\n`;
        md += `| Threat Type | Scenario | Damage | Reproducibility | Exploitability | Affected Users | Discoverability |\n`;
        md += `| ----------- | -------- | ------ | --------------- | -------------- | -------------- | --------------- |\n`;
        dreadRaw.forEach((item: any) => {
          md += `| ${item['Threat Type'] ?? ''} | ${item['Scenario'] ?? ''} | ${item['Damage Potential'] ?? ''} | ${item['Reproducibility'] ?? ''} | ${item['Exploitability'] ?? ''} | ${item['Affected Users'] ?? ''} | ${item['Discoverability'] ?? ''} |\n`;
        });
        md += `\n`;
      }

      const mitigationMd = parts.mitigation?.result?.result?.markdown;
      if (mitigationMd) {
        md += `## Mitigation Strategies\n\n${mitigationMd}\n\n`;
      }

      const attackTreeMd = parts.attack_tree?.result?.result?.markdown;
      if (attackTreeMd) {
        md += `## Attack Tree Analysis\n\n${attackTreeMd}\n\n`;
      }

      const blob = new Blob([md], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `threat-shield-report-${reportId}.md`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download report. Please try from the full report page.');
    }
  };

  const handleDownloadToggle = (e: React.MouseEvent<HTMLButtonElement>, reportId: string) => {
    e.stopPropagation();
    if (openDownloadId === reportId) {
      setOpenDownloadId(null);
      setDownloadMenuPos(null);
    } else {
      const rect = e.currentTarget.getBoundingClientRect();
      setDownloadMenuPos({ top: rect.bottom + 4, right: window.innerWidth - rect.right });
      setOpenDownloadId(reportId);
    }
  };

  const handleInfoToggle = (e: React.MouseEvent<HTMLButtonElement>, reportId: string) => {
    e.stopPropagation();
    if (infoPopupId === reportId) {
      setInfoPopupId(null);
      setInfoFiles([]);
    } else {
      setInfoPopupId(reportId);
      setInfoFiles([]);
      fetch(`${API_BASE_URL}/assessment-files/${reportId}`)
        .then(r => r.json())
        .then(data => setInfoFiles(data.files || []))
        .catch(() => setInfoFiles([]));
    }
  };

  const allDepartments = useMemo(() =>
    Array.from(new Set(reports.map(r => r.details?.department).filter(Boolean) as string[])).sort(),
    [reports]
  );

  const filtered = useMemo(() => {
    let list = reports.filter(r => !!r.threat_model);
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
  }, [reports, search, filterDepartment, filterMethodology, filterOutputs, filterDateFrom, filterDateTo, sortField, sortDir]);

  const hasFilters = search || filterDepartment.length || filterMethodology.length || filterOutputs.length || filterDateFrom || filterDateTo;

  const clearFilters = () => {
    setSearch(''); setFilterDepartment([]); setFilterMethodology([]); setFilterOutputs([]); setFilterDateFrom(''); setFilterDateTo('');
  };

  const handleSelect = async (report: ReportMetadata) => {
    setAssessmentId(report.id);
    try {
      await apiService.getStoredThreatModel(report.id);
    } catch { /* best effort */ }
    navigate(`/view-threat-model/${report.id}`);
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

  return (
    <>
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      <div className="px-6 pt-8 pb-16">

        {/* Page header */}
        <div className="mb-6 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-lg bg-[#0052cc] flex items-center justify-center shadow-sm shadow-blue-200 dark:shadow-blue-900/50 flex-shrink-0">
                <svg style={{ width: 16, height: 16 }} fill="none" viewBox="0 0 24 24" stroke="white" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100 tracking-tight">Threat Models</h1>
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-400 ml-10.5">View and manage all security assessments.</p>
          </div>
          {!loading && !error && (
            <div className="text-sm text-slate-500 dark:text-slate-400">
              <span className="font-semibold text-slate-700 dark:text-slate-200">{filtered.length}</span>
              {' '}{filtered.length !== 1 ? 'assessments' : 'assessment'}
              {hasFilters ? ' matched' : ' total'}
            </div>
          )}
        </div>

        {/* Filter bar */}
        <div className="relative z-20 bg-white dark:bg-gray-900/80 backdrop-blur-sm rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm mb-4 px-4 py-3">
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

            {/* TEAM dropdown */}
            <MultiSelectDropdown
              label="TEAM"
              items={allDepartments.map(department => ({ key: department, label: department }))}
              selected={filterDepartment}
              onToggle={key => setFilterDepartment(prev => prev.includes(key) ? prev.filter(l => l !== key) : [...prev, key])}
            />

            {/* Methodology dropdown */}
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

            {/* Completeness dropdown */}
            <MultiSelectDropdown
              label="Completeness"
              items={OUTPUTS.map(o => ({ key: o.key, label: o.label }))}
              selected={filterOutputs}
              onToggle={key => setFilterOutputs(prev => prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key])}
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
          </div>
        </div>

        {/* Table */}
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-visible">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-28">
              <div className="relative w-9 h-9 mb-4">
                <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-800" />
                <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
              </div>
              <p className="text-sm text-slate-400 dark:text-slate-500">Loading assessments...</p>
            </div>
          ) : error || filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-28">
              <div className="w-12 h-12 rounded-xl bg-slate-50 dark:bg-gray-800 border border-slate-200 dark:border-gray-700 flex items-center justify-center mb-3">
                <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                </svg>
              </div>
              <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1">
                {error ? 'No threat models found' : 'No results match your filters'}
              </p>
              {!error && hasFilters && (
                <button onClick={clearFilters} className="text-xs text-[#0052cc] dark:text-blue-400 hover:underline mt-1">Clear filters</button>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 dark:border-gray-800/80">
                    <th className="text-left pl-5 pr-3 py-3.5 text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
                      <button onClick={() => toggleSort('name')} className="flex items-center hover:text-slate-600 dark:hover:text-slate-300 transition-colors">
                        Project <SortIcon field="name" />
                      </button>
                    </th>
                    <th className="text-left px-3 py-3.5 text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider whitespace-nowrap">TEAM</th>
                    <th className="text-left px-3 py-3.5 text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider whitespace-nowrap">Methodology</th>
                    <th className="text-left px-3 py-3.5 text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
                      <button onClick={() => toggleSort('date')} className="flex items-center hover:text-slate-600 dark:hover:text-slate-300 transition-colors">
                        Date <SortIcon field="date" />
                      </button>
                    </th>
                    <th className="text-left px-3 py-3.5 text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider">Completeness</th>
                    <th className="text-left px-3 py-3.5 text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider whitespace-nowrap">Validation</th>
                    <th className="text-right pl-3 pr-5 py-3.5 text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50 dark:divide-gray-800/60">
                  {filtered.map((report, i) => {
                    const projectName = report.details?.projectName ?? report.name;
                    const department = report.details?.department;
                    const methodology = report.details?.threatModelingMethodology;
                    const { relative, full } = formatDate(report.timestamp, timeZone);
                    const present = OUTPUTS.filter(o => o.check(report));
                    const missing = OUTPUTS.filter(o => !o.check(report));
                    const { total: tcTotal, validated: tcValidated } = getTestStats(report);
                    const pct = tcTotal > 0 ? Math.round((tcValidated / tcTotal) * 100) : 0;

                    return (
                      <tr
                        key={report.id}
                        className="group hover:bg-blue-50/40 dark:hover:bg-blue-900/10 transition-colors cursor-pointer"
                        style={{ animation: `fadeIn 0.18s ease ${i * 0.025}s both` }}
                        onClick={() => handleSelect(report)}
                      >
                        {/* Project */}
                        <td className="pl-5 pr-3 py-3.5 relative">
                          <div className="flex items-center gap-2.5 min-w-0">
                            <div className="w-7 h-7 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-100 dark:border-blue-800/40 flex items-center justify-center flex-shrink-0">
                              <svg style={{ width: 13, height: 13 }} fill="none" viewBox="0 0 24 24" stroke="#0052cc" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                              </svg>
                            </div>
                            <div className="min-w-0">
                              <p className="text-[13px] font-semibold text-slate-800 dark:text-slate-200 truncate max-w-[220px] group-hover:text-[#0052cc] dark:group-hover:text-blue-400 transition-colors">
                                {projectName}
                              </p>
                              <p className="text-[11px] text-slate-400 dark:text-slate-500 font-mono mt-0.5">{report.id.slice(0, 8)}…</p>
                            </div>
                          </div>
                          <button
                            title="View Assessment Details"
                            onClick={(e) => handleInfoToggle(e, report.id)}
                            className={`absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded-md transition-all duration-150 ${infoPopupId === report.id ? 'opacity-100 text-[#0052cc] bg-blue-50 dark:bg-blue-900/20 dark:text-blue-400' : 'opacity-0 group-hover:opacity-100 text-slate-400 dark:text-slate-500 hover:text-[#0052cc] hover:bg-blue-50 dark:hover:bg-blue-900/20 dark:hover:text-blue-400'}`}
                          >
                            <svg style={{ width: 13, height: 13 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                          </button>
                        </td>

                        {/* TEAM */}
                        <td className="px-3 py-3.5">
                          {department ? (
                            <span className="inline-block text-[11px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-md bg-slate-100 dark:bg-gray-700/60 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-gray-600/60 whitespace-nowrap">
                              {department}
                            </span>
                          ) : (
                            <span className="text-slate-300 dark:text-slate-600">—</span>
                          )}
                        </td>

                        {/* Methodology */}
                        <td className="px-3 py-3.5">
                          {methodology ? (
                            <span className="inline-block text-xs font-medium px-2 py-0.5 rounded-md bg-blue-50 dark:bg-blue-900/20 text-[#0052cc] dark:text-blue-400 border border-blue-100 dark:border-blue-800/40 whitespace-nowrap">
                              {methodology}
                            </span>
                          ) : (
                            <span className="text-slate-300 dark:text-slate-600">—</span>
                          )}
                        </td>

                        {/* Date */}
                        <td className="px-3 py-3.5">
                          <span title={full} className="text-[13px] text-slate-600 dark:text-slate-400 whitespace-nowrap">
                            {relative}
                          </span>
                        </td>

                        {/* Completeness */}
                        <td className="px-3 py-3.5" onClick={e => e.stopPropagation()}>
                          <div className="flex items-center gap-1 flex-wrap">
                            {present.map(o => (
                              <button
                                key={o.key}
                                title={`Go to ${o.label}`}
                                onClick={() => navigate(ROUTE_MAP[o.key](report.id))}
                                className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-medium border transition-opacity hover:opacity-70 cursor-pointer ${o.color} ${o.borderColor}`}
                              >
                                <span className={`w-1.5 h-1.5 rounded-full ${o.dot} flex-shrink-0`} />
                                {o.short}
                              </button>
                            ))}
                            {missing.map(o => (
                              <span
                                key={o.key}
                                title={`${o.label} — not generated`}
                                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-medium border bg-slate-50 dark:bg-gray-800/60 text-slate-300 dark:text-slate-600 border-slate-100 dark:border-gray-700/60"
                              >
                                <span className="w-1.5 h-1.5 rounded-full bg-slate-200 dark:bg-gray-700 flex-shrink-0" />
                                {o.short}
                              </span>
                            ))}
                          </div>
                        </td>

                        {/* Validation */}
                        <td className="px-3 py-3.5">
                          {tcTotal > 0 ? (
                            pct === 100 ? (
                              <div
                                title="All test cases validated"
                                className="w-7 h-7 rounded-full bg-emerald-100 dark:bg-emerald-900/30 border border-emerald-200 dark:border-emerald-700/50 flex items-center justify-center"
                              >
                                <svg style={{ width: 14, height: 14 }} fill="none" stroke="currentColor" viewBox="0 0 24 24" className="text-emerald-600 dark:text-emerald-400">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                              </div>
                            ) : (
                              <div className="flex items-center gap-2 min-w-[100px]">
                                <div className="flex-1 h-1.5 rounded-full bg-slate-100 dark:bg-gray-700/60 overflow-hidden">
                                  <div
                                    className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-emerald-500 transition-all duration-500"
                                    style={{ width: `${pct}%` }}
                                  />
                                </div>
                                <span className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 w-8 text-right flex-shrink-0">{pct}%</span>
                              </div>
                            )
                          ) : (
                            <span className="text-slate-300 dark:text-slate-600 text-xs">—</span>
                          )}
                        </td>

                        {/* Actions */}
                        <td className="pl-3 pr-5 py-3.5" onClick={e => e.stopPropagation()}>
                          {(() => {
                            const hasThreatModel = OUTPUTS.find(o => o.key === 'threat_model')!.check(report);
                            const hasDread       = OUTPUTS.find(o => o.key === 'dread_assessment')!.check(report);
                            const hasMitigation  = OUTPUTS.find(o => o.key === 'mitigation')!.check(report);
                            const hasAttackTree  = OUTPUTS.find(o => o.key === 'attack_tree')!.check(report);
                            const hasTestCases   = OUTPUTS.find(o => o.key === 'test_cases')!.check(report);
                            const disabledCls = 'text-slate-400 dark:text-slate-500 opacity-40 cursor-not-allowed pointer-events-none';
                            const btn = (enabled: boolean, hover: string) =>
                              `p-1.5 rounded-lg transition-all ${enabled ? `text-slate-400 ${hover}` : disabledCls}`;
                            return (
                          <div className="flex items-center justify-end gap-0.5">

                            {/* Group 1: Threat Model + connecting line + Interactive Mode */}
                            <div className="flex items-center">
                              <button
                                title="View Threat Model"
                                disabled={!hasThreatModel}
                                onClick={(e) => { e.stopPropagation(); handleSelect(report); }}
                                className={btn(hasThreatModel, 'hover:text-[#0052cc] hover:bg-blue-50 dark:hover:bg-blue-900/20 dark:hover:text-blue-400')}
                              >
                                <svg style={{ width: 15, height: 15 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                              </button>
                              <div className="w-4 h-px bg-slate-200 dark:bg-gray-700 mx-0.5 flex-shrink-0" />
                              <button
                                title="Interactive Mode"
                                disabled={!hasThreatModel}
                                onClick={(e) => { e.stopPropagation(); navigate(`/interactive-threat-model/${report.id}`); }}
                                className={btn(hasThreatModel, 'hover:text-indigo-600 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 dark:hover:text-indigo-400')}
                              >
                                <svg style={{ width: 15, height: 15 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M14 10l-2 1m0 0l-2-1m2 1v2.5M20 7l-2 1m2-1l-2-1m2 1v2.5M14 4l-2-1-2 1M4 7l2-1M4 7l2 1M4 7v2.5M12 21l-2-1m2 1l2-1m-2 1v-2.5M6 18l-2-1v-2.5M18 18l2-1v-2.5" />
                                </svg>
                              </button>
                            </div>

                            {/* Separator */}
                            <div className="w-px h-5 bg-slate-200 dark:bg-gray-700 mx-1 flex-shrink-0" />

                            {/* Group 2: Attack Tree, DREAD, Mitigations, Security Test Cases */}
                            <button
                              title="Attack Tree"
                              disabled={!hasAttackTree}
                              onClick={(e) => { e.stopPropagation(); navigate(`/view-attack-tree/${report.id}`); }}
                              className={btn(hasAttackTree, 'hover:text-sky-600 hover:bg-sky-50 dark:hover:bg-sky-900/20 dark:hover:text-sky-400')}
                            >
                              <svg style={{ width: 15, height: 15 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM14 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM9 14v-2M9 14H5M9 14h4M16 14v-2M5 14v4M13 14v4" />
                              </svg>
                            </button>
                            <button
                              title="DREAD Assessment"
                              disabled={!hasDread}
                              onClick={(e) => { e.stopPropagation(); navigate(`/view-dread/${report.id}`); }}
                              className={btn(hasDread, 'hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-900/20 dark:hover:text-amber-400')}
                            >
                              <svg style={{ width: 15, height: 15 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                              </svg>
                            </button>
                            <button
                              title="Mitigations"
                              disabled={!hasMitigation}
                              onClick={(e) => { e.stopPropagation(); navigate(`/view-mitigation/${report.id}`); }}
                              className={btn(hasMitigation, 'hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-900/20 dark:hover:text-rose-400')}
                            >
                              <svg style={{ width: 15, height: 15 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                              </svg>
                            </button>
                            <button
                              title="Security Test Cases"
                              disabled={!hasTestCases}
                              onClick={(e) => { e.stopPropagation(); navigate(`/view-security-test-cases/${report.id}`); }}
                              className={btn(hasTestCases, 'hover:text-violet-600 hover:bg-violet-50 dark:hover:bg-violet-900/20 dark:hover:text-violet-400')}
                            >
                              <svg style={{ width: 15, height: 15 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                              </svg>
                            </button>

                            {/* Separator */}
                            <div className="w-px h-5 bg-slate-200 dark:bg-gray-700 mx-1 flex-shrink-0" />

                            {/* Group 3: Full Report, Chat */}
                            <button
                              disabled={!hasThreatModel}
                              onClick={(e) => { e.stopPropagation(); setAssessmentId(report.id); navigate(`/report/${report.id}`); }}
                              title="View Full Report"
                              className={btn(hasThreatModel, 'hover:text-violet-600 hover:bg-violet-50 dark:hover:bg-violet-900/20 dark:hover:text-violet-400')}
                            >
                              <svg style={{ width: 15, height: 15 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                              </svg>
                            </button>
                            <button
                              disabled={!hasThreatModel}
                              onClick={(e) => { e.stopPropagation(); setAssessmentId(report.id); navigate(`/chat/${report.id}`); }}
                              title="Open Threat Bot"
                              className={btn(hasThreatModel, 'hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-900/20 dark:hover:text-emerald-400')}
                            >
                              <svg style={{ width: 15, height: 15 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
                              </svg>
                            </button>

                            {/* Separator */}
                            <div className="w-px h-5 bg-slate-200 dark:bg-gray-700 mx-1 flex-shrink-0" />

                            {/* Download dropdown */}
                            <button
                              onClick={(e) => handleDownloadToggle(e, report.id)}
                              title="Download"
                              className="p-1.5 text-slate-500 dark:text-slate-300 hover:text-slate-800 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-lg transition-all flex items-center gap-0.5"
                            >
                              <svg style={{ width: 15, height: 15 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                              </svg>
                              <svg style={{ width: 10, height: 10 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M19 9l-7 7-7-7" />
                              </svg>
                            </button>

                          </div>
                          );})()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(5px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>

      {openDownloadId && downloadMenuPos && createPortal(        <>
          <div className="fixed inset-0 z-[9998]" onClick={() => { setOpenDownloadId(null); setDownloadMenuPos(null); }} />
          <div
            style={{ position: 'fixed', top: downloadMenuPos.top, right: downloadMenuPos.right, zIndex: 9999 }}
            className="bg-gray-800 rounded-xl shadow-xl py-1 min-w-[210px] border border-gray-700 overflow-hidden"
          >
            <button
              onClick={() => handleDownload(openDownloadId, 'markdown')}
              className="flex items-center gap-2.5 w-full px-4 py-3 text-sm text-white hover:bg-gray-700 transition-colors text-left"
            >
              <svg style={{ width: 14, height: 14 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Download as Markdown
            </button>
            <button
              onClick={() => handleDownload(openDownloadId, 'json')}
              className="flex items-center gap-2.5 w-full px-4 py-3 text-sm text-white hover:bg-gray-700 transition-colors text-left"
            >
              <svg style={{ width: 14, height: 14 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
              </svg>
              Download as JSON
            </button>
            <button
              onClick={() => handleDownload(openDownloadId, 'pdf')}
              className="flex items-center gap-2.5 w-full px-4 py-3 text-sm text-white hover:bg-gray-700 transition-colors text-left"
            >
              <svg style={{ width: 14, height: 14 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
              </svg>
              Download as PDF (Enriched)
            </button>
            <button
              onClick={() => handleDownload(openDownloadId, 'tmbom')}
              className="flex items-center gap-2.5 w-full px-4 py-3 text-sm text-white hover:bg-gray-700 transition-colors text-left"
            >
              <svg style={{ width: 14, height: 14 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Download TM-BOM
            </button>
          </div>
        </>,
        document.body
      )}

      {infoPopupId && (() => {
        const infoReport = reports.find(r => r.id === infoPopupId);
        if (!infoReport) return null;
        const d = infoReport.details as any;

        const DocRow = ({ label, value, url }: { label: string; value: string | null; url?: string }) => (
          <div className="flex items-start gap-2 py-2 border-b border-slate-100 dark:border-gray-800/60 last:border-0">
            <span className="text-[11px] font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wide w-32 flex-shrink-0 pt-0.5">{label}</span>
            {value ? (
              url ? (
                <a href={url} target="_blank" rel="noopener noreferrer" className="text-xs text-[#0052cc] dark:text-blue-400 hover:underline break-all">{value}</a>
              ) : (
                <span className="text-xs text-slate-700 dark:text-slate-300 break-words">{value}</span>
              )
            ) : (
              <span className="text-xs text-slate-300 dark:text-slate-600 italic">Not provided</span>
            )}
          </div>
        );

        const AdditionalDoc = ({ label, doc }: { label: string; doc: any }) => {
          if (!doc) return (
            <div className="flex items-center gap-2 py-1.5 border-b border-slate-100 dark:border-gray-800/60 last:border-0">
              <span className="text-[11px] font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wide w-36 flex-shrink-0">{label}</span>
              <span className="text-xs text-slate-300 dark:text-slate-600 italic">Not provided</span>
            </div>
          );
          const hasContent = doc.content || doc.title || doc.url;
          return (
            <div className="flex items-start gap-2 py-1.5 border-b border-slate-100 dark:border-gray-800/60 last:border-0">
              <span className="text-[11px] font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wide w-36 flex-shrink-0 pt-0.5">{label}</span>
              {hasContent ? (
                <div className="flex flex-col gap-0.5 min-w-0">
                  {doc.title && <span className="text-xs font-medium text-slate-700 dark:text-slate-300 truncate">{doc.title}</span>}
                  {doc.url && <a href={doc.url} target="_blank" rel="noopener noreferrer" className="text-[11px] text-[#0052cc] dark:text-blue-400 hover:underline truncate">{doc.url}</a>}
                  {!doc.title && !doc.url && <span className="text-xs text-emerald-600 dark:text-emerald-400">Provided</span>}
                </div>
              ) : (
                <span className="text-xs text-slate-300 dark:text-slate-600 italic">Not provided</span>
              )}
            </div>
          );
        };

        const formatFileSize = (bytes: number) => {
          if (bytes < 1024) return `${bytes} B`;
          if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
          return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
        };

        const additionalDocs = d?.additionalDocuments;

        return createPortal(
          <>
            {/* Backdrop */}
            <div
              className="fixed inset-0 z-[9998] bg-black/30 backdrop-blur-[2px]"
              onClick={() => { setInfoPopupId(null); setInfoFiles([]); }}
            />
            {/* Centered modal */}
            <div
              style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', zIndex: 9999, maxHeight: '85vh', width: '420px' }}
              className="bg-white dark:bg-gray-900 border border-slate-200 dark:border-gray-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col"
            >
              {/* Header */}
              <div className="flex items-start gap-3 px-5 py-4 border-b border-slate-100 dark:border-gray-800/60 bg-slate-50/70 dark:bg-gray-800/40 flex-shrink-0">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm">
                  <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-slate-800 dark:text-slate-100 truncate">{d?.projectName || infoReport.name}</p>
                  <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                    {d?.department && (
                      <span className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded bg-slate-200 dark:bg-gray-700 text-slate-600 dark:text-slate-400">{d.department}</span>
                    )}
                    {d?.threatModelingMethodology && (
                      <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-blue-50 dark:bg-blue-900/30 text-[#0052cc] dark:text-blue-400 border border-blue-100 dark:border-blue-800/40">{d.threatModelingMethodology}</span>
                    )}
                    {d?.timestamp && (
                      <span className="text-[10px] text-slate-400 dark:text-slate-500">{new Date(d.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</span>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => { setInfoPopupId(null); setInfoFiles([]); }}
                  className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-gray-700 rounded-lg transition-colors flex-shrink-0"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {/* Scrollable body */}
              <div className="overflow-y-auto flex-1 px-5 py-4 space-y-5">

                {/* Project */}
                <div>
                  <p className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-2.5 flex items-center gap-1.5">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
                    Project
                  </p>
                  <DocRow label="SecReview ID" value={d?.queue?.secreview_id || null} url={d?.queue?.secreview_id && process.env.REACT_APP_JIRA_BASE_URL ? `${process.env.REACT_APP_JIRA_BASE_URL}${d.queue.secreview_id}` : undefined} />
                  <DocRow label="Name" value={d?.projectName || null} />
                  <DocRow label="Description" value={d?.description || null} />
                  <DocRow label="App Type" value={d?.applicationType || null} />
                </div>

                {/* Divider */}
                <div className="h-px bg-slate-100 dark:bg-gray-800/60" />

                {/* Security Configuration */}
                <div>
                  <p className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-2.5 flex items-center gap-1.5">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                    Security Configuration
                  </p>
                  <div className="flex items-center gap-2 py-2 border-b border-slate-100 dark:border-gray-800/60">
                    <span className="text-[11px] font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wide w-32 flex-shrink-0">Internet Facing</span>
                    {d?.isInternetFacing != null ? (
                      <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-semibold ${d.isInternetFacing ? 'bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800/40' : 'bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800/40'}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${d.isInternetFacing ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                        {d.isInternetFacing ? 'Yes' : 'No'}
                      </span>
                    ) : (
                      <span className="text-xs text-slate-300 dark:text-slate-600 italic">Not specified</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 py-2 border-b border-slate-100 dark:border-gray-800/60">
                    <span className="text-[11px] font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wide w-32 flex-shrink-0">Data Sensitivity</span>
                    {d?.dataSensitivityLevel ? (
                      <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-semibold border ${
                        d.dataSensitivityLevel === 'Highest' ? 'bg-red-50 text-red-700 border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800/40' :
                        d.dataSensitivityLevel === 'High' ? 'bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-900/20 dark:text-orange-400 dark:border-orange-800/40' :
                        d.dataSensitivityLevel === 'Medium' ? 'bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-900/20 dark:text-yellow-400 dark:border-yellow-800/40' :
                        'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800/40'
                      }`}>{d.dataSensitivityLevel}</span>
                    ) : (
                      <span className="text-xs text-slate-300 dark:text-slate-600 italic">Not specified</span>
                    )}
                  </div>
                  <DocRow label="Auth Method" value={d?.authenticationMethod || null} />
                  <DocRow label="Methodology" value={d?.threatModelingMethodology || null} />
                </div>

                {/* Divider */}
                <div className="h-px bg-slate-100 dark:bg-gray-800/60" />

                {/* Documents */}
                <div>
                  <p className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-2.5 flex items-center gap-1.5">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                    Documents
                  </p>
                  <div className="flex items-center gap-2 py-2 border-b border-slate-100 dark:border-gray-800/60">
                    <span className="text-[11px] font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wide w-32 flex-shrink-0">Source</span>
                    {d?.source === 'queue' ? (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-semibold bg-violet-50 dark:bg-violet-900/20 text-violet-700 dark:text-violet-400 border border-violet-200 dark:border-violet-800/40">
                        <svg style={{ width: 10, height: 10 }} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" /></svg>
                        SecOps Portal
                      </span>
                    ) : d?.documentSource ? (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-semibold bg-slate-100 dark:bg-gray-700/60 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-gray-600/60">
                        {d.documentSource === 'pdf' ? (
                          <>
                            <svg style={{ width: 10, height: 10 }} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" /></svg>
                            PDF Upload
                          </>
                        ) : (
                          <>
                            <svg style={{ width: 10, height: 10 }} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>
                            {d.documentSource}
                          </>
                        )}
                      </span>
                    ) : (
                      <span className="text-xs text-slate-300 dark:text-slate-600 italic">Not specified</span>
                    )}
                  </div>
                  {d?.confluenceUrl && (
                    <DocRow label="Confluence URL" value={d.confluenceUrl} url={d.confluenceUrl} />
                  )}

                  {/* Uploaded files */}
                  {infoFiles.length > 0 && (
                    <div className="mt-3">
                      <p className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-2">Uploaded Files</p>
                      <div className="space-y-1.5">
                        {infoFiles.map(file => (
                          <div key={file.name} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-50 dark:bg-gray-800/50 border border-slate-100 dark:border-gray-700/60">
                            <div className="w-6 h-6 rounded bg-red-50 dark:bg-red-900/20 border border-red-100 dark:border-red-800/40 flex items-center justify-center flex-shrink-0">
                              <svg style={{ width: 11, height: 11 }} className="text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                              </svg>
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="text-xs font-medium text-slate-700 dark:text-slate-300 truncate">{file.name}</p>
                              <p className="text-[10px] text-slate-400 dark:text-slate-500">{formatFileSize(file.size)}</p>
                            </div>
                            <a
                              href={`${API_BASE_URL}/download-assessment-file/${infoReport.id}/${encodeURIComponent(file.name)}`}
                              download={file.name}
                              onClick={e => e.stopPropagation()}
                              className="p-1.5 text-slate-400 hover:text-[#0052cc] dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-md transition-all flex-shrink-0"
                              title={`Download ${file.name}`}
                            >
                              <svg style={{ width: 13, height: 13 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                              </svg>
                            </a>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Additional Documents */}
                  {additionalDocs && (
                    <div className="mt-3">
                      <p className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-1.5">Additional Documents</p>
                      <AdditionalDoc label="Confluence Doc" doc={additionalDocs.confluenceDoc} />
                      <AdditionalDoc label="Slack Thread" doc={additionalDocs.slackThread} />
                      <AdditionalDoc label="Meeting Transcript" doc={additionalDocs.meetingTranscript} />
                    </div>
                  )}
                </div>

              </div>

              {/* Footer */}
              <div className="px-5 py-3 border-t border-slate-100 dark:border-gray-800/60 bg-slate-50/70 dark:bg-gray-800/30 flex-shrink-0 flex items-center justify-between">
                <p className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">{infoReport.id}</p>
                <button
                  onClick={() => { setInfoPopupId(null); setInfoFiles([]); }}
                  className="text-xs text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </>,
          document.body
        );
      })()}
    </>
  );
};

export default ThreatModelList;
