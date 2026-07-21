import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import { useAssessment } from '../context/AssessmentContext';

interface DreadScores {
  damage: number;
  reproducibility: number;
  exploitability: number;
  affected_users: number;
  discoverability: number;
  average: number;
  priority: 'Critical' | 'High' | 'Moderate' | 'Low';
}

interface TestCase {
  description: string;
  steps: string[];
  expected_result: string;
  validated: boolean;
}

interface Threat {
  id: string;
  type: string;
  scenario: string;
  potential_impact: string;
  confidence: string;
  business_risk_type?: string;
  pasta_stage?: string;
  dread_scores?: DreadScores;
  mitigations: string[];
  test_cases: TestCase[];
}

interface TmBomData {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  metadata: {
    timestamp: string;
    assessment_id: string;
    project_name: string;
    lob: string;
    methodology: string;
    app_type: string;
    created_by: string;
    internet_facing: boolean;
    authentication: string;
    sensitive_data: string;
  };
  threats: Threat[];
  attack_tree: string;
  improvement_suggestions: string[];
  summary: {
    total_threats: number;
    critical_risk: number;
    high_risk: number;
    moderate_risk: number;
    low_risk: number;
    total_mitigations: number;
    total_test_cases: number;
    validated_test_cases: number;
  };
}

const DREAD_KEYS = ['damage', 'reproducibility', 'exploitability', 'affected_users', 'discoverability'] as const;
const DREAD_LABELS = ['D', 'R', 'E', 'A', 'D'];

function dreadColor(score: number) {
  if (score >= 9) return 'text-red-900 dark:text-red-300';
  if (score >= 8) return 'text-red-600 dark:text-red-400';
  if (score >= 4) return 'text-amber-600 dark:text-amber-400';
  return 'text-emerald-500 dark:text-emerald-400';
}

function dreadBarColor(score: number) {
  if (score >= 9) return 'bg-red-900';
  if (score >= 8) return 'bg-red-500';
  if (score >= 4) return 'bg-amber-500';
  return 'bg-emerald-400';
}

function priorityBadge(priority: string) {
  if (priority === 'Critical') return 'bg-red-900/10 text-red-900 dark:text-red-300 border-red-300 dark:border-red-800/50 ring-1 ring-red-900/20 dark:ring-red-400/20';
  if (priority === 'High') return 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800/40 ring-1 ring-red-400/20';
  if (priority === 'Moderate') return 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-800/40 ring-1 ring-amber-400/20';
  return 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/40 ring-1 ring-emerald-400/20';
}

function threatTypeBadge(type: string) {
  const map: Record<string, string> = {
    Spoofing: 'bg-violet-500/10 text-violet-600 dark:text-violet-400 border-violet-200 dark:border-violet-800/40',
    Tampering: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-200 dark:border-orange-800/40',
    Repudiation: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800/40',
    'Information Disclosure': 'bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-200 dark:border-sky-800/40',
    'Denial of Service': 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800/40',
    'Elevation of Privilege': 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/40',
  };
  return map[type] ?? 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700';
}

function confidenceDot(conf: string) {
  if (conf === 'High') return 'bg-red-400';
  if (conf === 'Medium') return 'bg-amber-400';
  return 'bg-emerald-400';
}

export default function TmBom() {
  const { assessment_id } = useParams<{ assessment_id: string }>();
  const navigate = useNavigate();
  const [data, setData] = useState<TmBomData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedThreats, setExpandedThreats] = useState<Set<string>>(new Set());
  const [downloading, setDownloading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [suggestionsOpen, setSuggestionsOpen] = useState(false);
  const [whatIsOpen, setWhatIsOpen] = useState(false);
  const [notGenerated, setNotGenerated] = useState(false);
  const { setAssessmentId } = useAssessment();

  useEffect(() => {
    if (!assessment_id) return;
    setAssessmentId(assessment_id);
    setLoading(true);
    setNotGenerated(false);
    setError(null);
    apiService.getTmBom(assessment_id)
      .then(setData)
      .catch((e: any) => {
        if (e.notGenerated) {
          setNotGenerated(true);
        } else {
          setError(e.message);
        }
      })
      .finally(() => setLoading(false));
  }, [assessment_id]);

  const handleGenerate = async () => {
    if (!assessment_id) return;
    setGenerating(true);
    setError(null);
    try {
      const result = await apiService.generateTmBom(assessment_id);
      setData(result);
      setNotGenerated(false);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setGenerating(false);
    }
  };

  const toggleThreat = (id: string) => {
    setExpandedThreats(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const handleDownload = async () => {
    if (!assessment_id) return;
    setDownloading(true);
    try {
      const blob = await apiService.downloadTmBom(assessment_id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `tmbom-${assessment_id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      alert(`Download failed: ${e.message}`);
    } finally {
      setDownloading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-transparent">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-12 h-12">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-200 dark:border-cyan-900" />
            <div className="absolute inset-0 rounded-full border-2 border-t-cyan-500 animate-spin" />
          </div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400 tracking-wide">Assembling TM-BOM…</p>
        </div>
      </div>
    );
  }

  if (notGenerated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-transparent">
        <div className="text-center max-w-md px-6">
          <div className="w-16 h-16 rounded-2xl bg-cyan-50 dark:bg-cyan-950/30 border border-cyan-100 dark:border-cyan-900/40 flex items-center justify-center mx-auto mb-5">
            <svg className="w-8 h-8 text-cyan-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <h2 className="text-lg font-bold text-slate-800 dark:text-slate-100 mb-2">TM-BOM Not Generated</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed mb-6">
            A Threat Model Bill of Materials hasn't been generated for this assessment yet.
            Generate one to get a structured inventory of all threats, DREAD scores, mitigations, and ASVS test cases.
          </p>
          {error && (
            <p className="text-xs text-red-500 dark:text-red-400 mb-4 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/30 rounded-lg px-3 py-2">{error}</p>
          )}
          <div className="flex items-center justify-center gap-3">
            <button
              onClick={() => navigate(-1)}
              className="px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 transition-colors"
            >
              ← Go back
            </button>
            <button
              onClick={handleGenerate}
              disabled={generating}
              className="flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-60 text-white text-sm font-semibold rounded-lg transition-colors shadow-sm shadow-cyan-900/20"
            >
              {generating ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin" />
                  Generating…
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Generate TM-BOM
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-transparent">
        <div className="text-center max-w-md">
          <div className="w-12 h-12 rounded-full bg-red-50 dark:bg-red-950/30 flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <p className="text-sm font-medium text-red-600 dark:text-red-400 mb-1">Failed to load TM-BOM</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-5">{error || 'Data unavailable for this assessment'}</p>
          <button onClick={() => navigate(-1)} className="text-sm font-medium text-cyan-600 dark:text-cyan-400 hover:underline">
            ← Go back
          </button>
        </div>
      </div>
    );
  }

  const { metadata, threats, summary, improvement_suggestions } = data;
  const coveragePercent = summary.total_test_cases > 0
    ? Math.round((summary.validated_test_cases / summary.total_test_cases) * 100)
    : 0;

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">

      {/* Top bar */}
      <div className="sticky top-0 z-30 bg-white/90 dark:bg-[#0d1f38]/90 backdrop-blur-md border-b border-slate-200 dark:border-white/5">
        <div className="px-6 lg:px-8 xl:px-10 py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-3 min-w-0">
            <button
              onClick={() => navigate(`/view-threat-model/${assessment_id}`)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-white/5 transition-colors shrink-0"
              title="Back to threat model"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
            </button>
            <div className="h-4 w-px bg-slate-200 dark:bg-white/10 shrink-0" />
            <div className="flex items-center gap-2 min-w-0">
              <span className="text-xs font-mono text-slate-400 dark:text-slate-500 shrink-0">TM-BOM</span>
              <span className="text-slate-300 dark:text-slate-600 shrink-0">·</span>
              <span className="text-sm font-semibold text-slate-700 dark:text-slate-200 truncate">{metadata.project_name}</span>
              {metadata.lob && (
                <span className="hidden sm:inline-flex px-2 py-0.5 rounded-md text-xs bg-slate-100 dark:bg-white/5 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-white/10 shrink-0">
                  {metadata.lob}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 ml-4">
            <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-100 dark:bg-white/5 border border-slate-200 dark:border-white/10">
              <span className="text-xs text-slate-400 dark:text-slate-500 font-mono">{data.bomFormat}</span>
              <span className="text-slate-300 dark:text-slate-600">·</span>
              <span className="text-xs text-slate-400 dark:text-slate-500 font-mono">v{data.specVersion}</span>
              <span className="text-slate-300 dark:text-slate-600">·</span>
              <span className="text-xs text-slate-400 dark:text-slate-500 font-mono">OWASP</span>
            </div>
            <button
              onClick={handleDownload}
              disabled={downloading}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-60 text-white text-xs font-semibold rounded-lg transition-colors shadow-sm shadow-cyan-900/20"
            >
              {downloading ? (
                <div className="w-3.5 h-3.5 border-2 border-white/40 border-t-white rounded-full animate-spin" />
              ) : (
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
              )}
              Download JSON
            </button>
          </div>
        </div>
      </div>

      <div className="px-6 lg:px-8 xl:px-10 py-8 space-y-6">

        {/* Page title + methodology badge */}
        <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
          <div>
            <h1 className="text-2xl lg:text-3xl font-bold text-slate-900 dark:text-slate-50 tracking-tight">
              Threat Model Bill of Materials
            </h1>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              Complete threat inventory with DREAD scores, mitigations, and ASVS test cases.
            </p>
          </div>
          <span className="self-start sm:self-auto px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border border-cyan-200 dark:border-cyan-800/50">
            {metadata.methodology}
          </span>
        </div>

        {/* What is a TM-BOM — collapsible */}
        <div className="rounded-xl border border-cyan-200/80 dark:border-cyan-800/30 bg-cyan-50/60 dark:bg-cyan-950/10 overflow-hidden">
          <button
            onClick={() => setWhatIsOpen(o => !o)}
            className="w-full flex items-center justify-between px-5 py-3.5 text-left group"
          >
            <div className="flex items-center gap-2.5">
              <svg className="w-4 h-4 text-cyan-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span className="text-sm font-semibold text-cyan-700 dark:text-cyan-300">What is a TM-BOM?</span>
            </div>
            <svg className={`w-4 h-4 text-cyan-400 transition-transform duration-200 ${whatIsOpen ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {whatIsOpen && (
            <div className="px-5 pb-5 border-t border-cyan-200/60 dark:border-cyan-800/30">
              <div className="pt-4 grid md:grid-cols-2 gap-6 text-sm text-slate-700 dark:text-slate-300">
                <div className="space-y-3 leading-relaxed">
                  <p>
                    A <strong className="text-slate-900 dark:text-slate-100">Threat Model Bill of Materials (TM-BOM)</strong> is a structured, machine-readable document that packages all threat modeling artifacts for a system into a single standardized file — inspired by the <span className="font-medium text-slate-800 dark:text-slate-200">CycloneDX</span> BOM standard and aligned with <span className="font-medium text-slate-800 dark:text-slate-200">OWASP</span> threat modeling principles.
                  </p>
                  <p>
                    Just as a Software BOM (SBOM) inventories every dependency in your codebase, a TM-BOM inventories every <em>threat</em> your system faces — along with how each one is scored, mitigated, and tested.
                  </p>
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-widest text-slate-400 dark:text-slate-500 mb-3">What's inside this TM-BOM</p>
                  <div className="space-y-2">
                    {[
                      ['THREAT-NNN IDs', 'Stable OWASP-style identifiers for every threat'],
                      ['DREAD Scores', 'Damage · Reproducibility · Exploitability · Affected Users · Discoverability'],
                      ['Mitigations', 'Recommended controls cross-linked per threat'],
                      ['ASVS Test Cases', 'Verification steps with validation status'],
                      ['Attack Tree', 'Mermaid diagram of attack paths'],
                      ['Improvement Suggestions', 'Architecture-level recommendations'],
                    ].map(([term, desc]) => (
                      <div key={term} className="flex gap-2.5">
                        <span className="text-cyan-500 mt-0.5 shrink-0 text-xs">▸</span>
                        <span className="text-sm"><strong className="font-semibold text-slate-700 dark:text-slate-200">{term}</strong> <span className="text-slate-500 dark:text-slate-400">— {desc}</span></span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Metadata + summary row */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">

          {/* Metadata card */}
          <div className="xl:col-span-2 bg-white dark:bg-gray-900/60 rounded-xl border border-slate-200 dark:border-white/5 shadow-sm p-5">
            <p className="text-xs font-semibold uppercase tracking-widest text-slate-400 dark:text-slate-500 mb-4">Assessment Details</p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-4">
              <MetaField label="App Type" value={metadata.app_type} />
              <MetaField label="Created By" value={metadata.created_by} />
              <MetaField label="Internet Facing" value={metadata.internet_facing ? 'Yes' : 'No'} />
              <MetaField
                label="Generated"
                value={new Date(metadata.timestamp).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}
              />
              {metadata.authentication && <MetaField label="Authentication" value={metadata.authentication} />}
              {metadata.sensitive_data && <MetaField label="Sensitive Data" value={metadata.sensitive_data} />}
            </div>
          </div>

          {/* Summary stats */}
          <div className="grid grid-cols-2 gap-3">
            <StatCard
              label="Total Threats"
              value={summary.total_threats}
              sub={`${summary.total_mitigations} mitigations`}
              valueClass="text-slate-800 dark:text-slate-100"
            />
            <CriticalHighCard
              critical={summary.critical_risk ?? 0}
              high={summary.high_risk}
            />
            <StatCard
              label="Test Cases"
              value={summary.total_test_cases}
              sub={`${summary.validated_test_cases} validated`}
              valueClass="text-slate-800 dark:text-slate-100"
            />
            <StatCard
              label="Coverage"
              value={`${coveragePercent}%`}
              sub="ASVS test coverage"
              valueClass="text-cyan-600 dark:text-cyan-400"
              accent="bg-cyan-50 dark:bg-cyan-950/20 border-cyan-100 dark:border-cyan-900/30"
            />
          </div>
        </div>

        {/* Threat inventory */}
        <div className="bg-white dark:bg-gray-900/60 rounded-xl border border-slate-200 dark:border-white/5 shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-100 dark:border-white/5 flex items-center justify-between bg-slate-50/50 dark:bg-white/[0.02]">
            <div>
              <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Threat Inventory</h2>
              <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{threats.length} threats identified · click any row to expand</p>
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-400 dark:text-slate-500">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-900 inline-block" />Critical</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500 inline-block" />High</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-500 inline-block" />Moderate</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />Low</span>
            </div>
          </div>

          {/* Column headers */}
          <div className="hidden lg:grid grid-cols-12 gap-2 px-6 py-2.5 bg-slate-50 dark:bg-white/[0.02] text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest border-b border-slate-100 dark:border-white/5">
            <div className="col-span-1">ID</div>
            <div className="col-span-2">Type</div>
            <div className="col-span-4">Scenario</div>
            <div className="col-span-1 text-center">DREAD</div>
            <div className="col-span-1 text-center">Risk</div>
            <div className="col-span-1 text-center">Conf.</div>
            <div className="col-span-1 text-center">Mits.</div>
            <div className="col-span-1 text-center">Tests</div>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-white/[0.04]">
            {threats.map(threat => {
              const expanded = expandedThreats.has(threat.id);
              const dread = threat.dread_scores;
              return (
                <div key={threat.id} className={expanded ? 'bg-slate-50/80 dark:bg-white/[0.02]' : ''}>
                  <button
                    onClick={() => toggleThreat(threat.id)}
                    className="w-full text-left hover:bg-slate-50 dark:hover:bg-white/[0.025] transition-colors duration-100"
                  >
                    {/* Desktop row */}
                    <div className="hidden lg:grid grid-cols-12 gap-2 px-6 py-3.5 items-center">
                      <div className="col-span-1 font-mono text-[11px] text-slate-400 dark:text-slate-500 font-medium">{threat.id}</div>
                      <div className="col-span-2">
                        <span className={`inline-flex px-2 py-0.5 rounded-md text-[11px] font-medium border ${threatTypeBadge(threat.type)}`}>
                          {threat.type}
                        </span>
                      </div>
                      <div className="col-span-4 text-sm text-slate-700 dark:text-slate-300 leading-snug line-clamp-2 pr-2">{threat.scenario}</div>
                      <div className="col-span-1 text-center">
                        {dread ? (
                          <span className={`text-sm font-bold tabular-nums ${dreadColor(dread.average)}`}>
                            {dread.average.toFixed(1)}
                          </span>
                        ) : <span className="text-xs text-slate-300 dark:text-slate-600">—</span>}
                      </div>
                      <div className="col-span-1 text-center">
                        {dread ? (
                          <span className={`inline-flex px-2 py-0.5 rounded-md text-[10px] font-bold border ${priorityBadge(dread.priority)}`}>
                            {dread.priority}
                          </span>
                        ) : <span className="text-xs text-slate-300 dark:text-slate-600">—</span>}
                      </div>
                      <div className="col-span-1 flex justify-center">
                        <span className={`w-2 h-2 rounded-full mt-0.5 ${confidenceDot(threat.confidence)}`} title={threat.confidence} />
                      </div>
                      <div className="col-span-1 text-center text-sm font-medium text-slate-600 dark:text-slate-400 tabular-nums">
                        {threat.mitigations.length}
                      </div>
                      <div className="col-span-1 text-center text-sm font-medium text-slate-600 dark:text-slate-400 tabular-nums">
                        {threat.test_cases.length}
                      </div>
                    </div>

                    {/* Mobile row */}
                    <div className="lg:hidden px-5 py-4 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[11px] text-slate-400 dark:text-slate-500">{threat.id}</span>
                        <span className={`inline-flex px-2 py-0.5 rounded-md text-[11px] font-medium border ${threatTypeBadge(threat.type)}`}>
                          {threat.type}
                        </span>
                        {dread && (
                          <span className={`inline-flex px-2 py-0.5 rounded-md text-[10px] font-bold border ${priorityBadge(dread.priority)}`}>
                            {dread.priority}
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-slate-700 dark:text-slate-300 leading-snug">{threat.scenario}</p>
                    </div>
                  </button>

                  {expanded && (
                    <div className="px-6 pb-6 border-t border-slate-100 dark:border-white/[0.06] bg-slate-50/60 dark:bg-white/[0.015]">
                      <div className="pt-5 grid lg:grid-cols-3 gap-6">

                        {/* Impact + DREAD */}
                        <div className="space-y-5">
                          <div>
                            <SectionLabel>Potential Impact</SectionLabel>
                            <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed mt-1.5">{threat.potential_impact}</p>
                          </div>
                          {threat.pasta_stage && (
                            <div>
                              <SectionLabel>PASTA Stage</SectionLabel>
                              <p className="text-sm text-slate-700 dark:text-slate-300 mt-1.5">{threat.pasta_stage}</p>
                            </div>
                          )}
                          {threat.business_risk_type && (
                            <div>
                              <SectionLabel>Business Risk Type</SectionLabel>
                              <p className="text-sm text-slate-700 dark:text-slate-300 mt-1.5">{threat.business_risk_type}</p>
                            </div>
                          )}
                          {dread && (
                            <div>
                              <SectionLabel>DREAD Breakdown</SectionLabel>
                              <div className="mt-2 grid grid-cols-5 gap-2">
                                {DREAD_KEYS.map((k, i) => (
                                  <div key={k} className="flex flex-col items-center gap-1">
                                    <div className="w-full bg-slate-200 dark:bg-white/10 rounded-full h-1.5 overflow-hidden">
                                      <div
                                        className={`h-full rounded-full transition-all ${dreadBarColor(dread[k])}`}
                                        style={{ width: `${dread[k] * 10}%` }}
                                      />
                                    </div>
                                    <span className={`text-[11px] font-bold tabular-nums ${dreadColor(dread[k])}`}>{dread[k]}</span>
                                    <span className="text-[9px] font-bold text-slate-400 dark:text-slate-500 uppercase">{DREAD_LABELS[i]}</span>
                                  </div>
                                ))}
                              </div>
                              <div className="mt-2 flex items-center justify-end gap-2">
                                <span className="text-xs text-slate-400 dark:text-slate-500">Average</span>
                                <span className={`text-sm font-bold tabular-nums ${dreadColor(dread.average)}`}>{dread.average.toFixed(1)}</span>
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Mitigations */}
                        <div>
                          <SectionLabel>Mitigations ({threat.mitigations.length})</SectionLabel>
                          {threat.mitigations.length > 0 ? (
                            <ul className="mt-2 space-y-2">
                              {threat.mitigations.map((m, i) => (
                                <li key={i} className="flex gap-2.5 text-sm">
                                  <span className="text-cyan-500 shrink-0 mt-0.5 text-xs font-bold">›</span>
                                  <span className="text-slate-700 dark:text-slate-300 leading-snug">{m}</span>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="text-xs text-slate-400 dark:text-slate-500 mt-2">No mitigations recorded.</p>
                          )}
                        </div>

                        {/* Test Cases */}
                        <div>
                          <SectionLabel>
                            ASVS Test Cases ({threat.test_cases.filter(tc => tc.validated).length}/{threat.test_cases.length} validated)
                          </SectionLabel>
                          {threat.test_cases.length > 0 ? (
                            <ul className="mt-2 space-y-2">
                              {threat.test_cases.map((tc, i) => (
                                <li
                                  key={i}
                                  className={`rounded-lg px-3.5 py-3 border text-sm leading-snug ${
                                    tc.validated
                                      ? 'bg-emerald-50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900/30'
                                      : 'bg-white dark:bg-gray-900/40 border-slate-200 dark:border-white/5'
                                  }`}
                                >
                                  <div className="flex items-start gap-2">
                                    {tc.validated ? (
                                      <svg className="w-3.5 h-3.5 text-emerald-500 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                                      </svg>
                                    ) : (
                                      <span className="w-3.5 h-3.5 mt-0.5 shrink-0 flex items-center justify-center">
                                        <span className="w-1.5 h-1.5 rounded-full bg-slate-300 dark:bg-slate-600" />
                                      </span>
                                    )}
                                    <span className="text-slate-700 dark:text-slate-300">{tc.description}</span>
                                  </div>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="text-xs text-slate-400 dark:text-slate-500 mt-2">No test cases recorded.</p>
                          )}
                        </div>

                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Improvement Suggestions */}
        {improvement_suggestions.length > 0 && (
          <div className="bg-white dark:bg-gray-900/60 rounded-xl border border-slate-200 dark:border-white/5 shadow-sm overflow-hidden">
            <button
              onClick={() => setSuggestionsOpen(o => !o)}
              className="w-full flex items-center justify-between px-6 py-4 text-left hover:bg-slate-50 dark:hover:bg-white/[0.02] transition-colors"
            >
              <div>
                <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Improvement Suggestions</h2>
                <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{improvement_suggestions.length} architecture-level recommendations</p>
              </div>
              <svg className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${suggestionsOpen ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {suggestionsOpen && (
              <div className="px-6 pb-6 border-t border-slate-100 dark:border-white/[0.04]">
                <ol className="mt-4 space-y-3">
                  {improvement_suggestions.map((s, i) => (
                    <li key={i} className="flex gap-3 text-sm">
                      <span className="text-slate-300 dark:text-slate-600 shrink-0 font-mono tabular-nums pt-0.5">{String(i + 1).padStart(2, '0')}.</span>
                      <span className="text-slate-700 dark:text-slate-300 leading-relaxed">{s}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between pt-2 pb-6 text-xs text-slate-400 dark:text-slate-600">
          <span className="font-mono">{data.serialNumber}</span>
          <span>{data.bomFormat} · v{data.specVersion} · OWASP</span>
        </div>

      </div>
    </div>
  );
}

function MetaField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500 mb-1">{label}</p>
      <p className="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">{value || '—'}</p>
    </div>
  );
}

function StatCard({
  label, value, sub, valueClass, accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  valueClass: string;
  accent?: string;
}) {
  return (
    <div className={`rounded-xl border shadow-sm p-4 ${accent ?? 'bg-white dark:bg-gray-900/60 border-slate-200 dark:border-white/5'}`}>
      <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500 mb-2">{label}</p>
      <p className={`text-3xl font-bold tabular-nums leading-none ${valueClass}`}>{value}</p>
      {sub && <p className="text-xs text-slate-400 dark:text-slate-500 mt-1.5">{sub}</p>}
    </div>
  );
}

function CriticalHighCard({ critical, high }: { critical: number; high: number }) {
  return (
    <div className="rounded-xl border shadow-sm p-4 bg-red-50 dark:bg-red-950/20 border-red-100 dark:border-red-900/30">
      <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500 mb-2">Critical / High</p>
      <div className="flex items-baseline gap-2">
        <span className="text-3xl font-bold tabular-nums leading-none text-red-900 dark:text-red-300">{critical}</span>
        <span className="text-xs text-slate-400 dark:text-slate-500 font-medium">critical</span>
        <span className="text-slate-300 dark:text-slate-600">·</span>
        <span className="text-3xl font-bold tabular-nums leading-none text-red-600 dark:text-red-400">{high}</span>
        <span className="text-xs text-slate-400 dark:text-slate-500 font-medium">high</span>
      </div>
      <p className="text-xs text-slate-400 dark:text-slate-500 mt-1.5">DREAD avg ≥ 9 / ≥ 8</p>
    </div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500">{children}</p>
  );
}
