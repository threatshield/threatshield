import React, { useEffect, useState, useMemo, memo, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate, useParams, Link } from 'react-router-dom';
import ReactFlow, {
  MiniMap, Controls, Background,
  useNodesState, useEdgesState,
  MarkerType, Handle, Position,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { API_BASE_URL } from '../services/api';
import {
  AssessmentData,
  isPastaAssessment,
  consolidateThreats,
  computeDreadScore,
  getDepartmentColors,
  formatDate,
} from '../utils/threatConsolidation';
import { consolidateDiagramNodes } from '../utils/diagramConsolidation';

// ── Helpers ───────────────────────────────────────────────────────────────────

const TYPE_PALETTE = ['#6366f1', '#f97316', '#eab308', '#0ea5e9', '#ef4444', '#f43f5e', '#8b5cf6', '#10b981', '#64748b'];

const STRIDE_ORDER  = ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'];
const PASTA_ORDER   = ['Financial', 'Regulatory', 'Operational', 'Reputational'];
const PASTA_PALETTE = ['#8b5cf6', '#6366f1', '#0ea5e9', '#10b981'];

const NO_DATA_SIGNALS   = ['cannot identify', 'insufficient context', 'no specific application', 'must inform you', 'without access to', 'no context provided', 'cannot complete', 'i must be transparent'];
const DOC_REQUEST_WORDS = ['document', 'diagram', 'source code', 'confluence', 'specification', 'repository', 'artifact', 'codebase'];

function extractVendorNames(text: string): string[] {
  if (!text) return [];
  const lower = text.toLowerCase().slice(0, 600);
  if (NO_DATA_SIGNALS.some(s => lower.includes(s))) return [];

  // Primary: ## 1. **Name** (desc)  |  ## 1. Name (desc)  |  ## 1. **Name (desc)**  |  ## 1. Name
  // Requires digit+dot after ##, so section headings like "## Summary Table" are never matched.
  const headings = [...text.matchAll(/^##\s+\d+\.\s+(.+)$/gm)]
    .map(m => m[1]
      .replace(/\*+/g, '')           // strip bold markers
      .replace(/\s*\([^)]*\)\s*$/, '') // strip trailing (description)
      .replace(/:$/, '')             // strip trailing colon
      .trim()
    )
    .filter(name => {
      if (!name || name.length > 80 || name.length < 2) return false;
      const n = name.toLowerCase();
      return !DOC_REQUEST_WORDS.some(w => n.includes(w));
    });
  if (headings.length > 0) return headings;

  // Fallback: table rows — | **Name** | ServiceName |
  return [...text.matchAll(/\|\s*\*{0,2}Name(?:\s+of\s+(?:the\s+)?(?:third[-\s]party\s+)?(?:service|integration))?\*{0,2}\s*\|\s*([^|*\n]{2,60})/g)]
    .map(m => m[1].trim())
    .filter(name => name.length > 1 && !name.startsWith('-'));
}

// ── Stat Table Card ───────────────────────────────────────────────────────────

interface StatEntry { label: string; value: number; color: string; dimmed?: boolean; }

const StatTableCard: React.FC<{ title: string; entries: StatEntry[]; badge?: string }> = ({ title, entries, badge }) => (
  <div className="bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl shadow-sm p-5">
    <div className="flex items-center justify-between mb-4">
      <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300">{title}</h3>
      {badge && (
        <span className="text-xs font-bold text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-gray-800 px-2 py-0.5 rounded-full">
          {badge}
        </span>
      )}
    </div>
    <div className="flex">
      {entries.map(({ label, value, color, dimmed }) => (
        <div
          key={label}
          className={`flex-1 min-w-0 flex flex-col items-center px-1.5 py-2 border-r border-slate-100 dark:border-gray-800/60 last:border-r-0 transition-opacity ${dimmed ? 'opacity-35' : ''}`}
        >
          <div className="w-1.5 h-1.5 rounded-full mb-1.5 flex-shrink-0" style={{ backgroundColor: color }} />
          <span className="text-xl font-bold leading-none mb-1.5" style={{ color }}>{value}</span>
          <span className="text-[10px] font-medium text-slate-500 dark:text-slate-400 text-center leading-tight w-full break-words hyphens-auto">
            {label}
          </span>
        </div>
      ))}
    </div>
  </div>
);

// ── Threat Type Table Card ────────────────────────────────────────────────────

const ThreatTypeTableCard: React.FC<{
  threatsByType: Array<[string, number]>;
  total: number;
  title?: string;
  methodology?: 'STRIDE' | 'PASTA';
}> = ({ threatsByType, total, title = 'Threats by Type', methodology = 'STRIDE' }) => {
  const countMap = new Map(threatsByType);
  const order    = methodology === 'PASTA' ? PASTA_ORDER  : STRIDE_ORDER;
  const palette  = methodology === 'PASTA' ? PASTA_PALETTE : TYPE_PALETTE;

  const orderedEntries: StatEntry[] = order.map((k, i) => ({
    label: k, value: countMap.get(k) ?? 0, color: palette[i % palette.length], dimmed: !countMap.has(k),
  }));
  const otherEntries: StatEntry[] = threatsByType
    .filter(([t]) => !order.includes(t))
    .map(([t, c], i) => ({ label: t, value: c, color: TYPE_PALETTE[(order.length + i) % TYPE_PALETTE.length] }));

  return (
    <StatTableCard
      title={title}
      badge={total > 0 ? `${total} total` : undefined}
      entries={[...orderedEntries, ...otherEntries]}
    />
  );
};

// ── Third-party Vendors Card ──────────────────────────────────────────────────

const VendorsCard: React.FC<{ assessments: AssessmentData[] }> = ({ assessments }) => {
  const [open, setOpen] = useState(false);
  const rows = useMemo(() =>
    assessments.map(a => ({
      id: a.id,
      name: a.name,
      vendors: extractVendorNames(a.third_party_integrations_text ?? ''),
    })),
    [assessments]
  );
  const hasAnyVendors = rows.some(r => r.vendors.length > 0);

  useEffect(() => {
    if (hasAnyVendors) setOpen(true);
  }, [hasAnyVendors]);

  return (
    <div className="bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl shadow-sm overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors"
      >
        <div className="flex items-center gap-2.5">
          <svg className="w-4 h-4 text-slate-400 dark:text-slate-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">Third-party Vendors</span>
        </div>
        <svg
          className={`w-4 h-4 text-slate-400 transition-transform duration-200 flex-shrink-0 ${open ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="border-t border-slate-100 dark:border-gray-800/60 p-5">
          {hasAnyVendors ? (
            <div className="overflow-auto max-h-64">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-100 dark:border-gray-800/60">
                    <th className="text-left font-semibold text-slate-500 dark:text-slate-400 pb-2 pr-4 w-2/5">Sub-Model</th>
                    <th className="text-left font-semibold text-slate-500 dark:text-slate-400 pb-2">Vendors</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50 dark:divide-gray-800/40">
                  {rows.map(({ id, name, vendors }) => (
                    <tr key={id} className="align-top">
                      <td className="pr-4 py-2 font-medium text-slate-700 dark:text-slate-300 truncate max-w-[140px]">{name}</td>
                      <td className="py-2 text-slate-500 dark:text-slate-400">
                        {vendors.length > 0
                          ? vendors.join(' · ')
                          : <span className="italic text-slate-300 dark:text-slate-600">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex items-center justify-center h-20">
              <p className="text-sm text-slate-400 dark:text-slate-500">No vendor data extracted</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ── Data Flow Diagram Card (React Flow) ───────────────────────────────────────

const LAYER_ORDER = ['Client', 'API Gateway', 'Microservice', 'Database', 'Infrastructure', 'External / Third-Party System'];

const LAYER_COLORS: Record<string, { bg: string; border: string; headerBg: string; tag: string; tagText: string }> = {
  'Client':                        { bg: '#eff6ff', border: '#93c5fd', headerBg: '#3b82f6', tag: '#dbeafe', tagText: '#1e40af' },
  'API Gateway':                   { bg: '#f0fdf4', border: '#86efac', headerBg: '#22c55e', tag: '#dcfce7', tagText: '#15803d' },
  'Microservice':                  { bg: '#faf5ff', border: '#c4b5fd', headerBg: '#8b5cf6', tag: '#ede9fe', tagText: '#6d28d9' },
  'Database':                      { bg: '#fefce8', border: '#fde047', headerBg: '#eab308', tag: '#fef9c3', tagText: '#854d0e' },
  'Infrastructure':                { bg: '#fff7ed', border: '#fdba74', headerBg: '#f97316', tag: '#ffedd5', tagText: '#9a3412' },
  'External / Third-Party System': { bg: '#fff1f2', border: '#fda4af', headerBg: '#f43f5e', tag: '#ffe4e6', tagText: '#be123c' },
};
const DEFAULT_LAYER_COLOR = { bg: '#f8fafc', border: '#cbd5e1', headerBg: '#64748b', tag: '#f1f5f9', tagText: '#475569' };

const DfdComponentNode = memo(({ data, selected }: {
  data: { label: string; type: string; similarNames?: string[] };
  selected?: boolean;
}) => {
  const c = LAYER_COLORS[data.type] ?? DEFAULT_LAYER_COLOR;
  const [showTooltip, setShowTooltip] = useState(false);
  const hasSimilar = (data.similarNames?.length ?? 0) > 0;

  return (
    <div
      className="rounded-lg shadow-sm w-[200px] border-2 transition-all duration-200"
      style={{
        background: c.bg,
        borderColor: selected ? '#0052cc' : c.border,
        borderWidth: selected ? 2 : 1.5,
      }}
    >
      <Handle type="target" position={Position.Top} />
      <div className="px-3 py-2.5 relative">
        <p className="font-semibold text-xs text-slate-800 break-words leading-snug pr-5">{data.label}</p>
        <span
          className="mt-1.5 inline-block text-[9px] font-semibold px-1.5 py-0.5 rounded-full"
          style={{ background: c.tag, color: c.tagText }}
        >
          {data.type}
        </span>
        {hasSimilar && (
          <div className="absolute top-1.5 right-1.5">
            <button
              className="w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold text-white cursor-pointer nodrag"
              style={{ background: c.headerBg }}
              onClick={e => { e.stopPropagation(); setShowTooltip(v => !v); }}
              title={`${data.similarNames!.length} similar name${data.similarNames!.length > 1 ? 's' : ''} merged`}
            >
              i
            </button>
            {showTooltip && (
              <div
                className="absolute top-5 right-0 z-50 bg-white dark:bg-gray-900 border border-slate-200 dark:border-gray-700 rounded-lg shadow-xl p-2.5 min-w-[160px] max-w-[240px] nodrag"
                onClick={e => e.stopPropagation()}
              >
                <div className="flex items-center justify-between mb-1.5 gap-2">
                  <p className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide">Also known as</p>
                  <button
                    className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-[10px] leading-none"
                    onClick={e => { e.stopPropagation(); setShowTooltip(false); }}
                  >✕</button>
                </div>
                {data.similarNames!.map((name, idx) => (
                  <div
                    key={idx}
                    className="text-[11px] text-slate-700 dark:text-slate-300 py-1 px-1.5 rounded border-b last:border-b-0 border-slate-100 dark:border-gray-800 truncate"
                    title={name}
                  >
                    {name}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
});
DfdComponentNode.displayName = 'DfdComponentNode';

const DFD_NODE_TYPES = { 'dfd-component': DfdComponentNode };

// ── Architecture Overview (clustered, no ReactFlow) ───────────────────────────

const OverviewItemRow: React.FC<{
  item: { label: string; similarNames?: string[] };
  borderColor: string;
  headerBg: string;
}> = ({ item, borderColor, headerBg }) => {
  const btnRef = useRef<HTMLButtonElement>(null);
  const [tooltipPos, setTooltipPos] = useState<{ top: number; right: number } | null>(null);
  const hasSimilar = (item.similarNames?.length ?? 0) > 0;

  const handleToggle = () => {
    if (tooltipPos) { setTooltipPos(null); return; }
    if (btnRef.current) {
      const r = btnRef.current.getBoundingClientRect();
      setTooltipPos({ top: r.bottom + 6, right: window.innerWidth - r.right });
    }
  };

  useEffect(() => {
    if (!tooltipPos) return;
    const close = (e: MouseEvent) => {
      if (!(e.target as Element).closest('[data-oir-tooltip]')) setTooltipPos(null);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [tooltipPos]);

  return (
    <div
      className="px-3 py-1.5 border-b last:border-b-0 flex items-center gap-1.5"
      style={{ borderColor: `${borderColor}44` }}
    >
      <p className="text-[11px] text-slate-700 dark:text-slate-300 truncate flex-1" title={item.label}>{item.label}</p>
      {hasSimilar && (
        <div className="flex-shrink-0 flex items-center gap-0.5">
          <span className="text-[9px] font-semibold px-1 py-0.5 rounded-l-full text-white" style={{ background: headerBg }}>
            +{item.similarNames!.length}
          </span>
          <button
            ref={btnRef}
            className="w-3.5 h-[18px] rounded-r-full flex items-center justify-center text-[8px] font-bold text-white"
            style={{ background: headerBg, opacity: 0.85 }}
            onClick={handleToggle}
            title="Show merged names"
          >i</button>
          {tooltipPos && createPortal(
            <div
              data-oir-tooltip
              className="fixed z-[9999] bg-white dark:bg-gray-900 border border-slate-200 dark:border-gray-700 rounded-lg shadow-2xl p-2 min-w-[160px] max-w-[240px]"
              style={{ top: tooltipPos.top, right: tooltipPos.right }}
            >
              <div className="flex items-center justify-between mb-1 gap-2">
                <p className="text-[9px] font-semibold text-slate-500 uppercase tracking-wide">Also known as</p>
                <button className="text-slate-400 hover:text-slate-600 text-[9px]" onClick={() => setTooltipPos(null)}>✕</button>
              </div>
              {item.similarNames!.map((name, idx) => (
                <div key={idx} className="text-[10px] text-slate-700 dark:text-slate-300 py-0.5 border-b last:border-b-0 border-slate-100 dark:border-gray-800 truncate" title={name}>{name}</div>
              ))}
            </div>,
            document.body
          )}
        </div>
      )}
    </div>
  );
};

const ArchOverview: React.FC<{
  nodes: any[];
  edges: any[];
  mergedCount: number;
  useJaccard: boolean;
  onToggleJaccard: () => void;
}> = ({ nodes, edges, mergedCount, useJaccard, onToggleJaccard }) => {
  const groups = useMemo(() => {
    const map = new Map<string, Array<{ label: string; similarNames?: string[] }>>();
    for (const n of nodes) {
      const t = n.data?.type ?? 'Microservice';
      if (!map.has(t)) map.set(t, []);
      map.get(t)!.push({ label: n.data?.label || n.id, similarNames: n.data?.similarNames });
    }
    return LAYER_ORDER.filter(l => map.has(l)).map(l => ({ type: l, items: map.get(l)! }));
  }, [nodes]);

  const layerEdgeCounts = useMemo(() => {
    const nodeTypeMap = new Map<string, string>();
    for (const n of nodes) nodeTypeMap.set(n.id, n.data?.type ?? 'Microservice');
    const counts = new Map<string, number>();
    for (const e of edges) {
      const st = nodeTypeMap.get(e.source);
      const tt = nodeTypeMap.get(e.target);
      if (st && tt && st !== tt) {
        const key = `${st}→${tt}`;
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
    }
    return counts;
  }, [nodes, edges]);

  if (groups.length === 0) return (
    <div className="flex items-center justify-center h-32">
      <p className="text-sm text-slate-400">No nodes to display</p>
    </div>
  );

  return (
    <div className="overflow-x-auto py-6 px-5">
      <div className="flex items-start gap-3 min-w-max">
        {groups.map((group, i) => {
          const c = LAYER_COLORS[group.type] ?? DEFAULT_LAYER_COLOR;
          const nextGroup = groups[i + 1];
          const edgeCount = nextGroup ? (layerEdgeCounts.get(`${group.type}→${nextGroup.type}`) ?? 0) : 0;
          return (
            <React.Fragment key={group.type}>
              <div className="w-52 flex-shrink-0 rounded-xl overflow-hidden shadow-sm border" style={{ borderColor: c.border }}>
                <div className="px-3 py-2 flex items-center justify-between" style={{ backgroundColor: c.headerBg }}>
                  <span className="text-[11px] font-bold text-white leading-tight">{group.type}</span>
                  <span className="text-[10px] font-bold bg-white/25 text-white px-1.5 py-0.5 rounded-full">{group.items.length}</span>
                </div>
                <div className="max-h-56 overflow-y-auto" style={{ backgroundColor: c.bg }}>
                  {group.items.map(item => (
                    <OverviewItemRow key={item.label} item={item} borderColor={c.border} headerBg={c.headerBg} />
                  ))}
                </div>
              </div>
              {nextGroup && (
                <div className="flex flex-col items-center justify-center self-center gap-0.5 flex-shrink-0">
                  <svg className="w-6 h-5 text-slate-300" fill="none" viewBox="0 0 24 20" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 10h14M14 5l5 5-5 5" />
                  </svg>
                  {edgeCount > 0 && (
                    <span className="text-[9px] font-semibold text-slate-400">{edgeCount} links</span>
                  )}
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
      <div className="mt-4 flex flex-col items-center gap-1">
        <p className="text-[10px] text-slate-400 text-center">
          {nodes.length} components · {edges.length} connections across {groups.length} layers
          {useJaccard && mergedCount > 0 && (
            <span className="ml-1">· <span className="text-amber-500 font-semibold">{mergedCount} node{mergedCount > 1 ? 's' : ''} merged</span> via Jaccard similarity</span>
          )}
        </p>
        <button
          onClick={onToggleJaccard}
          className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border transition-colors ${
            useJaccard
              ? 'border-amber-200 bg-amber-50 text-amber-600 hover:bg-amber-100 dark:border-amber-800/40 dark:bg-amber-900/20 dark:text-amber-400'
              : 'border-slate-200 bg-slate-100 text-slate-500 hover:bg-slate-200 dark:border-gray-700 dark:bg-gray-800 dark:text-slate-400'
          }`}
        >
          {useJaccard ? 'Merged view — click to show all nodes' : 'Show merged view (Jaccard)'}
        </button>
      </div>
    </div>
  );
};



const DfdCard: React.FC<{ name: string; id: string; reactflow: string }> = ({ name, id, reactflow }) => {
  const [open, setOpen] = useState(true);
  const [rfNodes, setRfNodes, onNodesChange] = useNodesState([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    if (!reactflow) { setRfNodes([]); setRfEdges([]); return; }
    try {
      const parsed = typeof reactflow === 'string' ? JSON.parse(reactflow) : reactflow;
      if (!parsed?.nodes?.length) { setRfNodes([]); setRfEdges([]); return; }

      const transformedNodes = parsed.nodes.map((n: any, i: number) => ({
        ...n,
        type: 'dfd-component',
        position: n.position?.x != null ? n.position : { x: 250 + i * 320, y: 100 + (i % 3) * 220 },
        data: { ...n.data, type: n.type || 'Client' },
        style: { width: 200, height: 'auto', padding: 0, border: 'none', background: 'transparent' },
      }));
      const transformedEdges = (parsed.edges ?? []).map((e: any) => ({
        ...e,
        animated: true,
        style: { stroke: '#94a3b8', strokeWidth: 2 },
        markerEnd: { type: MarkerType.Arrow, color: '#94a3b8' },
      }));
      setRfNodes(transformedNodes);
      setRfEdges(transformedEdges);
    } catch { setRfNodes([]); setRfEdges([]); }
  }, [id, reactflow]);

  if (!reactflow) return null;

  return (
    <div className="bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl shadow-sm overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors"
      >
        <div className="flex items-center gap-2.5 min-w-0 flex-1">
          <svg className="w-4 h-4 text-[#0052cc] dark:text-blue-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
          </svg>
          <span className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex-shrink-0">Data Flow Diagram</span>
          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-md bg-slate-100 dark:bg-gray-800 text-slate-500 dark:text-slate-400 flex-shrink-0">Latest sub-model</span>
          <span className="text-xs text-slate-400 dark:text-slate-500 font-normal">— {name}</span>
          <div className="relative flex-shrink-0 group" onClick={e => e.stopPropagation()}>
            <button
              type="button"
              className="w-4 h-4 rounded-full border border-slate-300 dark:border-gray-600 text-slate-400 dark:text-slate-500 hover:border-slate-500 dark:hover:border-slate-400 hover:text-slate-600 dark:hover:text-slate-300 flex items-center justify-center text-[10px] font-bold transition-colors"
            >
              i
            </button>
            <div className="absolute left-0 top-6 z-20 hidden group-hover:block bg-slate-800 dark:bg-gray-950 text-slate-100 text-[10px] font-mono px-2.5 py-1.5 rounded-lg shadow-lg whitespace-nowrap border border-slate-700 dark:border-gray-700">
              {id}
            </div>
          </div>
        </div>
        <svg
          className={`w-4 h-4 text-slate-400 transition-transform duration-200 flex-shrink-0 ${open ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div className="border-t border-slate-100 dark:border-gray-800/60" style={{ height: 480 }}>
          {rfNodes.length > 0 ? (
            <ReactFlow
              nodes={rfNodes}
              edges={rfEdges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              nodeTypes={DFD_NODE_TYPES}
              fitView
              className="bg-white dark:bg-gray-900"
            >
              <Controls />
              <MiniMap />
              <Background color="#94a3b8" gap={16} size={1} />
            </ReactFlow>
          ) : (
            <div className="flex items-center justify-center h-full">
              <p className="text-sm text-slate-400 dark:text-slate-500">No diagram data available</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ── Consolidated Data Flow Diagram Card ──────────────────────────────────────

interface ConsolidatedStatus {
  status: 'idle' | 'running' | 'completed' | 'failed';
  started_at?: string;
  completed_at?: string;
  error?: string;
  source_count?: number;
}

interface ConsolidatedDiagram {
  reactflow: string;
  summary: string;
  components: string[];
  source_count: number;
}

const ConsolidatedDfdCard: React.FC<{
  subModelCount: number;
  groupId: string;
  assessmentIds: string[];
}> = ({ subModelCount, groupId, assessmentIds }) => {
  const [open, setOpen] = useState(false);
  const [jobStatus, setJobStatus] = useState<ConsolidatedStatus>({ status: 'idle' });
  const [diagram, setDiagram] = useState<ConsolidatedDiagram | null>(null);
  const [rfNodes, setRfNodes, onNodesChange] = useNodesState([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState([]);
  const [fullscreen, setFullscreen] = useState(false);
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [viewMode, setViewMode] = useState<'overview' | 'detail'>('overview');
  const [useJaccard, setUseJaccard] = useState(true);
  const [showDisconnected, setShowDisconnected] = useState(false);
  const [diagramRaw, setDiagramRaw] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });

  const fetchStatus = useCallback(async () => {
    if (!groupId) return;
    try {
      const res = await fetch(`${API_BASE_URL}/consolidated-diagram/status?group_id=${encodeURIComponent(groupId)}`);
      if (!res.ok) return;
      const data = await res.json();
      const st: ConsolidatedStatus = data.status ?? { status: 'idle' };
      setJobStatus(st);
      if (data.diagram) setDiagram(data.diagram);
      if (st.status === 'completed') setOpen(true);
    } catch {}
  }, [groupId]);

  useEffect(() => { fetchStatus(); }, [fetchStatus]);

  useEffect(() => {
    if (jobStatus.status !== 'running') return;
    const id = setInterval(fetchStatus, 3000);
    return () => clearInterval(id);
  }, [jobStatus.status, fetchStatus]);

  useEffect(() => {
    if (!diagram?.reactflow) { setDiagramRaw({ nodes: [], edges: [] }); return; }
    try {
      const parsed = typeof diagram.reactflow === 'string' ? JSON.parse(diagram.reactflow) : diagram.reactflow;
      if (!parsed?.nodes?.length) { setDiagramRaw({ nodes: [], edges: [] }); return; }
      const rawNodes = parsed.nodes.map((n: any, i: number) => ({
        ...n,
        type: 'dfd-component',
        position: n.position?.x != null ? n.position : { x: 250 + i * 320, y: 100 + (i % 3) * 220 },
        data: { label: n.data?.label || n.id, type: n.data?.type || 'Microservice' },
        style: { width: 200, height: 'auto', padding: 0, border: 'none', background: 'transparent' },
      }));
      const rawEdges = (parsed.edges ?? []).map((e: any) => ({
        ...e,
        animated: false,
        style: { stroke: '#8b5cf6', strokeWidth: 1.5, opacity: 0.6 },
        markerEnd: { type: MarkerType.Arrow, color: '#8b5cf6' },
      }));
      setDiagramRaw({ nodes: rawNodes, edges: rawEdges });
    } catch { setDiagramRaw({ nodes: [], edges: [] }); }
  }, [diagram]);

  useEffect(() => {
    if (!diagramRaw.nodes.length) { setRfNodes([]); setRfEdges([]); return; }
    if (useJaccard) {
      const { nodes: merged, edges: mergedEdges } = consolidateDiagramNodes(diagramRaw.nodes, diagramRaw.edges);
      setRfNodes(merged);
      setRfEdges(mergedEdges);
    } else {
      setRfNodes(diagramRaw.nodes);
      setRfEdges(diagramRaw.edges);
    }
  }, [diagramRaw, useJaccard]);

  // Node types for filter chips
  const allNodeTypes = useMemo(() => {
    const counts = new Map<string, number>();
    for (const n of rfNodes) {
      const t = (n.data as any)?.type ?? 'Unknown';
      counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [rfNodes]);

  const displayNodes = useMemo(() => {
    const disconnected = new Set<string>();
    const connected = new Set<string>();
    for (const e of rfEdges) { connected.add(e.source); connected.add(e.target); }
    for (const n of rfNodes) { if (!connected.has(n.id)) disconnected.add(n.id); }
    return rfNodes.map(n => ({
      ...n,
      hidden: (hiddenTypes.size > 0 && hiddenTypes.has((n.data as any)?.type ?? ''))
           || (!showDisconnected && disconnected.has(n.id)),
    }));
  }, [rfNodes, rfEdges, hiddenTypes, showDisconnected]);

  const disconnectedIds = useMemo(() => {
    const connected = new Set<string>();
    for (const e of rfEdges) { connected.add(e.source); connected.add(e.target); }
    return new Set(rfNodes.filter(n => !connected.has(n.id)).map(n => n.id));
  }, [rfNodes, rfEdges]);

  const mergedCount = useMemo(() =>
    rfNodes.reduce((s, n) => s + ((n.data as any)?.similarNames?.length ?? 0), 0),
    [rfNodes]
  );

  const displayEdges = useMemo(() => {
    const visibleIds = new Set(displayNodes.filter(n => !n.hidden).map(n => n.id));
    return rfEdges.map(e => ({ ...e, hidden: !visibleIds.has(e.source) || !visibleIds.has(e.target) }));
  }, [rfEdges, displayNodes]);

  const overviewNodes = useMemo(() =>
    showDisconnected ? rfNodes : rfNodes.filter(n => !disconnectedIds.has(n.id)),
    [rfNodes, showDisconnected, disconnectedIds]
  );

  const toggleType = useCallback((t: string) => {
    setHiddenTypes(prev => { const next = new Set(prev); next.has(t) ? next.delete(t) : next.add(t); return next; });
  }, []);

  const triggerConsolidation = async () => {
    setJobStatus({ status: 'running' });
    setOpen(true);
    try {
      await fetch(`${API_BASE_URL}/consolidated-diagram/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_id: groupId, assessment_ids: assessmentIds }),
      });
    } catch {}
  };

  const formatTs = (ts?: string) => {
    if (!ts) return '';
    try {
      return new Date(ts).toLocaleString('en-IN', {
        day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
      });
    } catch { return ts; }
  };

  const isRunning   = jobStatus.status === 'running';
  const isCompleted = jobStatus.status === 'completed';
  const isFailed    = jobStatus.status === 'failed';

  return (
    <div className="bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl shadow-sm overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors"
      >
        <div className="flex items-center gap-2.5 min-w-0 flex-1">
          {isRunning ? (
            <div className="w-4 h-4 flex-shrink-0 border-2 border-violet-300 border-t-violet-600 rounded-full animate-spin" />
          ) : (
            <svg className="w-4 h-4 text-violet-500 dark:text-violet-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
            </svg>
          )}
          <span className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex-shrink-0">Consolidated Data Flow Diagram</span>
          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-md bg-violet-50 dark:bg-violet-900/30 text-violet-600 dark:text-violet-400 border border-violet-200 dark:border-violet-800/40 flex-shrink-0">
            {subModelCount} sub-models
          </span>
          {isRunning && (
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-md bg-sky-50 dark:bg-sky-900/30 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-800/40 flex-shrink-0 animate-pulse">
              Generating…
            </span>
          )}
          {isCompleted && (
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-md bg-emerald-50 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/40 flex-shrink-0">
              {diagram?.source_count ?? jobStatus.source_count} merged
            </span>
          )}
          {isFailed && (
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-md bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800/40 flex-shrink-0">
              Failed
            </span>
          )}
          {!isRunning && !isCompleted && !isFailed && (
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-md bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-800/40 flex-shrink-0">
              Not generated
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {isCompleted && rfNodes.length > 0 && (
            <button
              onClick={e => { e.stopPropagation(); setFullscreen(v => !v); }}
              className="p-1 rounded-md text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-gray-800/60 transition-colors"
              title={fullscreen ? 'Exit fullscreen' : 'Expand diagram'}
            >
              {fullscreen ? (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              ) : (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
                </svg>
              )}
            </button>
          )}
          <svg
            className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {open && (
        <div className="border-t border-slate-100 dark:border-gray-800/60">

          {isRunning && (
            <div className="flex flex-col items-center justify-center py-16 gap-4 px-8">
              <div className="w-14 h-14 border-4 border-violet-100 dark:border-violet-900/40 border-t-violet-500 rounded-full animate-spin" />
              <div className="text-center">
                <p className="text-sm font-semibold text-slate-700 dark:text-slate-300">Generating consolidated diagram…</p>
                <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">
                  Merging {jobStatus.source_count ?? subModelCount} sub-model DFDs via AI — this may take a minute.
                </p>
                {jobStatus.started_at && (
                  <p className="text-[10px] text-slate-300 dark:text-slate-600 mt-2">Started {formatTs(jobStatus.started_at)}</p>
                )}
              </div>
            </div>
          )}

          {isFailed && (
            <div className="flex flex-col items-center justify-center py-12 gap-4 px-8">
              <div className="w-12 h-12 rounded-xl bg-red-50 dark:bg-red-900/20 flex items-center justify-center">
                <svg className="w-6 h-6 text-red-500 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div className="text-center max-w-sm">
                <p className="text-sm font-semibold text-slate-700 dark:text-slate-300">Consolidation failed</p>
                {jobStatus.error && (
                  <p className="text-xs text-red-500 dark:text-red-400 mt-1.5 leading-relaxed">{jobStatus.error}</p>
                )}
              </div>
              <button
                onClick={e => { e.stopPropagation(); triggerConsolidation(); }}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-700 text-white text-sm font-semibold transition-colors shadow-sm"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                Retry consolidation
              </button>
            </div>
          )}

          {!isRunning && !isFailed && !isCompleted && (
            <div className="flex flex-col items-center justify-center py-12 gap-5 px-8">
              <div className="w-16 h-16 rounded-2xl bg-violet-50 dark:bg-violet-900/20 border-2 border-dashed border-violet-200 dark:border-violet-800/40 flex items-center justify-center">
                <svg className="w-8 h-8 text-violet-400 dark:text-violet-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                </svg>
              </div>
              <div className="text-center max-w-sm">
                <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1.5">No consolidated diagram yet</p>
                <p className="text-xs text-slate-400 dark:text-slate-500 leading-relaxed">
                  Merge the data flow diagrams from all {subModelCount} sub-models into a single unified architecture view, highlighting shared components and cross-model data flows.
                </p>
              </div>
              <div className="flex items-center gap-5 mb-1">
                {[`${subModelCount} sub-models`, 'Deduplicated nodes', 'Unified edges'].map(label => (
                  <div key={label} className="flex items-center gap-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-violet-300 dark:bg-violet-600" />
                    <span className="text-[10px] font-medium text-slate-400 dark:text-slate-500">{label}</span>
                  </div>
                ))}
              </div>
              <button
                onClick={e => { e.stopPropagation(); triggerConsolidation(); }}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-violet-600 hover:bg-violet-700 text-white text-sm font-semibold transition-colors shadow-sm"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                Consolidate all diagrams and generate a new one
              </button>
            </div>
          )}

          {isCompleted && (
            <div className={fullscreen ? 'fixed inset-0 z-50 bg-white dark:bg-gray-900 flex flex-col overflow-hidden' : ''}>

              {/* Info bar + view toggle + regenerate */}
              <div className="flex items-center justify-between px-4 py-2.5 bg-slate-50 dark:bg-gray-800/30 border-b border-slate-100 dark:border-gray-800/60 gap-3">
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  <div className="flex items-center gap-0.5 bg-slate-100 dark:bg-gray-800 rounded-lg p-0.5 border border-slate-200 dark:border-gray-700/60 flex-shrink-0">
                    {(['overview', 'detail'] as const).map(m => (
                      <button
                        key={m}
                        onClick={() => setViewMode(m)}
                        className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all ${
                          viewMode === m
                            ? 'bg-white dark:bg-[#0d1e38] text-slate-800 dark:text-slate-100 shadow-sm'
                            : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'
                        }`}
                      >
                        {m === 'overview' ? 'Overview' : 'Detail graph'}
                      </button>
                    ))}
                  </div>
                  {jobStatus.completed_at && (
                    <span className="text-[11px] text-slate-400 dark:text-slate-500 truncate hidden sm:block">
                      {formatTs(jobStatus.completed_at)}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  {disconnectedIds.size > 0 && (
                    <div className="flex items-center gap-1 text-[10px] text-slate-400 dark:text-slate-500">
                      <svg className="w-3 h-3 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                      </svg>
                      <span>{showDisconnected ? 'Showing' : 'Hiding'} {disconnectedIds.size} isolated</span>
                      <button onClick={() => setShowDisconnected(v => !v)} className="font-semibold text-[#0052cc] dark:text-blue-400 hover:underline">
                        {showDisconnected ? 'Hide' : 'Show'}
                      </button>
                    </div>
                  )}
                  <button
                    onClick={e => { e.stopPropagation(); triggerConsolidation(); }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-violet-200 dark:border-violet-800/40 bg-violet-50 dark:bg-violet-900/20 text-violet-700 dark:text-violet-400 text-xs font-semibold hover:bg-violet-100 dark:hover:bg-violet-900/30 transition-colors"
                  >
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    Regenerate
                  </button>
                </div>
              </div>

              {viewMode === 'overview' && (
                <ArchOverview nodes={overviewNodes} edges={rfEdges} mergedCount={mergedCount} useJaccard={useJaccard} onToggleJaccard={() => setUseJaccard(v => !v)} />
              )}

              {viewMode === 'detail' && (
                <>
                  {allNodeTypes.length > 1 && (
                    <div className="flex items-center gap-2 px-4 py-2 bg-slate-50 dark:bg-gray-800/20 border-b border-slate-100 dark:border-gray-800/60 flex-wrap">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Layers:</span>
                      {allNodeTypes.map(([type, count]) => {
                        const hidden = hiddenTypes.has(type);
                        const c = LAYER_COLORS[type] ?? DEFAULT_LAYER_COLOR;
                        return (
                          <button
                            key={type}
                            onClick={() => toggleType(type)}
                            className={`flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border transition-all ${
                              hidden ? 'opacity-40 border-slate-200 dark:border-gray-700/40 bg-slate-100 dark:bg-gray-800 text-slate-500' : 'shadow-sm'
                            }`}
                            style={hidden ? undefined : { background: c.tag, borderColor: c.border, color: c.tagText }}
                          >
                            {type}
                            <span className="text-[9px] font-bold ml-0.5 opacity-70">{count}</span>
                          </button>
                        );
                      })}
                      {hiddenTypes.size > 0 && (
                        <button onClick={() => setHiddenTypes(new Set())} className="text-[10px] font-semibold text-[#0052cc] dark:text-blue-400 hover:underline">
                          Show all
                        </button>
                      )}
                      <div className="ml-auto flex-shrink-0">
                        <button
                          onClick={() => setUseJaccard(v => !v)}
                          className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border transition-colors ${
                            useJaccard
                              ? 'border-amber-200 bg-amber-50 text-amber-600 dark:border-amber-800/40 dark:bg-amber-900/20 dark:text-amber-400'
                              : 'border-slate-200 bg-slate-100 text-slate-500 dark:border-gray-700 dark:bg-gray-800 dark:text-slate-400'
                          }`}
                          title={useJaccard ? 'Disable Jaccard merging — show all nodes' : 'Enable Jaccard merging'}
                        >
                          {useJaccard ? `Jaccard merged (${mergedCount})` : 'Jaccard off'}
                        </button>
                      </div>
                    </div>
                  )}
                  <div className={fullscreen ? 'flex-1' : ''} style={fullscreen ? undefined : { height: 560 }}>
                    {displayNodes.filter(n => !n.hidden).length > 0 ? (
                      <ReactFlow
                        nodes={displayNodes}
                        edges={displayEdges}
                        onNodesChange={onNodesChange}
                        onEdgesChange={onEdgesChange}
                        nodeTypes={DFD_NODE_TYPES}
                        fitView
                        fitViewOptions={{ padding: 0.15 }}
                        className="bg-white dark:bg-gray-900"
                      >
                        <Controls />
                        <MiniMap />
                        <Background color="#e2e8f0" gap={20} size={1} />
                      </ReactFlow>
                    ) : (
                      <div className="flex items-center justify-center h-full">
                        <p className="text-sm text-slate-400 dark:text-slate-500">No diagram data available</p>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          )}

        </div>
      )}
    </div>
  );
};

// ── Sec Bugs Card ─────────────────────────────────────────────────────────────

const JIRA_BASE = process.env.REACT_APP_JIRA_BASE_URL || '';

const PRIORITY_COLOR: Record<string, string> = {
  critical: '#ef4444',
  highest:  '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  lowest:   '#94a3b8',
};

function priorityDot(priority: string) {
  const color = PRIORITY_COLOR[(priority || '').toLowerCase()] ?? '#94a3b8';
  return <span className="inline-block w-2 h-2 rounded-full flex-shrink-0 mt-0.5" style={{ backgroundColor: color }} />;
}

interface SecBug { id: string; name: string; status: string; priority: string; }

const SecBugsCard: React.FC<{ secbugs: SecBug[] }> = ({ secbugs }) => {
  const [open, setOpen] = useState(true);
  if (secbugs.length === 0) return null;
  return (
    <div className="bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl shadow-sm overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-4 py-3.5 hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors"
      >
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-red-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
          </svg>
          <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">Sec Bugs</span>
          <span className="text-xs font-bold text-white bg-red-500 px-1.5 py-0.5 rounded-full leading-none">{secbugs.length}</span>
        </div>
        <svg className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="border-t border-slate-100 dark:border-gray-800/60 divide-y divide-slate-50 dark:divide-gray-800/40 overflow-y-auto max-h-72">
          {secbugs.map(bug => (
            <div key={bug.id} className="flex items-start justify-between gap-2 px-4 py-2.5 hover:bg-slate-50 dark:hover:bg-gray-800/30 transition-colors">
              <div className="flex items-start gap-2 min-w-0">
                {priorityDot(bug.priority)}
                <span className="text-[11px] text-slate-600 dark:text-slate-400 leading-snug break-words">
                  <span className="font-semibold text-slate-700 dark:text-slate-300">[{bug.id}]</span>
                  {' — '}
                  {bug.name.length > 42 ? bug.name.slice(0, 42) + '…' : bug.name}
                </span>
              </div>
              <a
                href={`${JIRA_BASE}${bug.id}`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                className="flex-shrink-0 p-1 rounded-md text-slate-400 hover:text-[#0052cc] dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors"
                title="Open in Jira"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
              </a>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ── Main page ─────────────────────────────────────────────────────────────────

const CustomDepartmentDetail: React.FC = () => {
  const { id: customId } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [customName, setCustomName] = useState('Custom Analysis');
  const [raw, setRaw] = useState<AssessmentData[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [additionalInfoMap, setAdditionalInfoMap] = useState<Record<string, { dfd: string; reactflow: string; vendors: string }>>({});
  const [secbugs, setSecbugs] = useState<SecBug[]>([]);

  useEffect(() => {
    if (!customId) return;
    const token = localStorage.getItem('ts_auth_token') ?? '';
    const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};

    Promise.all([
      fetch(`${API_BASE_URL}/custom-threat-models/${customId}`, { headers })
        .then(r => { if (!r.ok) throw new Error('Custom analysis not found'); return r.json(); }),
      fetch(`${API_BASE_URL}/analytics-data`)
        .then(r => { if (!r.ok) throw new Error('Failed to fetch data'); return r.json(); }),
    ])
      .then(([custom, analytics]) => {
        setCustomName(custom.name ?? 'Custom Analysis');
        setSelectedIds(new Set(custom.assessment_ids ?? []));
        setRaw(analytics.data ?? []);
        setLoading(false);
      })
      .catch(e => { setError(e.message); setLoading(false); });
  }, [customId]);

  const selectedAssessments = useMemo(
    () => raw.filter(a => selectedIds.has(a.id)),
    [raw, selectedIds],
  );

  // Fetch additional info (DFD, vendors) by grouping selected assessments per DEPARTMENT
  useEffect(() => {
    if (selectedAssessments.length === 0) return;
    const lobs = [...new Set(
      selectedAssessments.map(a => a.details?.department).filter((v): v is string => Boolean(v))
    )];
    Promise.all(
      lobs.map(department =>
        fetch(`${API_BASE_URL}/department-additional-info?department=${encodeURIComponent(department)}`)
          .then(r => r.ok ? r.json() : { data: [] })
          .catch(() => ({ data: [] }))
      )
    ).then(results => {
      const map: Record<string, { dfd: string; reactflow: string; vendors: string }> = {};
      for (const { data } of results) {
        for (const item of (data ?? [])) {
          if (selectedIds.has(item.id)) {
            map[item.id] = {
              dfd: item.data_flow_diagram_code ?? '',
              reactflow: item.reactflow_data ?? '',
              vendors: item.third_party_integrations_text ?? '',
            };
          }
        }
      }
      setAdditionalInfoMap(map);
    });
  }, [selectedAssessments, selectedIds]);

  // Fetch secbugs from all LOBs in this custom analysis
  useEffect(() => {
    if (selectedAssessments.length === 0) return;
    const lobs = [...new Set(
      selectedAssessments.map(a => a.details?.department).filter((v): v is string => Boolean(v))
    )];
    Promise.all(
      lobs.map(department =>
        fetch(`${API_BASE_URL}/department-secbugs?department=${encodeURIComponent(department)}`)
          .then(r => r.ok ? r.json() : { data: [] })
          .catch(() => ({ data: [] }))
      )
    ).then(results => {
      const seen = new Set<string>();
      const merged: SecBug[] = [];
      for (const { data } of results) {
        for (const bug of (data ?? [])) {
          if (bug.id && !seen.has(bug.id)) {
            seen.add(bug.id);
            merged.push(bug);
          }
        }
      }
      const order: Record<string, number> = { critical: 0, highest: 0, high: 1, medium: 2, low: 3, lowest: 4 };
      merged.sort((a, b) => (order[(a.priority || '').toLowerCase()] ?? 5) - (order[(b.priority || '').toLowerCase()] ?? 5));
      setSecbugs(merged);
    });
  }, [selectedAssessments]);

  // Enrich assessments with DFD/vendor data from dedicated endpoint
  const enrichedAssessments = useMemo(() =>
    selectedAssessments.map(a => {
      const extra = additionalInfoMap[a.id];
      if (!extra) return a;
      return {
        ...a,
        data_flow_diagram_code: extra.dfd || a.data_flow_diagram_code || '',
        third_party_integrations_text: extra.vendors || a.third_party_integrations_text || '',
      };
    }),
    [selectedAssessments, additionalInfoMap]
  );

  const { strideAssessments, pastaAssessments, availableTabs } = useMemo(() => {
    const stride = selectedAssessments.filter(a => !isPastaAssessment(a));
    const pasta  = selectedAssessments.filter(a => isPastaAssessment(a));
    const tabs: ('STRIDE' | 'PASTA')[] = [];
    if (stride.length > 0) tabs.push('STRIDE');
    if (pasta.length > 0)  tabs.push('PASTA');
    return { strideAssessments: stride, pastaAssessments: pasta, availableTabs: tabs };
  }, [selectedAssessments]);

  const strideThreats   = useMemo(() => consolidateThreats(strideAssessments, 'STRIDE'), [strideAssessments]);
  const pastaThreats    = useMemo(() => consolidateThreats(pastaAssessments,  'PASTA'),  [pastaAssessments]);
  const allConsolidated = useMemo(() => [...strideThreats, ...pastaThreats], [strideThreats, pastaThreats]);

  // ── Summary stats ──────────────────────────────────────────────────────────

  const rawTotalThreats = useMemo(() =>
    selectedAssessments.reduce((sum, a) =>
      sum + (a.threat_model?.result?.raw_response?.threat_model?.length ?? 0), 0),
    [selectedAssessments]
  );

  const totalThreats  = allConsolidated.length;
  const totalCommon   = allConsolidated.filter(t => t.isCommon).reduce((s, t) => s + t.occurrenceCount, 0);
  const totalHighRisk = allConsolidated.filter(t => t.riskLevel === 'High' || t.riskLevel === 'Critical').length;

  // ── Threats by type — split by methodology (raw counts) ───────────────────

  const strideThreatsByType = useMemo(() => {
    const map = new Map<string, number>();
    for (const a of strideAssessments)
      for (const t of a.threat_model?.result?.raw_response?.threat_model ?? []) {
        const type = t['Threat Type'] ?? 'Unknown';
        map.set(type, (map.get(type) ?? 0) + 1);
      }
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
  }, [strideAssessments]);

  const pastaThreatsByType = useMemo(() => {
    const map = new Map<string, number>();
    for (const a of pastaAssessments)
      for (const t of a.threat_model?.result?.raw_response?.threat_model ?? []) {
        const brt = t['Business Risk Type'];
        const types = Array.isArray(brt) ? brt : brt ? [brt] : ['Unknown'];
        for (const type of types) map.set(type, (map.get(type) ?? 0) + 1);
      }
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
  }, [pastaAssessments]);

  const strideRawTotal = useMemo(() =>
    strideAssessments.reduce((s, a) => s + (a.threat_model?.result?.raw_response?.threat_model?.length ?? 0), 0),
    [strideAssessments]);

  const pastaRawTotal = useMemo(() =>
    pastaAssessments.reduce((s, a) => s + (a.threat_model?.result?.raw_response?.threat_model?.length ?? 0), 0),
    [pastaAssessments]);

  // ── Chart data ─────────────────────────────────────────────────────────────

  const riskOrder = ['Critical', 'High', 'Medium', 'Low', 'Unknown'] as const;

  const riskCounts = useMemo(() => {
    const map: Record<string, number> = {};
    for (const a of selectedAssessments) {
      for (const t of a.threat_model?.result?.raw_response?.threat_model ?? []) {
        const score = computeDreadScore(a.dread_assessment, t['Scenario'], t['Threat Type'] ?? '');
        let level: string;
        if (score === 0) level = 'Unknown';
        else if (score >= 9) level = 'Critical';
        else if (score >= 8) level = 'High';
        else if (score >= 6) level = 'Medium';
        else level = 'Low';
        map[level] = (map[level] ?? 0) + 1;
      }
    }
    return map;
  }, [selectedAssessments]);

  const RISK_COLORS: Record<string, string> = {
    Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e', Unknown: '#94a3b8',
  };

  const testCaseStats = useMemo(() => {
    let generated = 0, validated = 0;
    for (const a of selectedAssessments) {
      const items = a.test_cases?.result?.test_cases ?? [];
      generated += items.length;
      validated += items.filter(i => i.validated).length;
    }
    return { generated, validated, notValidated: generated - validated };
  }, [selectedAssessments]);

  // ── DFD — pick the most recent selected assessment with reactflow data ─────

  const dfdInfo = useMemo(() => {
    const sorted = [...selectedAssessments].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    const a = sorted.find(a => additionalInfoMap[a.id]?.reactflow);
    if (!a) return null;
    return { name: a.name, id: a.id, reactflow: additionalInfoMap[a.id].reactflow };
  }, [selectedAssessments, additionalInfoMap]);

  // ── Loading / error states ─────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-[#0a1628]">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-14 h-14">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
          </div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Loading custom analysis…</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-[#0a1628]">
        <div className="text-center">
          <p className="text-sm font-medium text-red-500">{error}</p>
          <button onClick={() => navigate('/department-threat-models')} className="mt-3 text-sm text-[#0052cc] hover:underline">← Go back</button>
        </div>
      </div>
    );
  }

  if (selectedAssessments.length === 0) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-[#0a1628]">
        <div className="text-center">
          <p className="text-sm font-medium text-slate-600 dark:text-slate-400">No matching sub-models found.</p>
          <button onClick={() => navigate('/department-threat-models')} className="mt-3 text-sm text-[#0052cc] hover:underline">← Back to Threat Models</button>
        </div>
      </div>
    );
  }

  const colors   = getDepartmentColors('custom');
  const gradient = colors.gradient;

  // ── Main render ────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#0a1628] dark-grid-bg">
      <div className="px-6 sm:px-8 py-8">

        <button
          onClick={() => navigate('/department-threat-models')}
          className="flex items-center gap-1.5 text-sm font-medium text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 mb-6 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Threat Models
        </button>

        <div className="flex gap-5 items-start">

          {/* Left column */}
          <div className="flex-1 min-w-0 space-y-5">

            {/* Header card */}
            <div className="bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-2xl shadow-sm overflow-hidden">
              <div className={`h-1.5 w-full bg-gradient-to-r ${gradient}`} />
              <div className="p-6 flex items-center justify-between flex-wrap gap-4">
                <div className="flex items-center gap-4">
                  <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${gradient} flex items-center justify-center shadow-md`}>
                    <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z" />
                    </svg>
                  </div>
                  <div>
                    <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">{customName}</h1>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">
                      {selectedAssessments.length} sub-model{selectedAssessments.length !== 1 ? 's' : ''} selected
                      {availableTabs.length > 1 && ' · STRIDE & PASTA'}
                    </p>
                  </div>
                </div>
                <div className="flex gap-2">
                  {availableTabs.map(m => (
                    <span key={m} className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${
                      m === 'PASTA'
                        ? 'bg-purple-50 text-purple-600 border-purple-200 dark:bg-purple-900/20 dark:text-purple-400 dark:border-purple-800/40'
                        : 'bg-blue-50 text-blue-600 border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800/40'
                    }`}>{m}</span>
                  ))}
                </div>
              </div>

              {/* Stats row */}
              <div className="grid grid-cols-2 sm:grid-cols-5 divide-x divide-y sm:divide-y-0 divide-slate-100 dark:divide-gray-800/60 border-t border-slate-100 dark:border-gray-800/60">
                {[
                  { label: 'Sub-Models',     value: selectedAssessments.length, color: 'text-slate-800 dark:text-slate-100' },
                  { label: 'Total Threats',  value: rawTotalThreats,             color: 'text-slate-800 dark:text-slate-100' },
                  { label: 'Unique Threats', value: totalThreats,                color: 'text-slate-800 dark:text-slate-100' },
                  { label: 'Common Threats', value: totalCommon,                 color: 'text-amber-600 dark:text-amber-400' },
                  { label: 'High / Critical',value: totalHighRisk,              color: totalHighRisk > 0 ? 'text-red-600 dark:text-red-400' : 'text-slate-400' },
                ].map(stat => (
                  <div key={stat.label} className="px-5 py-4 text-center">
                    <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
                    <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mt-0.5">{stat.label}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Threats by Type — STRIDE / PASTA side-by-side when both exist */}
            <div className={`grid grid-cols-1 ${strideAssessments.length > 0 && pastaAssessments.length > 0 ? 'sm:grid-cols-2' : ''} gap-4`}>
              {strideAssessments.length > 0 && (
                <ThreatTypeTableCard
                  threatsByType={strideThreatsByType}
                  total={strideRawTotal}
                  title="STRIDE — Threats by Type"
                  methodology="STRIDE"
                />
              )}
              {pastaAssessments.length > 0 && (
                <ThreatTypeTableCard
                  threatsByType={pastaThreatsByType}
                  total={pastaRawTotal}
                  title="PASTA — Threats by Risk"
                  methodology="PASTA"
                />
              )}
            </div>

            {/* Risk Distribution + Test Cases */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <StatTableCard
                title="Risk Distribution"
                entries={riskOrder.map(r => ({
                  label: r,
                  value: riskCounts[r] ?? 0,
                  color: RISK_COLORS[r],
                  dimmed: (riskCounts[r] ?? 0) === 0,
                }))}
              />
              <StatTableCard
                title="Test Cases"
                badge={testCaseStats.generated > 0 ? `${testCaseStats.generated} generated` : undefined}
                entries={[
                  { label: 'Generated',     value: testCaseStats.generated,   color: '#64748b' },
                  { label: 'Validated',     value: testCaseStats.validated,    color: '#22c55e' },
                  { label: 'Not Validated', value: testCaseStats.notValidated, color: '#94a3b8' },
                ]}
              />
            </div>

            {/* Data Flow Diagrams */}
            <ConsolidatedDfdCard
              subModelCount={selectedAssessments.length}
              groupId={`custom_${customId ?? ''}`}
              assessmentIds={selectedAssessments.map(a => a.id)}
            />
            {dfdInfo && <DfdCard name={dfdInfo.name} id={dfdInfo.id} reactflow={dfdInfo.reactflow} />}

            {/* Third-party Vendors */}
            <VendorsCard assessments={enrichedAssessments} />

          </div>

          {/* Right column — sidebar */}
          <div className="w-[22%] flex-shrink-0 sticky top-4 self-start space-y-3">

            <button
              onClick={() => navigate(`/department-threat-models/custom/${customId}/threats`)}
              className="w-full flex items-center justify-between px-4 py-3 rounded-xl bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 shadow-sm hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors"
            >
              <div className="flex items-center gap-2">
                <svg className="w-4 h-4 flex-shrink-0 text-slate-500 dark:text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">View All Threats</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-xs font-bold text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-gray-800 px-1.5 py-0.5 rounded-full">{totalThreats}</span>
                <svg className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
              </div>
            </button>

            <div className="bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl shadow-sm overflow-hidden">
              <button
                onClick={() => setSidebarOpen(v => !v)}
                className="w-full flex items-center justify-between px-4 py-3.5 hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <svg className="w-4 h-4 text-slate-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                  </svg>
                  <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">Sub-Models</span>
                  <span className="text-xs font-bold text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-gray-800 px-1.5 py-0.5 rounded-full">{selectedAssessments.length}</span>
                </div>
                <svg className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${sidebarOpen ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {sidebarOpen && (
                <div className="border-t border-slate-100 dark:border-gray-800/60 divide-y divide-slate-100 dark:divide-gray-800/40 overflow-y-auto max-h-[calc(100vh-20rem)]">
                  {selectedAssessments.map((a, idx) => {
                    const isPasta = isPastaAssessment(a);
                    return (
                      <div key={a.id} className="px-4 py-3 hover:bg-slate-50 dark:hover:bg-gray-800/30 transition-colors">
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-start gap-2 min-w-0">
                            <span className="flex-shrink-0 mt-0.5 w-4 h-4 rounded-full bg-slate-100 dark:bg-gray-800 text-[10px] font-bold text-slate-500 dark:text-slate-400 flex items-center justify-center">{idx + 1}</span>
                            <div className="min-w-0">
                              <p className="text-xs font-semibold text-slate-700 dark:text-slate-300 leading-snug truncate">{a.name}</p>
                              <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                                {a.details?.department && (
                                  <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-slate-100 text-slate-600 dark:bg-gray-800 dark:text-slate-400">{a.details.department}</span>
                                )}
                                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full border ${isPasta ? 'bg-purple-50 text-purple-600 border-purple-200 dark:bg-purple-900/20 dark:text-purple-400 dark:border-purple-800/40' : 'bg-blue-50 text-blue-600 border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800/40'}`}>
                                  {isPasta ? 'PASTA' : 'STRIDE'}
                                </span>
                                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-full bg-slate-50 text-slate-400 dark:bg-gray-800/50 dark:text-slate-600 border border-slate-200 dark:border-gray-700/40">
                                  #{a.id.slice(0, 8)}
                                </span>
                              </div>
                              <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">{formatDate(a.timestamp)}</p>
                              <p className="text-[10px] text-slate-400 dark:text-slate-500">{a.threat_model?.result?.raw_response?.threat_model?.length ?? 0} threats</p>
                            </div>
                          </div>
                          <Link to={`/view-threat-model/${a.id}`} className="flex-shrink-0 mt-0.5 p-1 rounded-md text-slate-400 hover:text-[#0052cc] dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors" title="View sub-model">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                            </svg>
                          </Link>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
            <SecBugsCard secbugs={secbugs} />
          </div>

        </div>
      </div>
    </div>
  );
};

export default CustomDepartmentDetail;
