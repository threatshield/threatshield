// Jaccard-based node consolidation for consolidated DFD diagrams.
// Mirrors the threat consolidation algorithm from threatConsolidation.ts but
// operates on diagram node labels within the same category (node type).
// Cross-category merging is explicitly prohibited.

import { jaccardSimilarity } from './threatConsolidation';

// Default threshold — slightly higher than the threat threshold (0.28) because
// node labels are shorter and more precise.
export const DIAGRAM_SIMILARITY_THRESHOLD = 0.35;

// Per-category overrides.
// Microservices need a much higher bar: "service" is near-ubiquitous as a
// suffix, so almost every pair shares one token and gets a Jaccard ≈ 0.33.
// Union-Find transitivity makes this worse — A~B~C collapses even when A and C
// would never merge directly. 0.6 requires meaningful semantic overlap beyond
// the bare "service" suffix.
export const CATEGORY_THRESHOLDS: Record<string, number> = {
  'Microservice': 0.6,
};

// Infrastructure-specific synonym normalization applied on top of the base
// security synonyms already baked into jaccardSimilarity.
const INFRA_SYNONYMS: Array<[RegExp, string]> = [
  [/\b(database|datastore|data\s*store|data\s*lake|warehouse|repo(?:sitory)?)\b/gi, 'database'],
  [/\b(gateway|ingress|proxy|load.?balancer|lb|nlb|alb)\b/gi, 'gateway'],
  [/\b(cache|redis|memcache\w*|elasticache)\b/gi, 'cache'],
  [/\b(queue|broker|kafka|rabbitmq|sqs|pubsub|message.?bus|event.?bus)\b/gi, 'queue'],
  [/\b(service|svc|ms|microservice|handler|processor|worker)\b/gi, 'service'],
  [/\b(infra\w*|infrastructure|platform|cloud|hosting)\b/gi, 'infra'],
  [/\b(app(?:lication)?|portal|dashboard|ui|frontend|client)\b/gi, 'client'],
  [/\b(auth\w*|identity|iam|sso|login|oauth\w*)\b/gi, 'auth'],
  [/\b(storage|s3|blob|gcs|object.?store)\b/gi, 'storage'],
  [/\b(monitor\w*|observ\w*|alert\w*|log(?:ging)?|tracing)\b/gi, 'monitor'],
];

function normalizeNodeLabel(label: string): string {
  let r = label.toLowerCase();
  for (const [re, rep] of INFRA_SYNONYMS) r = r.replace(re, rep);
  return r;
}

// Jaccard over infra-normalized labels. The jaccardSimilarity import already
// handles security synonyms + stop-word removal + tokenization internally,
// so we pass the already-normalized strings directly.
function nodeJaccard(a: string, b: string): number {
  return jaccardSimilarity(normalizeNodeLabel(a), normalizeNodeLabel(b));
}

export interface MergedNodeData {
  label: string;
  type: string;            // node category, e.g. 'API Gateway'
  similarNames?: string[]; // other labels merged into this canonical node
}

export interface ConsolidatedDiagramResult {
  nodes: any[];  // ReactFlow node objects with MergedNodeData in .data
  edges: any[];  // ReactFlow edge objects with remapped source/target
}

/**
 * Consolidates ReactFlow diagram nodes using Jaccard similarity, strictly
 * within each category (node type). Never merges across categories.
 *
 * For each cluster of similar nodes the canonical representative is the node
 * with the shortest label (most generic name). The other labels are stored in
 * data.similarNames so the UI can surface them via the 'i' icon.
 *
 * Edges whose source or target maps to a merged-away node are rewritten to
 * point to the canonical node, and resulting duplicates / self-loops are
 * removed.
 */
export function consolidateDiagramNodes(
  nodes: any[],
  edges: any[],
): ConsolidatedDiagramResult {
  if (!nodes.length) return { nodes: [], edges };

  // Group by category (data.type)
  const byCategory = new Map<string, any[]>();
  for (const n of nodes) {
    const cat = (n.data?.type ?? 'Microservice') as string;
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat)!.push(n);
  }

  // old-id → canonical-id remapping built during cluster resolution
  const idRemap = new Map<string, string>();
  const resultNodes: any[] = [];

  for (const [cat, catNodes] of byCategory.entries()) {
    const n = catNodes.length;
    if (n === 0) continue;

    // Use a category-specific threshold if defined, otherwise fall back to default
    const threshold = CATEGORY_THRESHOLDS[cat] ?? DIAGRAM_SIMILARITY_THRESHOLD;

    if (n === 1) {
      resultNodes.push(catNodes[0]);
      idRemap.set(catNodes[0].id, catNodes[0].id);
      continue;
    }

    // Union-Find with path compression — transitive closure within category
    const parent = catNodes.map((_, i) => i);
    function find(x: number): number {
      return parent[x] === x ? x : (parent[x] = find(parent[x]));
    }
    function union(x: number, y: number) {
      parent[find(x)] = find(y);
    }

    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const labelA = catNodes[i].data?.label || catNodes[i].id;
        const labelB = catNodes[j].data?.label || catNodes[j].id;
        if (nodeJaccard(labelA, labelB) >= threshold) {
          union(i, j);
        }
      }
    }

    // Collect clusters
    const clusterMap = new Map<number, any[]>();
    for (let i = 0; i < n; i++) {
      const root = find(i);
      if (!clusterMap.has(root)) clusterMap.set(root, []);
      clusterMap.get(root)!.push(catNodes[i]);
    }

    for (const [, cluster] of clusterMap.entries()) {
      // Canonical = shortest label (most generic); ties broken by first seen
      const canonical = cluster.reduce((best, cur) => {
        const bestLen = (best.data?.label || best.id).length;
        const curLen = (cur.data?.label || cur.id).length;
        return curLen < bestLen ? cur : best;
      });

      const similarNames = cluster
        .filter(node => node.id !== canonical.id)
        .map(node => node.data?.label || node.id);

      for (const node of cluster) {
        idRemap.set(node.id, canonical.id);
      }

      resultNodes.push({
        ...canonical,
        data: {
          ...canonical.data,
          similarNames: similarNames.length > 0 ? similarNames : undefined,
        },
      });
    }
  }

  // Remap edges + deduplicate + drop self-loops
  const seen = new Set<string>();
  const resultEdges: any[] = [];
  for (const e of edges) {
    const src = idRemap.get(e.source) ?? e.source;
    const tgt = idRemap.get(e.target) ?? e.target;
    if (src === tgt) continue;
    const key = `${src}→${tgt}`;
    if (seen.has(key)) continue;
    seen.add(key);
    resultEdges.push({ ...e, source: src, target: tgt });
  }

  return { nodes: resultNodes, edges: resultEdges };
}
