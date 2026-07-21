// Shared threat consolidation utilities used by DepartmentThreatModels and DepartmentThreatModelDetail.
// Single source of truth for similarity computation, clustering, color palette, and DEPARTMENT summaries.

// ── Types ─────────────────────────────────────────────────────────────────────

export interface Threat {
  'Threat Type'?: string;
  'Scenario': string;
  'Potential Impact'?: string;
  'Business Risk Type'?: string | string[];
  'PASTA Stage'?: string;
}

export interface DreadItem {
  'Threat Type': string;
  'Scenario': string;
  'Damage Potential': number;
  'Reproducibility': number;
  'Exploitability': number;
  'Affected Users': number;
  'Discoverability': number;
}

export interface TestCaseItem {
  'Threat Type': string;
  Scenario: string;
  asvs_requirement?: string;
  test_cases?: Array<{
    test_description?: string;
    steps?: string[];
    expected_result?: string;
    prerequisites?: string;
    validation_criteria?: string;
  }>;
  validated?: boolean;
}

export interface AssessmentData {
  id: string;
  name: string;
  timestamp: string;
  data_flow_diagram_code?: string;
  third_party_integrations_text?: string;
  details?: {
    department?: string;
    threatModelingMethodology?: string;
    dataSensitivityLevel?: string;
    projectName?: string;
  };
  threat_model?: {
    result?: {
      raw_response?: {
        threat_model?: Threat[];
        improvement_suggestions?: string[];
      };
    };
  };
  dread_assessment?: {
    result?: {
      raw_response?: {
        'Risk Assessment'?: DreadItem[];
      };
    };
  };
  test_cases?: {
    result?: {
      test_cases?: TestCaseItem[];
    };
  };
}

export interface ContributingAssessment {
  id: string;
  name: string;
  timestamp: string;
  originalScenario: string;
  dreadScore: number;
}

export interface ConsolidatedThreat {
  key: string;
  threatType: string;
  scenario: string;
  potentialImpact: string;
  occurrenceCount: number;
  isCommon: boolean;
  avgDreadScore: number;
  maxDreadScore: number;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown';
  contributingAssessments: ContributingAssessment[];
  methodology: 'STRIDE' | 'PASTA';
  businessRiskTypes: string[];
}

export interface DepartmentColorScheme {
  gradient: string;
  badge: string;
  statHighlight: string;
  iconBg: string;
}

export interface DepartmentSummary {
  department: string;
  displayName: string;
  assessments: AssessmentData[];
  strideAssessments: AssessmentData[];
  pastaAssessments: AssessmentData[];
  // Consolidated (deduplicated) counts — same source as the detail page
  strideThreats: ConsolidatedThreat[];
  pastaThreats: ConsolidatedThreat[];
  totalThreats: number;
  commonThreats: number;
  highRiskThreats: number;
  methodologies: ('STRIDE' | 'PASTA')[];
  latestTimestamp: string;
}

// ── Similarity ────────────────────────────────────────────────────────────────

const STOP_WORDS = new Set([
  'the','a','an','and','or','but','in','on','at','to','for','of','with','by',
  'from','as','is','was','are','were','be','been','this','that','it','its',
  'can','could','via','into','upon','over','through',
]);

// Maps security synonyms to canonical tokens before Jaccard computation so
// "JWT replay" and "OAuth token spoofing" share enough tokens to cluster.
const SECURITY_SYNONYMS: Array<[RegExp, string]> = [
  [/\b(jwt|oauth2?|bearer|saml|session|cookie|ticket|assertion|credential|auth(?:entication|orization)?)\b/gi, 'authtoken'],
  [/\b(spoof(?:ing)?|forg(?:e|ed|ing)|fake|counterfeit|fabricat\w*|impersonat\w*)\b/gi, 'spoof'],
  [/\b(replay\w*|re-?use\w*|resubmit\w*)\b/gi, 'replay'],
  [/\b(steal\w*|hijack\w*|intercept\w*|captur\w*|exfiltrat\w*|extract\w*|harvest\w*)\b/gi, 'steal'],
  [/\b(attacker|adversar\w*|hacker|threat\s*actor|malicious\s*(?:user|actor|party))\b/gi, 'attacker'],
  [/\b(api|endpoint|microservice|backend|web\s*service|rest\s*api)\b/gi, 'service'],
  [/\b(inject\w*|xss|cross.site\w*|sqli|sql\s*injection|command\s*injection)\b/gi, 'inject'],
  [/\b(escalat\w*|privilege|elevat\w*|admin(?:istrat\w*)?|root|superuser)\b/gi, 'privilege'],
  [/\b(dos|ddos|denial.of.service|flood\w*|overload\w*|exhaust\w*|resource\s*exhaustion)\b/gi, 'dos'],
  [/\b(leak\w*|expos\w*|disclos\w*|reveal\w*|pii|personal\s*data|sensitive\s*(?:data|info\w*)|confidential)\b/gi, 'leak'],
  [/\b(unauthori[sz]ed|unauthenticated|bypass\w*|circumvent\w*)\b/gi, 'unauthorized'],
  [/\b(password|passphrase|plaintext|cleartext|private\s*key|signing\s*key)\b/gi, 'secret'],
  [/\b(user|customer|account|identity|principal|end.?user)\b/gi, 'user'],
  [/\b(access|authoriz\w*|permission|role|grant|entitlement)\b/gi, 'access'],
  [/\b(validat\w*|verif\w*|sanitiz\w*)\b/gi, 'validate'],
  [/\b(encrypt\w*|decrypt\w*|tls|ssl|https|cipher\w*)\b/gi, 'crypto'],
  [/\b(log(?:ging)?|audit\s*(?:trail?|log)?)\b/gi, 'auditlog'],
  [/\b(config(?:uration)?|setting\w*|env(?:ironment)?\s*var\w*)\b/gi, 'config'],
  [/\b(signature|sign(?:ed|ing)|hmac|rsa|ecdsa)\b/gi, 'sign'],
  [/\b(server|application|system|platform|component)\b/gi, 'system'],
];

export const SIMILARITY_THRESHOLD = 0.28;

function normalizeSecurity(s: string): string {
  let r = s.toLowerCase();
  for (const [re, rep] of SECURITY_SYNONYMS) r = r.replace(re, rep);
  return r;
}

function tokenize(s: string): string[] {
  return normalizeSecurity(s)
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2 && !STOP_WORDS.has(w));
}

export function jaccardSimilarity(a: string, b: string): number {
  const setA = new Set(tokenize(a));
  const setB = new Set(tokenize(b));
  if (setA.size === 0 && setB.size === 0) return 1;
  const intersection = [...setA].filter(x => setB.has(x)).length;
  const union = new Set([...setA, ...setB]).size;
  return union === 0 ? 0 : intersection / union;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function isPastaAssessment(a: AssessmentData): boolean {
  if (a.details?.threatModelingMethodology?.toUpperCase() === 'PASTA') return true;
  const first = a.threat_model?.result?.raw_response?.threat_model?.[0];
  return !!(first && ('Business Risk Type' in first || 'PASTA Stage' in first));
}

export function computeDreadScore(
  dreadData: AssessmentData['dread_assessment'],
  scenario: string,
  threatType: string,
): number {
  const items = dreadData?.result?.raw_response?.['Risk Assessment'] ?? [];
  const match = items.find(item =>
    item['Threat Type'] === threatType && jaccardSimilarity(item['Scenario'], scenario) > 0.3
  );
  if (!match) return 0;
  return (
    (match['Damage Potential'] ?? 0) + (match['Reproducibility'] ?? 0) +
    (match['Exploitability'] ?? 0) + (match['Affected Users'] ?? 0) +
    (match['Discoverability'] ?? 0)
  ) / 5;
}

// Direct score from a raw DreadItem — no Jaccard matching, matches Analytics.tsx logic.
export function computeRawDreadScore(item: DreadItem): number {
  return (
    (item['Damage Potential'] ?? 0) + (item['Reproducibility'] ?? 0) +
    (item['Exploitability'] ?? 0)   + (item['Affected Users'] ?? 0) +
    (item['Discoverability'] ?? 0)
  ) / 5;
}

function toRiskLevel(score: number): ConsolidatedThreat['riskLevel'] {
  if (score === 0) return 'Unknown';
  if (score >= 9) return 'Critical';
  if (score >= 8) return 'High';
  if (score >= 6) return 'Medium';
  return 'Low';
}

export function formatDate(ts: string): string {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
  } catch {
    return '—';
  }
}

// ── Consolidation ─────────────────────────────────────────────────────────────

function toStringArray(v: string | string[] | undefined): string[] {
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
}

export function consolidateThreats(
  assessments: AssessmentData[],
  methodology: 'STRIDE' | 'PASTA',
): ConsolidatedThreat[] {
  type ThreatEntry = { threat: Threat; assessment: AssessmentData; dreadScore: number };

  const entries: ThreatEntry[] = [];
  for (const a of assessments) {
    for (const t of a.threat_model?.result?.raw_response?.threat_model ?? []) {
      entries.push({
        threat: t,
        assessment: a,
        dreadScore: computeDreadScore(a.dread_assessment, t['Scenario'], t['Threat Type'] ?? ''),
      });
    }
  }

  const byType: Record<string, ThreatEntry[]> = {};
  for (const e of entries) {
    const type = e.threat['Threat Type'] ?? 'Unknown';
    if (!byType[type]) byType[type] = [];
    byType[type].push(e);
  }

  const consolidated: ConsolidatedThreat[] = [];

  for (const [threatType, typeEntries] of Object.entries(byType)) {
    const n = typeEntries.length;
    if (n === 0) continue;

    // Union-Find: transitive closure — if A~B and B~C, all three merge
    const parent = typeEntries.map((_, i) => i);
    const find = (x: number): number =>
      parent[x] === x ? x : (parent[x] = find(parent[x]));
    const union = (x: number, y: number) => { parent[find(x)] = find(y); };

    for (let i = 0; i < n; i++)
      for (let j = i + 1; j < n; j++)
        if (jaccardSimilarity(typeEntries[i].threat['Scenario'], typeEntries[j].threat['Scenario']) >= SIMILARITY_THRESHOLD)
          union(i, j);

    const clusterMap = new Map<number, ThreatEntry[]>();
    for (let i = 0; i < n; i++) {
      const root = find(i);
      if (!clusterMap.has(root)) clusterMap.set(root, []);
      clusterMap.get(root)!.push(typeEntries[i]);
    }

    for (const [rootIdx, cluster] of clusterMap.entries()) {
      const canonical = cluster.reduce((best, cur) => {
        if (cur.dreadScore > best.dreadScore) return cur;
        if (cur.dreadScore === best.dreadScore && cur.assessment.timestamp > best.assessment.timestamp) return cur;
        return best;
      });

      const dreadScores = cluster.map(c => c.dreadScore).filter(s => s > 0);
      const avgDread = dreadScores.length > 0
        ? dreadScores.reduce((a, b) => a + b, 0) / dreadScores.length : 0;
      const maxDread = dreadScores.length > 0 ? Math.max(...dreadScores) : 0;

      consolidated.push({
        key: `${threatType}-${rootIdx}`,
        threatType,
        scenario: canonical.threat['Scenario'],
        potentialImpact: canonical.threat['Potential Impact'] ?? '',
        occurrenceCount: cluster.length,
        isCommon: cluster.length >= 2,
        avgDreadScore: avgDread,
        maxDreadScore: maxDread,
        riskLevel: toRiskLevel(maxDread || avgDread),
        contributingAssessments: cluster.map(c => ({
          id: c.assessment.id,
          name: c.assessment.name,
          timestamp: c.assessment.timestamp,
          originalScenario: c.threat['Scenario'],
          dreadScore: c.dreadScore,
        })),
        methodology,
        businessRiskTypes: toStringArray(canonical.threat['Business Risk Type']),
      });
    }
  }

  return consolidated.sort((a, b) => {
    if (a.isCommon !== b.isCommon) return a.isCommon ? -1 : 1;
    return b.maxDreadScore - a.maxDreadScore;
  });
}

// ── DEPARTMENT summaries ─────────────────────────────────────────────────────────────

export function computeDepartmentSummaries(assessments: AssessmentData[]): DepartmentSummary[] {
  // Group case-insensitively so "Wealth", "wealth", "WEALTH" all merge into one DEPARTMENT.
  // The display name is taken from the first (most common) casing encountered.
  const departmentMap: Record<string, AssessmentData[]> = {};
  const departmentDisplayName: Record<string, string> = {};
  for (const a of assessments) {
    const raw = (a.details?.department ?? '').trim();
    if (!raw) continue;
    const key = raw.toLowerCase();
    if (!departmentMap[key]) {
      departmentMap[key] = [];
      departmentDisplayName[key] = raw;
    }
    departmentMap[key].push(a);
  }

  return Object.entries(departmentMap)
    .map(([departmentKey, items]) => {
      const department = departmentDisplayName[departmentKey];
      const sorted = [...items].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      const stride = sorted.filter(a => !isPastaAssessment(a));
      const pasta = sorted.filter(a => isPastaAssessment(a));

      const strideThreats = consolidateThreats(stride, 'STRIDE');
      const pastaThreats = consolidateThreats(pasta, 'PASTA');
      const allThreats = [...strideThreats, ...pastaThreats];

      const methodologies: ('STRIDE' | 'PASTA')[] = [];
      if (stride.length > 0) methodologies.push('STRIDE');
      if (pasta.length > 0) methodologies.push('PASTA');

      return {
        department,
        displayName: department.toUpperCase() === department ? department : department.charAt(0).toUpperCase() + department.slice(1),
        assessments: sorted,
        strideAssessments: stride,
        pastaAssessments: pasta,
        strideThreats,
        pastaThreats,
        totalThreats: allThreats.length,
        commonThreats: allThreats.filter(t => t.isCommon).reduce((s, t) => s + t.occurrenceCount, 0),
        highRiskThreats: sorted.reduce((count, a) => {
          const items = a.dread_assessment?.result?.raw_response?.['Risk Assessment'] ?? [];
          return count + items.filter(item => computeRawDreadScore(item) >= 8).length;
        }, 0),
        methodologies,
        latestTimestamp: sorted[0]?.timestamp ?? '',
      };
    })
    .sort((a, b) => b.assessments.length - a.assessments.length);
}

// ── Color palette ─────────────────────────────────────────────────────────────
// Deterministic: color is derived from a hash of the lowercase DEPARTMENT name,
// so the same DEPARTMENT always gets the same color on every page.

export const DEPARTMENT_PALETTE: DepartmentColorScheme[] = [
  { gradient: 'from-emerald-500 to-teal-600',  badge: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300', statHighlight: 'text-emerald-600 dark:text-emerald-400', iconBg: 'bg-emerald-50 dark:bg-emerald-900/20' },
  { gradient: 'from-blue-500 to-indigo-600',    badge: 'bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',             statHighlight: 'text-blue-600 dark:text-blue-400',     iconBg: 'bg-blue-50 dark:bg-blue-900/20' },
  { gradient: 'from-violet-500 to-purple-600',  badge: 'bg-violet-50 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',     statHighlight: 'text-violet-600 dark:text-violet-400', iconBg: 'bg-violet-50 dark:bg-violet-900/20' },
  { gradient: 'from-orange-500 to-amber-600',   badge: 'bg-orange-50 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',     statHighlight: 'text-orange-600 dark:text-orange-400', iconBg: 'bg-orange-50 dark:bg-orange-900/20' },
  { gradient: 'from-sky-500 to-cyan-600',       badge: 'bg-sky-50 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300',                 statHighlight: 'text-sky-600 dark:text-sky-400',       iconBg: 'bg-sky-50 dark:bg-sky-900/20' },
  { gradient: 'from-rose-500 to-pink-600',      badge: 'bg-rose-50 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',             statHighlight: 'text-rose-600 dark:text-rose-400',     iconBg: 'bg-rose-50 dark:bg-rose-900/20' },
  { gradient: 'from-teal-500 to-green-600',     badge: 'bg-teal-50 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300',             statHighlight: 'text-teal-600 dark:text-teal-400',     iconBg: 'bg-teal-50 dark:bg-teal-900/20' },
  { gradient: 'from-slate-500 to-gray-600',     badge: 'bg-slate-100 text-slate-600 dark:bg-slate-800/60 dark:text-slate-300',        statHighlight: 'text-slate-600 dark:text-slate-400',   iconBg: 'bg-slate-50 dark:bg-slate-800/20' },
];

export function getDepartmentColors(department: string): DepartmentColorScheme {
  let hash = 0;
  const key = department.toLowerCase();
  for (let i = 0; i < key.length; i++) hash = ((hash * 31) + key.charCodeAt(i)) >>> 0;
  return DEPARTMENT_PALETTE[hash % DEPARTMENT_PALETTE.length];
}
