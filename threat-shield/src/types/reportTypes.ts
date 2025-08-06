export interface Threat {
  'Threat Type': string;
  'Scenario': string;
  'Potential Impact': string;
}

export interface DreadAssessmentItem {
  'Threat Type': string;
  'Scenario': string;
  'Damage Potential': number;
  'Reproducibility': number;
  'Exploitability': number;
  'Affected Users': number;
  'Discoverability': number;
}

export interface AttackTreeNode {
  id: string;
  type: 'goal' | 'attack' | 'vulnerability';
  label: string;
  children?: AttackTreeNode[];
}

export interface AttackTree {
  nodes: AttackTreeNode[];
  total_paths?: number;
}

export interface MitigationItem {
  'Threat Type': string;
  'Scenario': string;
  'Mitigations': string[];
  'Suggested Mitigation(s)'?: string;
}

export interface ProjectDetails {
  projectName: string;
  timestamp: string;
  threatModelingMethodology?: string;
}

export interface ReportDetails extends ProjectDetails {
  [key: string]: any;
}

export interface ReportMetadata {
  id: string;
  name?: string;
  timestamp?: string;
  details?: ReportDetails;
  threat_model?: ThreatModelResponse;
  dread_assessment?: DreadAssessmentResponse;
  mitigation?: MitigationResponse;
  attack_tree?: AttackTreeResponse;
  [key: string]: any; // Allow string indexing
}

export interface ThreatModelResponse {
  timestamp: string;
  result: {
    result: {
      raw_response: {
        threat_model: Threat[];
        improvement_suggestions: string[];
      };
      markdown: string;
      threat_model?: Threat[];
    };
  };
}

export interface DreadAssessmentResponse {
  timestamp: string;
  result: {
    result: {
      raw_response: {
        'Risk Assessment': DreadAssessmentItem[];
      };
      markdown: string;
    };
  };
}

export interface MitigationResponse {
  timestamp: string;
  result: {
    result?: {
      raw_response: {
        mitigations: MitigationItem[];
      };
      markdown: string;
    };
    raw_response?: {
      mitigations: MitigationItem[];
    };
    markdown: string;
  };
}

export interface AttackTreeResponse {
  timestamp: string;
  result: {
    result: {
      markdown: string;
      attack_tree?: AttackTree;
    };
  };
}

export interface ReportResponse {
  timestamp: string;
  result: {
    threat_model?: ThreatModelResponse;
    dread_assessment?: DreadAssessmentResponse;
    mitigation?: MitigationResponse;
    attack_tree?: AttackTreeResponse;
  };
}
