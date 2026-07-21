// Base interfaces for data structures
export interface Threat {
  'Threat Type': string;
  'Scenario': string;
  'Potential Impact': string;
  'Confidence'?: string;
}

// PASTA specific threat interface
export interface DiagramData {
  intro: string;
  diagram: string;
  description: string;
}

export interface PastaThreat {
  'Threat Type': string;
  'Scenario': string;
  'Business Risk Type': string[];
  'PASTA Stage': string;
  'Potential Impact': string;
  'Confidence'?: string;
}

export interface DreadAssessmentItem {
  'Threat Type': string;
  'Scenario': string;
  'Damage Potential': number;
  'Reproducibility': number;
  'Exploitability': number;
  'Affected Users': number;
  'Discoverability': number;
  'DEPARTMENT'?: string; // Optional DEPARTMENT (Department) field
}

export interface ASVSTestCase {
  'Threat Type': string;
  'Scenario': string;
  asvs_requirement: string;  // Changed from string[] to string to match actual data
  test_cases: Array<{
    test_description: string;
    steps: string[];
    expected_result: string;
    prerequisites?: string;
    test_data?: string;
    validation_criteria?: string;
    validated?: boolean;
  }>;
}

export interface ASVSTestCaseResponse {
  timestamp: string;
  result: {
    test_cases: ASVSTestCase[];  // Changed from test_plan to test_cases
  };
}

export interface TestCaseCountInfo {
  total: number;
  validated: number;
}

export interface AttackTreeNode {
  id: string;
  type: "goal" | "attack" | "vulnerability";
  label: string;
  children?: AttackTreeNode[];
  data?: {
    label: string;
  };
  position?: {
    x: number;
    y: number;
  };
}

// Component-specific response types
export interface ThreatModelResponse {
  timestamp: string;
  result: {
    raw_response: {
      threat_model: (Threat | PastaThreat)[];
      improvement_suggestions: string[];
    };
    markdown: string;
  };
}

export interface DreadAssessmentResult {
  raw_response: {
    'Risk Assessment': DreadAssessmentItem[];
  };
  markdown: string;
}

export interface DreadAssessmentResponse {
  timestamp: string;
  result: DreadAssessmentResult | {
    result: DreadAssessmentResult;
  };
}

export interface MitigationItem {
  'Threat Type'?: string;
  'Business Risk Type'?: string | string[];
  'PASTA Stage'?: string;
  'Scenario': string;
  'Suggested Mitigation(s)': string;
}

export interface MitigationResponse {
  timestamp: string;
  result: {
    raw_response: {
      mitigations: MitigationItem[];
    };
  };
}

export interface AttackTreeResponse {
  timestamp: string;
  result: {
    attack_tree: {
      nodes: AttackTreeNode[];
      total_paths?: number;
    };
    markdown: string;
  };
}

// Project details interface
export interface ProjectDetails {
  projectName: string;
  description: string;
  documentSource: 'pdf' | 'confluence';
  confluenceUrl?: string;
  department: string;
  applicationType: string;
  isInternetFacing: boolean;
  dataSensitivityLevel: 'Highest' | 'High' | 'Medium' | 'Low';
  authenticationMethod: 'SSO' | 'MFA' | 'OAUTH' | 'BASIC' | 'JWT';
  timestamp: string;
  threatModelingMethodology?: string; // Added for methodology badge
}

// Report metadata interface
export interface ReportMetadata {
  id: string;
  name: string;
  timestamp: string;
  threat_model?: ThreatModelResponse;
  dread_assessment?: DreadAssessmentResponse;
  mitigation?: MitigationResponse;
  attack_tree?: AttackTreeResponse;
  test_cases?: ASVSTestCaseResponse;
  details?: ProjectDetails;
  [key: string]: any; // Allow dynamic indexing with string keys
}

// Main report response interface
export interface ReportResponse {
  timestamp: string;
  result: {
    threat_model?: {
      timestamp: string;
      result: {
        raw_response: {
          threat_model: Array<{
            'Threat Type': string;
            'Scenario': string;
            'Potential Impact': string;
          }>;
          improvement_suggestions: string[];
        };
      };
    };
    dread_assessment?: {
      timestamp: string;
      result: {
        raw_response: {
          'Risk Assessment': Array<{
            'Threat Type': string;
            'Scenario': string;
            'Damage Potential': number;
            'Reproducibility': number;
            'Exploitability': number;
            'Affected Users': number;
            'Discoverability': number;
          }>;
        };
      };
    };
    mitigation?: {
      timestamp: string;
      result: {
        raw_response: {
          mitigations: MitigationItem[];
        };
      };
    };
    attack_tree?: {
      timestamp: string;
      result: {
        markdown: string;
      };
    };
  };
}
