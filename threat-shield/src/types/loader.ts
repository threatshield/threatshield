export type LoaderStage = 'upload' | 'threat-model' | 'parallel-analysis' | 'attack-tree' | 'dread' | 'mitigation' | 'security-test-cases' | 'complete';

export interface LogEntry {
  id: string;
  text: string;
  timestamp: number;
  indent?: number;
  type?: 'info' | 'success' | 'warning' | 'error' | 'task';
}

export interface LoaderState {
  stage: LoaderStage;
  progress: number;
  message: string;
  logs: LogEntry[];
}

export const stageMessages: Record<LoaderStage, string> = {
  'upload': 'Uploading and processing documents...',
  'threat-model': 'Generating threat model...',
  'parallel-analysis': 'Generating Attack Tree, DREAD, Mitigations and Test Cases...',
  'attack-tree': 'Generating Attack Tree...',
  'dread': 'Performing DREAD assessment...',
  'mitigation': 'Generating mitigations...',
  'security-test-cases': 'Generating ASVS security test cases...',
  'complete': 'Assessment complete!'
};

export const stageProgress: Record<LoaderStage, number> = {
  'upload': 15,
  'threat-model': 30,
  'parallel-analysis': 65,
  'attack-tree': 45,
  'dread': 60,
  'mitigation': 75,
  'security-test-cases': 90,
  'complete': 100
};
