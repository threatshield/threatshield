export type LoaderStage = 'upload' | 'threat-model' | 'attack-tree' | 'dread' | 'mitigation' | 'complete';

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
  'attack-tree': 'Generating Attack Tree...',
  'dread': 'Performing DREAD assessment...',
  'mitigation': 'Generating mitigations...',
  'complete': 'Assessment complete!'
};

export const stageProgress: Record<LoaderStage, number> = {
  'upload': 20,
  'threat-model': 40,
  'attack-tree': 60,
  'dread': 80,
  'mitigation': 90,
  'complete': 100
};
