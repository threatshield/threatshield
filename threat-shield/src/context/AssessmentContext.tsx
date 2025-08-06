import React, { createContext, useState, useContext } from 'react';

import { 
  ThreatModelResponse,
  DreadAssessmentResponse,
  MitigationResponse,
  AttackTreeResponse
} from '../types/reportTypes';

interface AssessmentContextType {
  assessmentId: string | null;
  setAssessmentId: (id: string) => void;
  threatModelData: ThreatModelResponse | null;
  setThreatModelData: (data: ThreatModelResponse) => void;
  dreadData: DreadAssessmentResponse | null;
  setDreadData: (data: DreadAssessmentResponse) => void;
  mitigationData: MitigationResponse | null;
  setMitigationData: (data: MitigationResponse) => void;
  attackTreeData: AttackTreeResponse | null;
  setAttackTreeData: (data: AttackTreeResponse | null) => void;
  loading: boolean;
  setLoading: (loading: boolean) => void;
  error: string | null;
  setError: (error: string | null) => void;
}

const AssessmentContext = createContext<AssessmentContextType | undefined>(undefined);

export const AssessmentProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [threatModelData, setThreatModelData] = useState<ThreatModelResponse | null>(null);
  const [dreadData, setDreadData] = useState<DreadAssessmentResponse | null>(null);
  const [mitigationData, setMitigationData] = useState<MitigationResponse | null>(null);
  const [attackTreeData, setAttackTreeData] = useState<AttackTreeResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <AssessmentContext.Provider value={{
      assessmentId,
      setAssessmentId,
      threatModelData,
      setThreatModelData,
      dreadData,
      setDreadData,
      mitigationData,
      setMitigationData,
      attackTreeData,
      setAttackTreeData,
      loading,
      setLoading,
      error,
      setError
    }}>
      {children}
    </AssessmentContext.Provider>
  );
};

export const useAssessment = () => {
  const context = useContext(AssessmentContext);
  if (context === undefined) {
    throw new Error('useAssessment must be used within an AssessmentProvider');
  }
  return context;
};

export default AssessmentContext;
