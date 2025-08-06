import React, { useState, useEffect, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import NavigationButtons from '../components/common/NavigationButtons';
import { useAssessment } from '../context/AssessmentContext';
import { apiService, API_BASE_URL } from '../services/api';
import { DreadAssessmentItem, AttackTreeNode, Threat, ThreatModelResponse } from '../types/reportTypes';

// Using ThreatModelResponse from reportTypes.ts

// Storage API response has a nested result structure
interface StorageApiResponse {
  timestamp: string;
  result: {
    timestamp: string;
    result: {
      raw_response: {
        threat_model?: Threat[];
        improvement_suggestions?: string[];
        nodes?: AttackTreeNode[]; // for attack tree
        'Mitigation Strategies'?: { [key: string]: string[] }; // for mitigation
        'Risk Assessment'?: DreadAssessmentItem[]; // for dread
      };
      markdown: string;
    }
  }
}

const ViewThreatModel: React.FC = () => {
  const { assessment_id } = useParams<{ assessment_id: string }>();
  const { setThreatModelData: setContextThreatModelData } = useAssessment();
  const [threatModelData, setThreatModelData] = useState<ThreatModelResponse | null>(null);
  const [dreadData, setDreadData] = useState<DreadAssessmentItem[] | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isHighRiskExpanded, setIsHighRiskExpanded] = useState<boolean>(true);
  const [hasAttackTree, setHasAttackTree] = useState<boolean>(true);
  const [hasMitigation, setHasMitigation] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [assessmentDetails, setAssessmentDetails] = useState<{
    projectName: string;
    timestamp: string;
  } | null>(null);

  const { threatModelData: contextThreatModelData } = useAssessment();

  // Fetch assessment details from storage history
  useEffect(() => {
    const fetchAssessmentDetails = async () => {
      if (assessment_id) {
        try {
          const response = await apiService.getStorageHistory();
          if (response && response.data) {
            const report = response.data.find(r => r.id === assessment_id);
            if (report && report.details) {
              setAssessmentDetails(report.details);
            } else {
              console.error('Report or details not found for assessment ID:', assessment_id);
            }
          } else {
            console.error('Failed to fetch storage history');
          }
        } catch (error) {
          console.error('Error fetching assessment details:', error);
        }
      }
    };
    
    fetchAssessmentDetails();
  }, [assessment_id]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        console.log('Fetching threat model from storage for ID:', assessment_id);
        
        if (!assessment_id) {
          throw new Error('Assessment ID is required');
        }
        
        // Fetch threat model from storage
        const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=threat_model`);
        if (!response.ok) {
          throw new Error('Failed to fetch threat model');
        }
        
        const data = await response.json();
        console.log('Raw threat model data:', data);
        
        // Ensure the data matches the expected format
        if (!data?.result?.result?.raw_response?.threat_model) {
          throw new Error('Invalid threat model data format');
        }
        
        // Transform the nested structure to match the expected format
        const transformedData: ThreatModelResponse = {
          timestamp: data.timestamp,
          result: {
            result: {
              raw_response: data.result.result.raw_response,
              markdown: data.result.result.markdown,
              threat_model: data.result.result.raw_response.threat_model
            }
          }
        };
        
        console.log('Transformed threat model data:', transformedData);
        setThreatModelData(transformedData);
        setContextThreatModelData(transformedData);

        // Fetch DREAD assessment data
        try {
          const dreadResponse = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=dread_assessment`);
          if (dreadResponse.ok) {
            const dreadData = await dreadResponse.json();
            if (dreadData?.result?.result?.raw_response?.['Risk Assessment']) {
              setDreadData(dreadData.result.result.raw_response['Risk Assessment']);
            }
          }
        } catch (err) {
          console.error('Error fetching DREAD data:', err);
        }

        // Check for Attack Tree data
        try {
          const attackTreeResponse = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=attack_tree`);
          if (attackTreeResponse.ok) {
            const attackTreeData = await attackTreeResponse.json();
            console.log('Attack Tree Response:', attackTreeData);
            // Check specifically for nodes in the attack tree response
            if (attackTreeData?.result?.result?.raw_response?.nodes) {
              setHasAttackTree(true);
            }
          }
        } catch (err) {
          console.error('Error checking attack tree data:', err);
        }

        // Check for Mitigation data
        try {
          const mitigationResponse = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=mitigation`);
          if (mitigationResponse.ok) {
            const mitigationData = await mitigationResponse.json();
            console.log('Mitigation Response:', mitigationData);
            // Check specifically for Mitigation Strategies in the response
            if (mitigationData?.result?.result?.raw_response?.['Mitigation Strategies']) {
              setHasMitigation(true);
            }
          }
        } catch (err) {
          console.error('Error checking mitigation data:', err);
        }
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to load threat model data';
        setError(errorMessage);
        console.error('Error fetching threat model:', err);
      } finally {
        setLoading(false);
      }
    };

    if (assessment_id) {
      console.log('Starting fetch for assessment ID:', assessment_id);
      fetchData();
    } else {
      console.error('No assessment ID provided');
      setError('No assessment ID provided');
    }
  }, [assessment_id, setContextThreatModelData]);

  // Get all threats
  const allThreats = useMemo(() => {
    return threatModelData?.result?.result?.raw_response?.threat_model || [];
  }, [threatModelData]);

  // Group threats by type
  const threatsByType = useMemo(() => {
    try {
      if (!threatModelData?.result?.result?.raw_response?.threat_model) {
        return {};
      }

      return threatModelData.result.result.raw_response.threat_model.reduce((acc: Record<string, Threat[]>, threat: Threat) => {
        if (!threat || !threat['Threat Type']) return acc;
        const type = threat['Threat Type'];
        if (!acc[type]) {
          acc[type] = [];
        }
        acc[type].push(threat);
        return acc;
      }, {});
    } catch (err) {
      console.error('Error processing threat model data:', err);
      return {};
    }
  }, [threatModelData]);

  // Get threat types
  const threatTypes = useMemo(() => {
    return Object.keys(threatsByType);
  }, [threatsByType]);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (error || !threatModelData) {
    return (
      <div className="max-w-6xl mx-auto p-6">
        <div className="card p-8 text-center">
          <h2 className="text-xl font-semibold text-red-600 mb-4">Error Loading Threat Model</h2>
          <p className="mb-4">{error || 'Failed to load threat model data.'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="text-center mb-10">
        <h1 className="text-4xl font-bold text-[#0052cc] mb-2">Threat Model Results</h1>
        <p className="text-xl text-gray-600 mb-2">Security analysis and identified vulnerabilities</p>
        <p className="text-lg text-blue-600 mb-3">
          {assessmentDetails ? 
            `${assessmentDetails.projectName} - ${new Date(assessmentDetails.timestamp).toLocaleDateString()}` 
            : assessment_id}
        </p>
        
        <NavigationButtons
          assessment_id={assessment_id!}
          currentPage="view-threat-model"
          hasAttackTree={hasAttackTree}
          hasDread={!!dreadData}
          hasMitigation={hasMitigation}
          viewMode={true}
        />
      </div>
      
      {/* High Risk Issues */}
      {dreadData && (
        <div className="mb-10">
          <div 
            className="flex items-center mb-6 cursor-pointer"
            onClick={() => setIsHighRiskExpanded(!isHighRiskExpanded)}
          >
            <div className="bg-red-100 p-2 rounded-full mr-3">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <h2 className="text-2xl font-semibold text-[#172b4d]">High Risk Issues</h2>
            <div className="ml-auto">
              <svg 
                xmlns="http://www.w3.org/2000/svg" 
                className={`h-6 w-6 text-[#0052cc] transform transition-transform duration-200 ${isHighRiskExpanded ? 'rotate-180' : ''}`} 
                fill="none" 
                viewBox="0 0 24 24" 
                stroke="currentColor"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </div>
          </div>

          <div className={`transition-all duration-300 ease-in-out overflow-hidden ${isHighRiskExpanded ? 'max-h-[2000px] opacity-100' : 'max-h-0 opacity-0'}`}>
            <div className="table-container shadow-sm mb-6">
              {dreadData.some(item => {
                const score = (
                  item['Damage Potential'] +
                  item['Reproducibility'] +
                  item['Exploitability'] +
                  item['Affected Users'] +
                  item['Discoverability']
                ) / 5;
                return score >= 8;
              }) ? (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Threat Type</th>
                      <th>Scenario</th>
                      <th>Risk Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dreadData
                      .map(item => ({
                        ...item,
                        score: (
                          item['Damage Potential'] +
                          item['Reproducibility'] +
                          item['Exploitability'] +
                          item['Affected Users'] +
                          item['Discoverability']
                        ) / 5
                      }))
                      .filter(item => item.score >= 8)
                      .map((item, index) => (
                        <tr key={index}>
                          <td className="font-medium">{item['Threat Type']}</td>
                          <td>{item['Scenario']}</td>
                          <td>
                            <div className="px-3 py-1 rounded-full text-center font-medium text-red-600 bg-red-50">
                              {item.score.toFixed(1)}
                            </div>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              ) : (
                <div className="text-center p-8 bg-gray-50 rounded-lg">
                  <p className="text-gray-600">No high risk issues found</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Threat Categories */}
      <div className="mb-10">
        <div className="flex items-center mb-6">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Threat Categories</h2>
        </div>
        <div className="flex flex-wrap gap-2">
          {threatTypes.length > 0 ? threatTypes.map(type => (
            <button
              key={type}
              onClick={() => setActiveTab(type)}
              className={`px-4 py-2 rounded-full font-medium transition-colors duration-200 ${
                activeTab === type
                  ? 'bg-[#0052cc] text-white shadow-sm'
                  : 'bg-white text-[#172b4d] border border-blue-100 hover:bg-blue-50'
              }`}
            >
              {type} ({threatsByType[type].length})
            </button>
          )) : (
            <div className="w-full text-center p-4 bg-gray-50 rounded-lg">
              <p className="text-gray-600">No threats found</p>
            </div>
          )}
          {threatTypes.length > 0 && (
            <button
              onClick={() => setActiveTab(null)}
              className={`px-4 py-2 rounded-full font-medium transition-colors duration-200 ${
                activeTab === null
                  ? 'bg-blue-50 text-[#0747a6] border border-blue-200 shadow-sm'
                  : 'bg-white text-[#172b4d] border border-blue-100 hover:bg-blue-50'
              }`}
            >
              Total ({threatModelData.result?.result?.raw_response?.threat_model?.length || 0})
            </button>
          )}
        </div>
      </div>
      
      {/* Threats Table */}
      <div className="mb-10">
        <div className="flex items-center mb-6">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Identified Threats</h2>
        </div>
        <div className="table-container shadow-sm">
          {allThreats.length > 0 ? (
            <table className="table">
              <thead>
                <tr>
                  <th>Threat Type</th>
                  <th>Scenario</th>
                  <th>Potential Impact</th>
                </tr>
              </thead>
              <tbody>
                {(activeTab ? threatsByType[activeTab] : allThreats).map((threat: Threat, index: number) => (
                  <tr key={index}>
                    <td className="font-medium">{threat['Threat Type']}</td>
                    <td>{threat['Scenario']}</td>
                    <td>{threat['Potential Impact']}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="text-center p-8 bg-gray-50 rounded-lg">
              <p className="text-gray-600">No threat data available</p>
            </div>
          )}
        </div>
      </div>
      
      {/* Improvement Suggestions */}
      <div>
        <div className="flex items-center mb-6">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Improvement Suggestions</h2>
        </div>
        <div className="card border border-blue-100 bg-white shadow-sm hover:shadow-md transition-shadow duration-200">
          {threatModelData.result?.result?.raw_response?.improvement_suggestions?.length > 0 ? (
            <ul className="list-disc pl-5 space-y-3 text-[#172b4d]">
              {threatModelData.result.result.raw_response.improvement_suggestions.map((suggestion: string, index: number) => (
                <li key={index} className="pb-2 border-b border-blue-50 last:border-0 last:pb-0">{suggestion}</li>
              ))}
            </ul>
          ) : (
            <div className="text-center p-4">
              <p className="text-gray-600">No improvement suggestions available</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ViewThreatModel;
