import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import NavigationButtons from '../components/common/NavigationButtons';
import { useAssessment } from '../context/AssessmentContext';
import { apiService } from '../services/api';
import { DreadAssessmentResponse, DreadAssessmentItem } from '../types/reportTypes';

// Helper function to safely get DREAD items
const getDreadItems = (result: any): DreadAssessmentItem[] => {
  try {
    // Case 1: Direct raw_response
    if (result?.raw_response?.['Risk Assessment']) {
      return result.raw_response['Risk Assessment'];
    }
    
    // Case 2: Nested in result.raw_response
    if (result?.result?.raw_response?.['Risk Assessment']) {
      return result.result.raw_response['Risk Assessment'];
    }
    
    // Case 3: Double nested in result.result.raw_response
    if (result?.result?.result?.raw_response?.['Risk Assessment']) {
      return result.result.result.raw_response['Risk Assessment'];
    }

    console.warn('No valid DREAD data found in result:', result);
    return [];
  } catch (error) {
    console.error('Error extracting DREAD items:', error);
    return [];
  }
};

// Local type for DREAD assessment items
type DreadAssessment = DreadAssessmentItem;

const Dread: React.FC = () => {
  const { assessment_id } = useParams<{ assessment_id: string }>();
  const { setDreadData: setContextDreadData } = useAssessment();
  const [dreadData, setDreadData] = useState<DreadAssessmentResponse | null>(null);
  const [attackTreeData, setAttackTreeData] = useState<any | null>(null);
  const [mitigationData, setMitigationData] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [sortField, setSortField] = useState<string>('Risk Score');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [isExpanded, setIsExpanded] = useState<boolean>(false);
  const [assessmentDetails, setAssessmentDetails] = useState<{
    projectName: string;
    timestamp: string;
  } | null>(null);

  const { dreadData: contextDreadData } = useAssessment();

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
    const fetchAllData = async () => {
      try {
        setLoading(true);
        console.log('Fetching data for assessment ID:', assessment_id);
        
        // Fetch all data in parallel using Promise.allSettled
        const responses = await Promise.allSettled([
          apiService.getDreadAssessment(assessment_id!),
          apiService.getAttackTree(assessment_id!),
          apiService.getMitigations(assessment_id!)
        ]);

        // Process DREAD response
        if (responses[0].status === 'fulfilled') {
          const dreadResponse = responses[0].value;
          if (!dreadResponse?.result || !getDreadItems(dreadResponse.result)) {
            throw new Error('Invalid DREAD assessment data structure');
          }
          setDreadData(dreadResponse);
          setContextDreadData(dreadResponse);
        } else {
          setDreadData(null);
        }

        // Process other responses
        setAttackTreeData(responses[1].status === 'fulfilled' ? responses[1].value : null);
        setMitigationData(responses[2].status === 'fulfilled' ? responses[2].value : null);

      } catch (err) {
        setError('Failed to load DREAD assessment data. Please try again.');
        console.error('Error fetching data:', err);
      } finally {
        setLoading(false);
      }
    };

    if (assessment_id) {
      if (contextDreadData) {
        // Use DREAD data from context if available
        setDreadData(contextDreadData);
        // Still fetch attack tree and mitigation data
        Promise.allSettled([
          apiService.getAttackTree(assessment_id),
          apiService.getMitigations(assessment_id)
        ]).then(responses => {
          setAttackTreeData(responses[0].status === 'fulfilled' ? responses[0].value : null);
          setMitigationData(responses[1].status === 'fulfilled' ? responses[1].value : null);
          setLoading(false);
        });
      } else {
        // Fetch all data if no context
        fetchAllData();
      }
    }
  }, [assessment_id, setContextDreadData, contextDreadData]);

  const calculateRiskScore = (assessment: DreadAssessment) => {
    const scores = [
      assessment['Damage Potential'],
      assessment['Reproducibility'],
      assessment['Exploitability'],
      assessment['Affected Users'],
      assessment['Discoverability']
    ];
    return (scores.reduce((a, b) => a + b, 0) / scores.length);
  };

  const getRiskLevel = (score: number) => {
    if (score >= 8) return { text: 'High', color: 'text-red-600 bg-red-50' };
    if (score >= 6) return { text: 'Medium', color: 'text-yellow-600 bg-yellow-50' };
    return { text: 'Low', color: 'text-green-600 bg-green-50' };
  };

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const sortedAssessments = dreadData?.result ? [...(getDreadItems(dreadData.result) || [])].sort((a, b) => {
    let valueA, valueB;

    if (sortField === 'Risk Score') {
      valueA = calculateRiskScore(a);
      valueB = calculateRiskScore(b);
      return sortDirection === 'asc' ? valueA - valueB : valueB - valueA;
    } else if (sortField === 'Threat Type') {
      valueA = a['Threat Type'];
      valueB = b['Threat Type'];
      return sortDirection === 'asc' ? valueA.localeCompare(valueB) : valueB.localeCompare(valueA);
    } else {
      valueA = a[sortField as keyof DreadAssessment] as number;
      valueB = b[sortField as keyof DreadAssessment] as number;
      return sortDirection === 'asc' ? valueA - valueB : valueB - valueA;
    }
  }) : [];

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (error || !dreadData) {
    return (
      <div className="max-w-6xl mx-auto p-6">
        <div className="card p-8 text-center">
          <h2 className="text-xl font-semibold text-red-600 mb-4">Error Loading DREAD Assessment</h2>
          <p className="mb-4">{error || 'Failed to load DREAD assessment data.'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="text-center mb-10">
        <h1 className="text-4xl font-bold text-[#0052cc] mb-2">DREAD Risk Assessment</h1>
        <p className="text-xl text-gray-600 mb-2">Quantitative risk analysis of identified threats</p>
        <p className="text-lg text-blue-600 mb-3">
          {assessmentDetails ? 
            `${assessmentDetails.projectName} - ${new Date(assessmentDetails.timestamp).toLocaleDateString()}` 
            : assessment_id}
        </p>
        
        <NavigationButtons
          assessment_id={assessment_id!}
          currentPage="view-dread"
          viewMode={true}
          hasAttackTree={!!attackTreeData}
          hasDread={!!dreadData}
          hasMitigation={!!mitigationData}
        />
      </div>
      
      {/* DREAD Explanation */}
      <div className="card border border-blue-100 shadow-sm hover:shadow-md transition-shadow duration-200 mb-8">
        <div 
          className="flex items-center pb-4 border-b border-blue-100 cursor-pointer"
          onClick={() => setIsExpanded(!isExpanded)}
        >
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Understanding DREAD</h2>
          <div className="ml-auto">
            <svg 
              xmlns="http://www.w3.org/2000/svg" 
              className={`h-6 w-6 text-[#0052cc] transform transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`} 
              fill="none" 
              viewBox="0 0 24 24" 
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </div>
        </div>
        
        <div className={`transition-all duration-300 ease-in-out overflow-hidden ${isExpanded ? 'max-h-[2000px] opacity-100' : 'max-h-0 opacity-0'}`}>
          <div className="bg-blue-50/50 p-4 rounded-lg border border-blue-100 mb-6">
          <p className="text-[#172b4d] mb-4">
            DREAD is a risk assessment model used to calculate risk scores for identified security threats. Each threat is rated on a scale of 1-10 across five categories:
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
          <div className="card bg-white p-4 border border-blue-100 hover:shadow-sm transition-shadow duration-200">
            <h3 className="font-semibold text-[#0052cc] mb-2 flex items-center">
              <span className="bg-[#0052cc] text-white w-6 h-6 rounded-full flex items-center justify-center mr-2 text-sm">D</span>
              Damage Potential
            </h3>
            <p className="text-sm text-[#172b4d]">How much damage could be caused if the vulnerability is exploited?</p>
          </div>
          
          <div className="card bg-white p-4 border border-blue-100 hover:shadow-sm transition-shadow duration-200">
            <h3 className="font-semibold text-[#0052cc] mb-2 flex items-center">
              <span className="bg-[#0052cc] text-white w-6 h-6 rounded-full flex items-center justify-center mr-2 text-sm">R</span>
              Reproducibility
            </h3>
            <p className="text-sm text-[#172b4d]">How easy is it to reproduce the attack?</p>
          </div>
          
          <div className="card bg-white p-4 border border-blue-100 hover:shadow-sm transition-shadow duration-200">
            <h3 className="font-semibold text-[#0052cc] mb-2 flex items-center">
              <span className="bg-[#0052cc] text-white w-6 h-6 rounded-full flex items-center justify-center mr-2 text-sm">E</span>
              Exploitability
            </h3>
            <p className="text-sm text-[#172b4d]">How much effort and expertise is needed to exploit the vulnerability?</p>
          </div>
          
          <div className="card bg-white p-4 border border-blue-100 hover:shadow-sm transition-shadow duration-200">
            <h3 className="font-semibold text-[#0052cc] mb-2 flex items-center">
              <span className="bg-[#0052cc] text-white w-6 h-6 rounded-full flex items-center justify-center mr-2 text-sm">A</span>
              Affected Users
            </h3>
            <p className="text-sm text-[#172b4d]">How many users would be affected if the vulnerability is exploited?</p>
          </div>
          
          <div className="card bg-white p-4 border border-blue-100 hover:shadow-sm transition-shadow duration-200">
            <h3 className="font-semibold text-[#0052cc] mb-2 flex items-center">
              <span className="bg-[#0052cc] text-white w-6 h-6 rounded-full flex items-center justify-center mr-2 text-sm">D</span>
              Discoverability
            </h3>
            <p className="text-sm text-[#172b4d]">How easy is it to discover the vulnerability?</p>
          </div>
        </div>
        
          <div className="bg-blue-50/50 p-4 rounded-lg border border-blue-100">
          <p className="text-[#172b4d]">
            <strong>Risk Score</strong> is calculated as the average of all five ratings. Higher scores indicate higher risk.
          </p>
          </div>
        </div>
      </div>
      
      {/* DREAD Assessment Table */}
      <div className="mb-10">
        <div className="flex items-center mb-6">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Risk Assessment Results</h2>
        </div>
        <div className="table-container shadow-sm">
          <table className="table">
            <thead>
              <tr>
                <th 
                  className="cursor-pointer hover:bg-blue-50"
                  onClick={() => handleSort('Threat Type')}
                >
                  <div className="flex items-center">
                    Threat Type
                    {sortField === 'Threat Type' && (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sortDirection === 'asc' ? "M5 15l7-7 7 7" : "M19 9l-7 7-7-7"} />
                      </svg>
                    )}
                  </div>
                </th>
                <th>Scenario</th>
                <th 
                  className="cursor-pointer hover:bg-blue-50"
                  onClick={() => handleSort('Damage Potential')}
                >
                  <div className="flex items-center">
                    D
                    {sortField === 'Damage Potential' && (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sortDirection === 'asc' ? "M5 15l7-7 7 7" : "M19 9l-7 7-7-7"} />
                      </svg>
                    )}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-blue-50"
                  onClick={() => handleSort('Reproducibility')}
                >
                  <div className="flex items-center">
                    R
                    {sortField === 'Reproducibility' && (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sortDirection === 'asc' ? "M5 15l7-7 7 7" : "M19 9l-7 7-7-7"} />
                      </svg>
                    )}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-blue-50"
                  onClick={() => handleSort('Exploitability')}
                >
                  <div className="flex items-center">
                    E
                    {sortField === 'Exploitability' && (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sortDirection === 'asc' ? "M5 15l7-7 7 7" : "M19 9l-7 7-7-7"} />
                      </svg>
                    )}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-blue-50"
                  onClick={() => handleSort('Affected Users')}
                >
                  <div className="flex items-center">
                    A
                    {sortField === 'Affected Users' && (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sortDirection === 'asc' ? "M5 15l7-7 7 7" : "M19 9l-7 7-7-7"} />
                      </svg>
                    )}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-blue-50"
                  onClick={() => handleSort('Discoverability')}
                >
                  <div className="flex items-center">
                    D
                    {sortField === 'Discoverability' && (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sortDirection === 'asc' ? "M5 15l7-7 7 7" : "M19 9l-7 7-7-7"} />
                      </svg>
                    )}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-blue-50"
                  onClick={() => handleSort('Risk Score')}
                >
                  <div className="flex items-center">
                    Risk Score
                    {sortField === 'Risk Score' && (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sortDirection === 'asc' ? "M5 15l7-7 7 7" : "M19 9l-7 7-7-7"} />
                      </svg>
                    )}
                  </div>
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedAssessments.map((assessment, index) => {
                const riskScore = calculateRiskScore(assessment);
                const riskLevel = getRiskLevel(riskScore);
                
                return (
                  <tr key={index}>
                    <td className="font-medium">{assessment['Threat Type']}</td>
                    <td>{assessment['Scenario']}</td>
                    <td className="text-center">{assessment['Damage Potential']}</td>
                    <td className="text-center">{assessment['Reproducibility']}</td>
                    <td className="text-center">{assessment['Exploitability']}</td>
                    <td className="text-center">{assessment['Affected Users']}</td>
                    <td className="text-center">{assessment['Discoverability']}</td>
                    <td>
                      <div className={`px-3 py-1 rounded-full text-center font-medium ${riskLevel.color}`}>
                        {riskScore.toFixed(1)}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
      
      {/* Risk Distribution */}
      <div>
        <div className="flex items-center mb-6">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Risk Distribution</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {['High', 'Medium', 'Low'].map((level) => {
            const count = sortedAssessments.filter(assessment => {
              const score = calculateRiskScore(assessment);
              if (level === 'High') return score >= 8;
              if (level === 'Medium') return score >= 6 && score < 8;
              return score < 6;
            }).length;
            
            const percentage = sortedAssessments.length > 0 
              ? Math.round((count / sortedAssessments.length) * 100) 
              : 0;
            
            const bgColor = level === 'High' ? 'bg-red-100' : level === 'Medium' ? 'bg-yellow-100' : 'bg-green-100';
            const textColor = level === 'High' ? 'text-red-800' : level === 'Medium' ? 'text-yellow-800' : 'text-green-800';
            const borderColor = level === 'High' ? 'border-red-200' : level === 'Medium' ? 'border-yellow-200' : 'border-green-200';
            
            return (
              <div key={level} className={`card p-6 ${bgColor} ${textColor} border ${borderColor}`}>
                <h3 className="text-lg font-semibold mb-2">{level} Risk</h3>
                <div className="flex items-end justify-between">
                  <div className="text-4xl font-bold">{count}</div>
                  <div className="text-2xl">{percentage}%</div>
                </div>
                <div className="mt-4 bg-white rounded-full h-2 overflow-hidden">
                  <div 
                    className={`h-full ${level === 'High' ? 'bg-red-500' : level === 'Medium' ? 'bg-yellow-500' : 'bg-green-500'}`}
                    style={{ width: `${percentage}%` }}
                  ></div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default Dread;
