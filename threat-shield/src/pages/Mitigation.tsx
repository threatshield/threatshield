import React, { useState, useEffect, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import NavigationButtons from '../components/common/NavigationButtons';
import { useAssessment } from '../context/AssessmentContext';
import { apiService, API_BASE_URL } from '../services/api';
import ReactMarkdown from 'react-markdown';
import { MitigationItem, MitigationResponse } from '../types/reportTypes';

const parseMitigationData = (data: MitigationResponse): MitigationItem[] => {
  try {
    // Check for double-nested structure first
    if (data?.result?.result?.raw_response?.mitigations) {
      console.log('Found double-nested mitigations data:', data.result.result.raw_response.mitigations);
      return data.result.result.raw_response.mitigations;
    }
    
    // Check for standard structure
    if (data?.result?.raw_response?.mitigations) {
      console.log('Found standard mitigations data:', data.result.raw_response.mitigations);
      return data.result.raw_response.mitigations;
    }
    
    console.error('No valid mitigations data found');
    return [];
  } catch (error) {
    console.error('Error parsing mitigation data:', error);
    return [];
  }
};

const Mitigation: React.FC = () => {
  const { assessment_id } = useParams<{ assessment_id: string }>();
  const { setMitigationData: setContextMitigationData } = useAssessment();
  const [mitigationData, setMitigationData] = useState<MitigationResponse | null>(null);
  const [attackTreeData, setAttackTreeData] = useState<any | null>(null);
  const [dreadData, setDreadData] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [assessmentDetails, setAssessmentDetails] = useState<{
    projectName: string;
    timestamp: string;
    threatModelingMethodology?: string;
  } | null>(null);

  const { mitigationData: contextMitigationData } = useAssessment();

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
      if (!assessment_id) {
        setError('No assessment ID provided');
        return;
      }

      try {
        setLoading(true);
        console.log('Fetching mitigation data for assessment ID:', assessment_id);

        const data = await apiService.getMitigations(assessment_id);
        console.log('Raw mitigation data:', JSON.stringify(data, null, 2));
        
        let processedData: MitigationResponse | null = null;
        
        // Keep the data as is since it already matches our MitigationResponse type
        processedData = data;
        
        if (processedData) {
          console.log('Processed mitigation data:', processedData);
          setMitigationData(processedData);
          setContextMitigationData(processedData);
          setActiveTab(null);
        } else {
          console.error('Could not process mitigation data from response:', data);
          setError('Invalid mitigation data format received');
        }

        // Fetch attack tree and DREAD data in parallel
        const [attackTreeResponse, dreadResponse] = await Promise.allSettled([
          apiService.getAttackTree(assessment_id),
          apiService.getDreadAssessment(assessment_id)
        ]);

        setAttackTreeData(attackTreeResponse.status === 'fulfilled' ? attackTreeResponse.value : null);
        setDreadData(dreadResponse.status === 'fulfilled' ? dreadResponse.value : null);

      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to load mitigation data';
        setError(errorMessage);
        console.error('Error in data fetching:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [assessment_id, setContextMitigationData]);

  // Enhanced parsing with better error handling and logging
  const parsedMitigations = useMemo(() => {
    if (!mitigationData) {
      console.error('No mitigation data available for parsing');
      return [];
    }
    
    console.log('Parsing mitigation data:', mitigationData);
    return parseMitigationData(mitigationData);
  }, [mitigationData]);

  // Group mitigations by threat type
  const threatsByType = useMemo(() => {
    try {
      if (!parsedMitigations || parsedMitigations.length === 0) {
        return {};
      }

      return parsedMitigations.reduce((acc: Record<string, MitigationItem[]>, mitigation: MitigationItem) => {
        if (!mitigation || !mitigation['Threat Type']) return acc;
        const type = mitigation['Threat Type'];
        if (!acc[type]) {
          acc[type] = [];
        }
        acc[type].push(mitigation);
        return acc;
      }, {});
    } catch (err) {
      console.error('Error processing mitigation data:', err);
      return {};
    }
  }, [parsedMitigations]);

  // Get threat types from the grouped mitigations
  const threatTypes = useMemo(() => {
    return Object.keys(threatsByType);
  }, [threatsByType]);

  // Calculate threat counts for each type
  const threatCounts = useMemo(() => {
    return threatTypes.reduce((acc, type) => {
      acc[type] = threatsByType[type]?.length || 0;
      return acc;
    }, {} as Record<string, number>);
  }, [threatTypes, threatsByType]);

  // Get filtered mitigations based on active tab
  const filteredMitigations = useMemo(() => {
    if (!activeTab) return parsedMitigations;
    return threatsByType[activeTab] || [];
  }, [activeTab, parsedMitigations, threatsByType]);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (error || !mitigationData) {
    return (
      <div className="max-w-6xl mx-auto p-6">
        <div className="card p-8 text-center">
          <h2 className="text-xl font-semibold text-red-600 mb-4">Error Loading Mitigations</h2>
          <p className="mb-4">{error || 'Failed to load mitigation data.'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="text-center mb-10">
        <h1 className="text-4xl font-bold text-[#0052cc] mb-2">Security Mitigations</h1>
        <p className="text-xl text-gray-600 mb-2">Recommended security controls and countermeasures</p>
        <p className="text-lg text-blue-600 mb-3">
          {assessmentDetails ? 
            `${assessmentDetails.projectName} - ${new Date(assessmentDetails.timestamp).toLocaleDateString()}` 
            : assessment_id}
        </p>
        
        <NavigationButtons
          assessment_id={assessment_id!}
          currentPage="view-mitigation"
          viewMode={true}
          hasAttackTree={!!attackTreeData}
          hasDread={!!dreadData}
          hasMitigation={!!mitigationData}
        />
      </div>
      
      {/* Threat Type Tabs */}
      <div className="mb-8">
        <div className="flex items-center mb-6">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
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
              {type} ({threatCounts[type]})
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
              Total ({parsedMitigations.length})
            </button>
          )}
        </div>
      </div>
      
      {/* Mitigations Table */}
      <div>
        <div className="flex items-center mb-6">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Recommended Mitigations</h2>
        </div>
        
        {parsedMitigations.length > 0 && (activeTab ? filteredMitigations : parsedMitigations).length > 0 ? (
          <div className="table-container shadow-sm">
            <table className="table">
              <thead>
                <tr>
                  <th>Threat Type</th>
                  <th className="w-1/4">Scenario</th>
                  <th>Suggested Mitigations</th>
                </tr>
              </thead>
              <tbody>
                {(activeTab ? filteredMitigations : parsedMitigations).map((mitigation: MitigationItem, index: number) => (
                  <tr key={index}>
                    <td>
                      {mitigation['Threat Type']}
                    </td>
                    <td>
                      {mitigation['Scenario']}
                    </td>
                    <td>
                      <div className="prose prose-blue max-w-none">
                        <div className="prose prose-blue max-w-none">
                          <ul className="list-none">
                            {mitigation['Mitigations'] && Array.isArray(mitigation['Mitigations'])
                              ? mitigation['Mitigations'].map((item, i) => {
                                    // Remove any leading or trailing numbers from the item
                                    let cleanedItem = item.trim()
                                      .replace(/^[\d]+[\.\s]*/, '') // Remove leading numbers like "1. " or "1" or "1"
                                      .replace(/\s\d+$/, ''); // Remove trailing numbers like " 1" or " 2"
                                    
                                    // Additional check to remove standalone numbers at the beginning
                                    if (/^\d+$/.test(cleanedItem.split(' ')[0])) {
                                      cleanedItem = cleanedItem.replace(/^\d+\s*/, '');
                                    }
                                    return cleanedItem ? <li key={i} className="before:content-['-'] before:mr-2">{cleanedItem}</li> : null;
                                  })
                                  .filter(Boolean)
                              : <li>No mitigation details available</li>
                            }
                          </ul>
                        </div>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="card border border-blue-100 p-8 text-center">
            <p className="text-gray-600">Select a threat category to view mitigations.</p>
          </div>
        )}
      </div>
      
      {/* Best Practices */}
      <div className="mt-12">
        <div className="flex items-center mb-6">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Security Best Practices</h2>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="card border border-blue-100 shadow-sm hover:shadow-md transition-shadow duration-200">
            <div className="flex items-center mb-4">
              <div className="bg-blue-100 p-2 rounded-full mr-3">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-[#172b4d]">Authentication & Authorization</h3>
            </div>
            <ul className="list-disc pl-5 space-y-2 text-[#172b4d]">
              <li>Implement multi-factor authentication (MFA) for all user accounts</li>
              <li>Use OAuth 2.0 or OpenID Connect for secure authentication flows</li>
              <li>Apply the principle of least privilege for all system access</li>
              <li>Implement proper session management with secure cookies</li>
              <li>Regularly audit user permissions and access controls</li>
            </ul>
          </div>
          
          <div className="card border border-blue-100 shadow-sm hover:shadow-md transition-shadow duration-200">
            <div className="flex items-center mb-4">
              <div className="bg-blue-100 p-2 rounded-full mr-3">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-[#172b4d]">Data Protection</h3>
            </div>
            <ul className="list-disc pl-5 space-y-2 text-[#172b4d]">
              <li>Encrypt sensitive data both in transit and at rest</li>
              <li>Implement proper key management procedures</li>
              <li>Use secure hashing algorithms for storing passwords</li>
              <li>Apply data minimization principles</li>
              <li>Implement proper data backup and recovery procedures</li>
            </ul>
          </div>
          
          <div className="card border border-blue-100 shadow-sm hover:shadow-md transition-shadow duration-200">
            <div className="flex items-center mb-4">
              <div className="bg-blue-100 p-2 rounded-full mr-3">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-[#172b4d]">Secure Coding</h3>
            </div>
            <ul className="list-disc pl-5 space-y-2 text-[#172b4d]">
              <li>Validate and sanitize all user inputs</li>
              <li>Use parameterized queries to prevent SQL injection</li>
              <li>Implement proper error handling without exposing sensitive information</li>
              <li>Keep dependencies updated and scan for vulnerabilities</li>
              <li>Follow secure coding standards and guidelines</li>
            </ul>
          </div>
          
          <div className="card border border-blue-100 shadow-sm hover:shadow-md transition-shadow duration-200">
            <div className="flex items-center mb-4">
              <div className="bg-blue-100 p-2 rounded-full mr-3">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-[#172b4d]">Logging & Monitoring</h3>
            </div>
            <ul className="list-disc pl-5 space-y-2 text-[#172b4d]">
              <li>Implement comprehensive logging for security-relevant events</li>
              <li>Set up real-time monitoring and alerting for suspicious activities</li>
              <li>Ensure logs are stored securely and cannot be tampered with</li>
              <li>Regularly review logs for security incidents</li>
              <li>Implement intrusion detection and prevention systems</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Mitigation;
