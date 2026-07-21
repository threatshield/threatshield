import React, { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import NavigationButtons from '../components/common/NavigationButtons';
import { useAssessment } from '../context/AssessmentContext';
import { apiService, API_BASE_URL } from '../services/api';
import { MitigationItem, MitigationResponse } from '../types/reportTypes';

const getMitigationText = (m: any): string =>
  m['Suggested Mitigation(s)'] || m['Suggested_Mitigation(s)'] || '';

const parseMitigationData = (data: MitigationResponse): MitigationItem[] => {
  try {
    // Check if we have JSON data in raw_response
    if (data?.result?.raw_response?.mitigations) {
      console.log('Found JSON mitigations data:', data.result.raw_response.mitigations);
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
  const navigate = useNavigate();
  const { assessment_id } = useParams<{ assessment_id: string }>();
  const { setMitigationData: setContextMitigationData } = useAssessment();
  const [mitigationData, setMitigationData] = useState<MitigationResponse | null>(null);
  const [attackTreeData, setAttackTreeData] = useState<any | null>(null);
  const [dreadData, setDreadData] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [assessmentDetails, setAssessmentDetails] = useState<{
    department: string;
    projectName: string;
    timestamp: string;
    threatModelingMethodology?: string;
  } | null>(null);
  const [failedMitigations, setFailedMitigations] = useState<boolean>(false);
  const [generatingMitigations, setGeneratingMitigations] = useState<boolean>(false);
  const [generationMessage, setGenerationMessage] = useState<string>('');

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

        // Direct API call to storage endpoint to ensure we get the latest data
        const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=mitigation`);
        if (!response.ok) {
          throw new Error(`Failed to fetch mitigation data: ${response.status}`);
        }

        const data = await response.json();
        console.log('Raw mitigation data:', JSON.stringify(data, null, 2));

        // Handle response structure
        let processedData: MitigationResponse | null = null;

        // Handle double-nested result structure
        if (data?.result?.result?.raw_response?.mitigations) {
          console.log('Found double-nested result structure');
          processedData = {
            timestamp: data.timestamp,
            result: {
              raw_response: data.result.result.raw_response
            }
          };
        }
        // Handle standard structure
        else if (data?.result?.raw_response?.mitigations) {
          console.log('Found standard structure');
          processedData = {
            timestamp: data.timestamp,
            result: {
              raw_response: data.result.raw_response
            }
          };
        }

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
    // Remove contextMitigationData from dependencies to prevent unnecessary re-renders
  }, [assessment_id, setContextMitigationData]);

  // Enhanced parsing with better error handling and logging
  const parsedMitigations = useMemo(() => {
    if (!mitigationData) {
      console.error('No mitigation data available for parsing');
      return [];
    }

    console.log('Parsing mitigation data:', mitigationData);
    const parsed = parseMitigationData(mitigationData);

    // Check if any mitigation has "Threat Type": "Error"
    const hasErrors = parsed.some((m: MitigationItem) => m['Threat Type'] === 'Error');
    setFailedMitigations(hasErrors);

    return parsed;
  }, [mitigationData]);

  // Determine if we're using PASTA methodology by checking the threatModelingMethodology in details.json
  const isPasta = useMemo(() => {
    // First check if we have the methodology in assessmentDetails
    if (assessmentDetails?.threatModelingMethodology) {
      return assessmentDetails.threatModelingMethodology === 'PASTA';
    }

    // Fallback to checking the first mitigation item if assessmentDetails doesn't have the methodology
    if (!parsedMitigations || parsedMitigations.length === 0) return false;
    const firstMitigation = parsedMitigations[0];
    return 'Business Risk Type' in firstMitigation || 'PASTA Stage' in firstMitigation;
  }, [assessmentDetails, parsedMitigations]);

  // Dynamically extract threat types from the parsed mitigations
  const threatsByType = useMemo(() => {
    try {
      if (!parsedMitigations || parsedMitigations.length === 0) {
        return {};
      }

      return parsedMitigations.reduce((acc: Record<string, MitigationItem[]>, mitigation: MitigationItem) => {
        if (isPasta) {
          if (!mitigation || !mitigation['Business Risk Type']) return acc;
          const riskTypes = Array.isArray(mitigation['Business Risk Type'])
            ? mitigation['Business Risk Type']
            : [mitigation['Business Risk Type'] as string];
          riskTypes.forEach(riskType => {
            if (!acc[riskType]) acc[riskType] = [];
            acc[riskType].push(mitigation);
          });
        } else {
          if (!mitigation || !mitigation['Threat Type']) return acc;
          const type = mitigation['Threat Type'];
          if (!acc[type]) acc[type] = [];
          acc[type].push(mitigation);
        }
        return acc;
      }, {});
    } catch (err) {
      console.error('Error processing mitigation data:', err);
      return {};
    }
  }, [parsedMitigations, isPasta]);

  const threatTypes = useMemo(() => Object.keys(threatsByType), [threatsByType]);

  const threatCounts = useMemo(() => {
    return threatTypes.reduce((acc, type) => {
      acc[type] = threatsByType[type]?.length || 0;
      return acc;
    }, {} as Record<string, number>);
  }, [threatTypes, threatsByType]);

  const filteredMitigations = useMemo(() => {
    if (!activeTab) return parsedMitigations;
    return threatsByType[activeTab] || [];
  }, [activeTab, parsedMitigations, threatsByType]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-14 h-14">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700"></div>
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin"></div>
          </div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Loading mitigations...</p>
        </div>
      </div>
    );
  }

  const handleRegenerateMitigations = async () => {
    try {
      setGeneratingMitigations(true);
      setGenerationMessage('');
      const data = await apiService.generateMitigation(assessment_id || '');
      if (data?.result?.raw_response?.mitigations) {
        const processedData: MitigationResponse = {
          timestamp: data.timestamp,
          result: {
            raw_response: data.result.raw_response
          }
        };
        setMitigationData(processedData);
        setContextMitigationData(processedData);
        setGenerationMessage('Successfully regenerated mitigations! Please refresh the page');
      }
    } catch (e) {
      console.error('Error regenerating mitigations', e);
      setGenerationMessage('Failed to regenerate mitigations. Please try again.');
    } finally {
      setGeneratingMitigations(false);
    }
  };

  if (error || !mitigationData) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center p-6">
        <div className="bg-white dark:bg-gray-900/80 border border-red-100 dark:border-red-900/40 rounded-2xl p-10 text-center max-w-md shadow-sm">
          <div className="w-14 h-14 rounded-2xl bg-red-50 dark:bg-red-900/20 border border-red-100 dark:border-red-800/40 flex items-center justify-center mx-auto mb-4">
            <svg className="h-7 w-7 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100 mb-2">Failed to Load Mitigations</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">{error || 'Failed to load mitigation data.'}</p>
          <button
            onClick={handleRegenerateMitigations}
            disabled={generatingMitigations}
            className="px-6 py-2.5 bg-[#0052cc] text-white rounded-lg hover:bg-[#0047b3] disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors duration-200 font-medium text-sm"
          >
            {generatingMitigations ? (
              <span className="flex items-center gap-2">
                <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Regenerating...
              </span>
            ) : (
              'Regenerate Mitigations'
            )}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      <div className="max-w-screen-2xl mx-auto px-6 py-8">

        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
                  <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <h1 className="text-2xl font-bold text-slate-800 dark:text-slate-100">Security Mitigations</h1>
              </div>
              {assessmentDetails ? (
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold bg-slate-100 dark:bg-gray-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-gray-700 uppercase tracking-wide">
                    {assessmentDetails.department}
                  </span>
                  <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{assessmentDetails.projectName}</span>
                  <span className="text-xs text-slate-400 dark:text-slate-500">&middot; {new Date(assessmentDetails.timestamp).toLocaleDateString()}</span>
                </div>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">{assessment_id}</p>
              )}
            </div>

            {/* Interactive mode button */}
            <button
              onClick={() => navigate(`/interactive-threat-model/${assessment_id}`)}
              className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 text-slate-600 dark:text-slate-300 text-sm font-medium rounded-lg hover:border-[#0052cc]/40 hover:text-[#0052cc] hover:bg-blue-50/50 dark:hover:bg-blue-950/30 transition-all duration-200 shadow-sm"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 10l-2 1m0 0l-2-1m2 1v2.5M20 7l-2 1m2-1l-2-1m2 1v2.5M14 4l-2-1-2 1M4 7l2-1M4 7l2 1M4 7v2.5M12 21l-2-1m2 1l2-1m-2 1v-2.5M6 18l-2-1v-2.5M18 18l2-1v-2.5" />
              </svg>
              Interactive Mode
            </button>
          </div>

          {/* Navigation strip */}
          <div className="mt-5">
            <NavigationButtons
              assessment_id={assessment_id!}
              currentPage="view-mitigation"
              viewMode={true}
              hasAttackTree={!!attackTreeData}
              hasDread={!!dreadData}
              hasMitigation={!!mitigationData}
            />
          </div>
        </div>

        {/* Generation errors banner */}
        {failedMitigations && (
          <div className="mb-6 p-4 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/40 rounded-xl">
            <div className="flex items-start justify-between">
              <div className="flex items-start flex-1">
                <svg className="w-5 h-5 text-red-600 dark:text-red-400 mt-0.5 mr-3 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
                <div>
                  <h3 className="text-red-800 dark:text-red-300 font-semibold text-sm">Generation Errors</h3>
                  <p className="text-red-700 dark:text-red-400 text-sm mt-1">
                    Some mitigations failed to generate. Please regenerate to retry.
                  </p>
                </div>
              </div>
              <button
                onClick={handleRegenerateMitigations}
                disabled={generatingMitigations}
                className="ml-4 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white rounded-lg font-medium text-sm transition-colors duration-200 flex-shrink-0"
              >
                {generatingMitigations ? (
                  <span className="flex items-center gap-2">
                    <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Regenerating...
                  </span>
                ) : (
                  'Regenerate Mitigations'
                )}
              </button>
            </div>
            {generationMessage && (
              <div className="mt-3 p-2 bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/40 rounded-lg text-emerald-700 dark:text-emerald-400 text-sm">
                {generationMessage}
              </div>
            )}
          </div>
        )}

        {/* Threat Type Filter Tabs */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-7 h-7 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/40 flex items-center justify-center">
              <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">
              {isPasta ? 'Business Risk Categories' : 'Threat Categories'}
            </h2>
          </div>
          <div className="flex flex-wrap gap-2">
            {threatTypes.length > 0 ? (
              <>
                <button
                  onClick={() => setActiveTab(null)}
                  className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 border ${
                    activeTab === null
                      ? 'bg-[#0052cc] text-white border-[#0052cc] shadow-sm'
                      : 'bg-white dark:bg-gray-900/80 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-gray-700/60 hover:border-[#0052cc]/40 hover:text-[#0052cc] hover:bg-blue-50/50 dark:hover:bg-blue-950/30'
                  }`}
                >
                  All ({parsedMitigations.length})
                </button>
                {threatTypes.map(type => (
                  <button
                    key={type}
                    onClick={() => setActiveTab(type)}
                    className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 border ${
                      activeTab === type
                        ? 'bg-[#0052cc] text-white border-[#0052cc] shadow-sm'
                        : 'bg-white dark:bg-gray-900/80 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-gray-700/60 hover:border-[#0052cc]/40 hover:text-[#0052cc] hover:bg-blue-50/50 dark:hover:bg-blue-950/30'
                    }`}
                  >
                    {type} ({threatCounts[type]})
                  </button>
                ))}
              </>
            ) : (
              <div className="w-full text-center p-4 bg-slate-50 dark:bg-gray-800/40 rounded-lg">
                <p className="text-slate-500 dark:text-slate-400 text-sm">No threats found</p>
              </div>
            )}
          </div>
        </div>

        {/* Mitigations Table */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-7 h-7 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/40 flex items-center justify-center">
              <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">Recommended Mitigations</h2>
            {activeTab && (
              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-50 dark:bg-blue-950/30 text-[#0052cc] border border-blue-100 dark:border-blue-900/40">
                {filteredMitigations.length} showing
              </span>
            )}
          </div>

          {parsedMitigations.length > 0 && (activeTab ? filteredMitigations : parsedMitigations).length > 0 ? (
            <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-slate-50 dark:bg-gray-800/60 border-b border-slate-200 dark:border-gray-800">
                      {isPasta ? (
                        <>
                          <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-36">Business Risk Type</th>
                          <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-40">Threat</th>
                          <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-1/4">Scenario</th>
                          <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3">Mitigations</th>
                        </>
                      ) : (
                        <>
                          <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-44">Threat Type</th>
                          <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-1/4">Scenario</th>
                          <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3">Suggested Mitigations</th>
                        </>
                      )}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-gray-800">
                    {(activeTab ? filteredMitigations : parsedMitigations).map((mitigation: MitigationItem, index: number) => (
                      <tr key={index} className="hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors align-top">
                        {isPasta ? (
                          <>
                            <td className="px-5 py-3.5 text-slate-800 dark:text-slate-200">
                              {Array.isArray(mitigation['Business Risk Type'])
                                ? mitigation['Business Risk Type'].join(', ')
                                : typeof mitigation['Business Risk Type'] === 'string'
                                  ? mitigation['Business Risk Type']
                                  : 'Unknown'}
                            </td>
                            <td className="px-5 py-3.5 font-medium text-slate-800 dark:text-slate-200">
                              {mitigation['Threat Type'] || 'Unknown'}
                            </td>
                            <td className="px-5 py-3.5 text-slate-600 dark:text-slate-300 text-sm leading-relaxed">
                              {mitigation['Scenario']}
                            </td>
                            <td className="px-5 py-3.5">
                              <ul className="list-none space-y-1">
                                {getMitigationText(mitigation)
                                  ? getMitigationText(mitigation)
                                      .split('\n')
                                      .map((item, i) => {
                                        let cleanedItem = item.trim()
                                          .replace(/^[\d]+[\.\s]*/, '')
                                          .replace(/\s\d+$/, '');
                                        if (/^\d+$/.test(cleanedItem.split(' ')[0])) {
                                          cleanedItem = cleanedItem.replace(/^\d+\s*/, '');
                                        }
                                        return cleanedItem ? (
                                          <li key={i} className="flex items-start gap-1.5 text-sm text-slate-600 dark:text-slate-300">
                                            <span className="text-slate-400 dark:text-slate-500 mt-0.5 flex-shrink-0">–</span>
                                            <span>{cleanedItem}</span>
                                          </li>
                                        ) : null;
                                      })
                                      .filter(Boolean)
                                  : <li className="text-sm text-slate-500 dark:text-slate-400">No mitigation details available</li>
                                }
                              </ul>
                            </td>
                          </>
                        ) : (
                          <>
                            <td className="px-5 py-3.5 font-medium text-slate-800 dark:text-slate-200">
                              {mitigation['Threat Type']}
                            </td>
                            <td className="px-5 py-3.5 text-slate-600 dark:text-slate-300 text-sm leading-relaxed">
                              {mitigation['Scenario']}
                            </td>
                            <td className="px-5 py-3.5">
                              <ul className="list-none space-y-1">
                                {getMitigationText(mitigation)
                                  ? getMitigationText(mitigation)
                                      .split('\n')
                                      .map((item, i) => {
                                        let cleanedItem = item.trim()
                                          .replace(/^[\d]+[\.\s]*/, '')
                                          .replace(/\s\d+$/, '');
                                        if (/^\d+$/.test(cleanedItem.split(' ')[0])) {
                                          cleanedItem = cleanedItem.replace(/^\d+\s*/, '');
                                        }
                                        return cleanedItem ? (
                                          <li key={i} className="flex items-start gap-1.5 text-sm text-slate-600 dark:text-slate-300">
                                            <span className="text-slate-400 dark:text-slate-500 mt-0.5 flex-shrink-0">–</span>
                                            <span>{cleanedItem}</span>
                                          </li>
                                        ) : null;
                                      })
                                      .filter(Boolean)
                                  : <li className="text-sm text-slate-500 dark:text-slate-400">No mitigation details available</li>
                                }
                              </ul>
                            </td>
                          </>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 rounded-xl p-10 text-center shadow-sm">
              <p className="text-sm text-slate-500 dark:text-slate-400">Select a threat category to view mitigations.</p>
            </div>
          )}
        </div>

        {/* Security Best Practices */}
        <div>
          <div className="flex items-center gap-3 mb-3">
            <div className="w-7 h-7 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/40 flex items-center justify-center">
              <svg className="h-4 w-4 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">Security Best Practices</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[
              {
                icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />,
                title: 'Authentication & Authorization',
                items: [
                  'Implement multi-factor authentication (MFA) for all user accounts',
                  'Use OAuth 2.0 or OpenID Connect for secure authentication flows',
                  'Apply the principle of least privilege for all system access',
                  'Implement proper session management with secure cookies',
                  'Regularly audit user permissions and access controls',
                ]
              },
              {
                icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />,
                title: 'Data Protection',
                items: [
                  'Encrypt sensitive data both in transit and at rest',
                  'Implement proper key management procedures',
                  'Use secure hashing algorithms for storing passwords',
                  'Apply data minimization principles',
                  'Implement proper data backup and recovery procedures',
                ]
              },
              {
                icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />,
                title: 'Secure Coding',
                items: [
                  'Validate and sanitize all user inputs',
                  'Use parameterized queries to prevent SQL injection',
                  'Implement proper error handling without exposing sensitive information',
                  'Keep dependencies updated and scan for vulnerabilities',
                  'Follow secure coding standards and guidelines',
                ]
              },
              {
                icon: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />,
                title: 'Logging & Monitoring',
                items: [
                  'Implement comprehensive logging for security-relevant events',
                  'Set up real-time monitoring and alerting for suspicious activities',
                  'Ensure logs are stored securely and cannot be tampered with',
                  'Regularly review logs for security incidents',
                  'Implement intrusion detection and prevention systems',
                ]
              },
            ].map((practice, i) => (
              <div key={i} className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-5">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-100 dark:border-blue-900/40 flex items-center justify-center flex-shrink-0">
                    <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      {practice.icon}
                    </svg>
                  </div>
                  <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{practice.title}</h3>
                </div>
                <ul className="space-y-2">
                  {practice.items.map((item, j) => (
                    <li key={j} className="flex items-start gap-2 text-sm text-slate-600 dark:text-slate-300">
                      <span className="text-[#0052cc] mt-1 flex-shrink-0">
                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                        </svg>
                      </span>
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
};

export default Mitigation;
