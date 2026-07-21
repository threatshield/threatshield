import React, { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import NavigationButtons from '../components/common/NavigationButtons';
import { useAssessment } from '../context/AssessmentContext';
import { apiService, API_BASE_URL } from '../services/api';
import { DreadAssessmentItem } from '../types/reportTypes';

import { Threat } from '../types/reportTypes';

const confidenceBadge = (level: string) => {
  const c = (level || 'Medium').trim();
  const cls = c === 'High' ? 'bg-red-100 text-red-700' : c === 'Low' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700';
  return <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>{c}</span>;
};

interface ThreatModelResponse {
  timestamp: string;
  result: {
    raw_response: {
      threat_model: Threat[];
      improvement_suggestions: string[];
    };
    markdown: string;
  };
}

// Color map for STRIDE threat types
const THREAT_TYPE_COLORS: Record<string, { bg: string; text: string; border: string; dot: string; darkBg: string; darkText: string; darkBorder: string }> = {
  Spoofing:        { bg: 'bg-violet-50',  text: 'text-violet-700',  border: 'border-violet-200', dot: 'bg-violet-500',  darkBg: 'dark:bg-violet-900/20', darkText: 'dark:text-violet-400', darkBorder: 'dark:border-violet-800/40' },
  Tampering:       { bg: 'bg-orange-50',  text: 'text-orange-700',  border: 'border-orange-200', dot: 'bg-orange-500',  darkBg: 'dark:bg-orange-900/20', darkText: 'dark:text-orange-400', darkBorder: 'dark:border-orange-800/40' },
  Repudiation:     { bg: 'bg-yellow-50',  text: 'text-yellow-700',  border: 'border-yellow-200', dot: 'bg-yellow-500',  darkBg: 'dark:bg-yellow-900/20', darkText: 'dark:text-yellow-400', darkBorder: 'dark:border-yellow-800/40' },
  'Information Disclosure': { bg: 'bg-sky-50', text: 'text-sky-700', border: 'border-sky-200', dot: 'bg-sky-500', darkBg: 'dark:bg-sky-900/20', darkText: 'dark:text-sky-400', darkBorder: 'dark:border-sky-800/40' },
  'Denial of Service': { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200', dot: 'bg-red-500', darkBg: 'dark:bg-red-900/20', darkText: 'dark:text-red-400', darkBorder: 'dark:border-red-800/40' },
  'Elevation of Privilege': { bg: 'bg-rose-50', text: 'text-rose-700', border: 'border-rose-200', dot: 'bg-rose-500', darkBg: 'dark:bg-rose-900/20', darkText: 'dark:text-rose-400', darkBorder: 'dark:border-rose-800/40' },
};

const getTypeStyle = (type: string) => {
  return THREAT_TYPE_COLORS[type] ?? { bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-200', dot: 'bg-blue-500', darkBg: 'dark:bg-blue-900/20', darkText: 'dark:text-blue-400', darkBorder: 'dark:border-blue-800/40' };
};

const ViewThreatModel: React.FC = () => {
  const { assessment_id } = useParams<{ assessment_id: string }>();
  const navigate = useNavigate();
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
    department: string;
    projectName: string;
    timestamp: string;
  } | null>(null);


  useEffect(() => {
    const fetchAssessmentDetails = async () => {
      if (assessment_id) {
        try {
          const response = await apiService.getStorageHistory();
          if (response && response.data) {
            const report = response.data.find(r => r.id === assessment_id);
            if (report && report.details) {
              setAssessmentDetails(report.details);
            }
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
        if (!assessment_id) throw new Error('Assessment ID is required');

        const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=threat_model`);
        if (!response.ok) throw new Error('Failed to fetch threat model');

        const data = await response.json();
        if (!data?.result?.result?.raw_response?.threat_model) {
          throw new Error('Invalid threat model data format');
        }

        const transformedData: ThreatModelResponse = {
          timestamp: data.timestamp,
          result: data.result.result
        };

        setThreatModelData(transformedData);
        setContextThreatModelData(transformedData);

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

        try {
          const attackTreeResponse = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=attack_tree`);
          if (attackTreeResponse.ok) {
            const attackTreeData = await attackTreeResponse.json();
            if (attackTreeData?.result?.result?.raw_response?.nodes) setHasAttackTree(true);
          }
        } catch (err) {
          console.error('Error checking attack tree data:', err);
        }

        try {
          const mitigationResponse = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=mitigation`);
          if (mitigationResponse.ok) {
            const mitigationData = await mitigationResponse.json();
            if (mitigationData?.result?.result?.raw_response?.['Mitigation Strategies']) setHasMitigation(true);
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
      fetchData();
    } else {
      setError('No assessment ID provided');
    }
  }, [assessment_id, setContextThreatModelData]);

  const isPasta = useMemo(() => {
    if (!threatModelData?.result?.raw_response?.threat_model?.length) return false;
    const firstThreat = threatModelData.result.raw_response.threat_model[0];
    return 'Business Risk Type' in firstThreat || 'PASTA Stage' in firstThreat;
  }, [threatModelData]);

  const allThreats = useMemo(() => {
    return threatModelData?.result?.raw_response?.threat_model || [];
  }, [threatModelData]);

  const threatsByType = useMemo(() => {
    try {
      if (!threatModelData?.result?.raw_response?.threat_model) return {};
      return threatModelData.result.raw_response.threat_model.reduce((acc: Record<string, any[]>, threat: any) => {
        if (isPasta) {
          if (!threat || !threat['Business Risk Type']) return acc;
          const riskTypes = Array.isArray(threat['Business Risk Type'])
            ? threat['Business Risk Type']
            : [threat['Business Risk Type']];
          riskTypes.forEach(riskType => {
            if (!acc[riskType]) acc[riskType] = [];
            acc[riskType].push(threat);
          });
        } else {
          if (!threat || !threat['Threat Type']) return acc;
          const type = threat['Threat Type'];
          if (!acc[type]) acc[type] = [];
          acc[type].push(threat);
        }
        return acc;
      }, {});
    } catch (err) {
      return {};
    }
  }, [threatModelData, isPasta]);

  const threatTypes = useMemo(() => Object.keys(threatsByType), [threatsByType]);

  const highRiskItems = useMemo(() => {
    if (!dreadData) return [];
    return dreadData
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
      .sort((a, b) => b.score - a.score);
  }, [dreadData]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-14 h-14">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100"></div>
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin"></div>
          </div>
          <p className="text-sm font-medium text-slate-500">Loading threat model...</p>
        </div>
      </div>
    );
  }

  if (error || !threatModelData) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center p-6">
        <div className="bg-white border border-red-100 dark:bg-gray-900/80 dark:border-red-800/40 rounded-2xl p-10 text-center max-w-md shadow-sm">
          <div className="w-14 h-14 rounded-2xl bg-red-50 border border-red-100 dark:bg-red-900/20 dark:border-red-800/40 flex items-center justify-center mx-auto mb-4">
            <svg className="h-7 w-7 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100 mb-2">Failed to Load Threat Model</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">{error || 'Unable to load threat model data.'}</p>
        </div>
      </div>
    );
  }

  const displayedThreats = activeTab ? threatsByType[activeTab] : allThreats;

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
                <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Threat Model Results</h1>
              </div>
              {assessmentDetails ? (
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold bg-slate-100 text-slate-600 border border-slate-200 dark:bg-gray-800/60 dark:text-slate-400 dark:border-gray-700/60 uppercase tracking-wide">
                    {assessmentDetails.department}
                  </span>
                  <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{assessmentDetails.projectName}</span>
                  <span className="text-xs text-slate-400 dark:text-slate-500">&middot; {new Date(assessmentDetails.timestamp).toLocaleDateString()}</span>
                </div>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">{assessment_id}</p>
              )}
            </div>

            <div className="flex items-center gap-2">
              {/* View TM-BOM button */}
              <button
                onClick={() => navigate(`/tmbom/${assessment_id}`)}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-50 border border-cyan-200 text-cyan-700 text-sm font-medium rounded-lg hover:border-cyan-400 hover:bg-cyan-100 dark:bg-cyan-900/20 dark:border-cyan-700/50 dark:text-cyan-400 dark:hover:border-cyan-500 dark:hover:bg-cyan-900/30 transition-all duration-200 shadow-sm"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                View TM-BOM
              </button>

              {/* Interactive mode button */}
              <button
                onClick={() => navigate(`/interactive-threat-model/${assessment_id}`)}
                className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 text-slate-600 text-sm font-medium rounded-lg hover:border-[#0052cc]/40 hover:text-[#0052cc] hover:bg-blue-50/50 dark:bg-gray-800/60 dark:border-gray-700 dark:text-slate-300 dark:hover:border-blue-500/40 dark:hover:text-blue-400 dark:hover:bg-blue-900/20 transition-all duration-200 shadow-sm"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 10l-2 1m0 0l-2-1m2 1v2.5M20 7l-2 1m2-1l-2-1m2 1v2.5M14 4l-2-1-2 1M4 7l2-1M4 7l2 1M4 7v2.5M12 21l-2-1m2 1l2-1m-2 1v-2.5M6 18l-2-1v-2.5M18 18l2-1v-2.5" />
                </svg>
                Interactive Mode
              </button>
            </div>
          </div>

          {/* Navigation strip */}
          <div className="mt-5">
            <NavigationButtons
              assessment_id={assessment_id!}
              currentPage="view-threat-model"
              hasAttackTree={hasAttackTree}
              hasDread={!!dreadData}
              hasMitigation={hasMitigation}
              viewMode={true}
            />
          </div>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
          <div className="bg-white border border-slate-200 dark:bg-gray-900/80 dark:border-gray-700/60 rounded-xl p-4 shadow-sm">
            <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Total Threats</p>
            <p className="text-2xl font-bold text-slate-800 dark:text-slate-100">{allThreats.length}</p>
          </div>
          <div className="bg-white border border-slate-200 dark:bg-gray-900/80 dark:border-gray-700/60 rounded-xl p-4 shadow-sm">
            <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Categories</p>
            <p className="text-2xl font-bold text-slate-800 dark:text-slate-100">{threatTypes.length}</p>
          </div>
          <div className="bg-white border border-red-100 dark:bg-gray-900/80 dark:border-red-800/40 rounded-xl p-4 shadow-sm">
            <p className="text-xs font-medium text-red-400 uppercase tracking-wider mb-1">High Risk</p>
            <p className="text-2xl font-bold text-red-600">{highRiskItems.length}</p>
          </div>
          <div className="bg-white border border-slate-200 dark:bg-gray-900/80 dark:border-gray-700/60 rounded-xl p-4 shadow-sm">
            <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Suggestions</p>
            <p className="text-2xl font-bold text-slate-800 dark:text-slate-100">{threatModelData.result?.raw_response?.improvement_suggestions?.length ?? 0}</p>
          </div>
        </div>

        {/* High Risk Issues */}
        {dreadData && (
          <div className="mb-6">
            <div
              className="flex items-center gap-3 mb-3 cursor-pointer group select-none"
              onClick={() => setIsHighRiskExpanded(!isHighRiskExpanded)}
            >
              <div className="w-7 h-7 rounded-lg bg-red-50 border border-red-200 dark:bg-red-900/20 dark:border-red-800/40 flex items-center justify-center">
                <svg className="h-4 w-4 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">High Risk Issues</h2>
              {highRiskItems.length > 0 && (
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-700 border border-red-200">
                  {highRiskItems.length}
                </span>
              )}
              <div className="ml-auto">
                <svg
                  className={`h-4 w-4 text-slate-400 dark:text-slate-500 group-hover:text-slate-600 dark:group-hover:text-slate-400 transform transition-transform duration-200 ${isHighRiskExpanded ? 'rotate-180' : ''}`}
                  fill="none" viewBox="0 0 24 24" stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </div>
            </div>

            <div className={`overflow-hidden transition-all duration-300 ease-in-out ${isHighRiskExpanded ? 'max-h-[2000px] opacity-100' : 'max-h-0 opacity-0'}`}>
              {highRiskItems.length > 0 ? (
                <div className="bg-white border border-slate-200 dark:bg-gray-900/80 dark:border-gray-700/60 rounded-xl overflow-hidden shadow-sm">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 dark:bg-gray-800/60 dark:border-gray-700/60">
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-40">Threat Type</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3">Scenario</th>
                        <th className="text-right text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-28">Risk Score</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-gray-800/60">
                      {highRiskItems.map((item, index) => (
                        <tr key={index} className="hover:bg-slate-50/70 dark:hover:bg-gray-800/40 transition-colors">
                          <td className="px-5 py-3.5 font-medium text-slate-700 dark:text-slate-300">{item['Threat Type']}</td>
                          <td className="px-5 py-3.5 text-slate-600 dark:text-slate-400">{item['Scenario']}</td>
                          <td className="px-5 py-3.5 text-right">
                            <span className="inline-flex items-center justify-center px-2.5 py-1 rounded-lg text-xs font-bold bg-red-50 text-red-600 border border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800/40">
                              {item.score.toFixed(1)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-white border border-slate-200 dark:bg-gray-900/80 dark:border-gray-700/60 rounded-xl p-8 text-center shadow-sm">
                  <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-200 dark:bg-emerald-900/20 dark:border-emerald-800/40 flex items-center justify-center mx-auto mb-3">
                    <svg className="w-5 h-5 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <p className="text-sm font-medium text-slate-600 dark:text-slate-400">No high risk issues found</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Threat Categories Filter */}
        <div className="mb-6 relative z-20">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-7 h-7 rounded-lg bg-blue-50 border border-blue-200 dark:bg-blue-900/20 dark:border-blue-800/40 flex items-center justify-center">
              <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">
              {isPasta ? 'Business Risk Categories' : 'Filter by Category'}
            </h2>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setActiveTab(null)}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 border ${
                activeTab === null
                  ? 'bg-[#0052cc] text-white border-[#0052cc] shadow-sm'
                  : 'bg-white text-slate-600 border-slate-200 hover:border-[#0052cc]/40 hover:text-[#0052cc] hover:bg-blue-50/50 dark:bg-gray-800/60 dark:text-slate-400 dark:border-gray-700 dark:hover:border-blue-500/40 dark:hover:text-blue-400'
              }`}
            >
              All ({allThreats.length})
            </button>
            {threatTypes.map(type => {
              const style = getTypeStyle(type);
              const isActive = activeTab === type;
              return (
                <button
                  key={type}
                  onClick={() => setActiveTab(type)}
                  className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 border ${
                    isActive
                      ? `${style.bg} ${style.text} ${style.border} shadow-sm`
                      : 'bg-white text-slate-600 border-slate-200 hover:border-slate-300 hover:bg-slate-50 dark:bg-gray-800/60 dark:text-slate-400 dark:border-gray-700 dark:hover:border-gray-600'
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`}></span>
                    {type} ({threatsByType[type].length})
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Threats Table */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-7 h-7 rounded-lg bg-blue-50 border border-blue-200 dark:bg-blue-900/20 dark:border-blue-800/40 flex items-center justify-center">
              <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">Identified Threats</h2>
            {activeTab && (
              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-50 text-[#0052cc] border border-blue-100 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800/40">
                {displayedThreats.length} showing
              </span>
            )}
          </div>

          {displayedThreats.length > 0 ? (
            <div className="bg-white border border-slate-200 dark:bg-gray-900/80 dark:border-gray-700/60 rounded-xl overflow-hidden shadow-sm">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 dark:bg-gray-800/60 dark:border-gray-700/60">
                    {isPasta ? (
                      <>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-36">Business Risk</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-40">Threat</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-32">PASTA Stage</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3">Scenario</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3">Impact</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-28">Confidence</th>
                      </>
                    ) : (
                      <>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-44">Threat Type</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3">Scenario</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-56">Potential Impact</th>
                        <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 w-28">Confidence</th>
                      </>
                    )}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-gray-800/60">
                  {displayedThreats.map((threat: any, index: number) => {
                    const typeStyle = getTypeStyle(isPasta ? '' : threat['Threat Type']);
                    return (
                      <tr key={index} className="hover:bg-slate-50/70 dark:hover:bg-gray-800/40 transition-colors align-top">
                        {isPasta ? (
                          <>
                            <td className="px-5 py-3.5">
                              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-50 text-[#0052cc] border border-blue-100 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800/40">
                                {Array.isArray(threat['Business Risk Type'])
                                  ? threat['Business Risk Type'].join(', ')
                                  : threat['Business Risk Type']}
                              </span>
                            </td>
                            <td className="px-5 py-3.5 font-medium text-slate-700 dark:text-slate-300">{threat['Threat Type']}</td>
                            <td className="px-5 py-3.5 text-slate-500 dark:text-slate-400 text-xs">{threat['PASTA Stage']}</td>
                            <td className="px-5 py-3.5 text-slate-600 dark:text-slate-400">{threat['Scenario']}</td>
                            <td className="px-5 py-3.5 text-slate-600 dark:text-slate-400">{threat['Potential Impact']}</td>
                            <td className="px-5 py-3.5">{confidenceBadge(threat['Confidence'] || 'Medium')}</td>
                          </>
                        ) : (
                          <>
                            <td className="px-5 py-3.5">
                              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${typeStyle.bg} ${typeStyle.text} ${typeStyle.border} ${typeStyle.darkBg} ${typeStyle.darkText} ${typeStyle.darkBorder}`}>
                                <span className={`w-1.5 h-1.5 rounded-full ${typeStyle.dot}`}></span>
                                {threat['Threat Type']}
                              </span>
                            </td>
                            <td className="px-5 py-3.5 text-slate-600 dark:text-slate-400 text-sm leading-relaxed">{threat['Scenario']}</td>
                            <td className="px-5 py-3.5 text-slate-500 dark:text-slate-400 text-sm leading-relaxed">{threat['Potential Impact']}</td>
                            <td className="px-5 py-3.5">{confidenceBadge(threat['Confidence'] || 'Medium')}</td>
                          </>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="bg-white border border-slate-200 dark:bg-gray-900/80 dark:border-gray-700/60 rounded-xl p-10 text-center shadow-sm">
              <p className="text-sm text-slate-500 dark:text-slate-400">No threat data available</p>
            </div>
          )}
        </div>

        {/* Improvement Suggestions */}
        <div>
          <div className="flex items-center gap-3 mb-3">
            <div className="w-7 h-7 rounded-lg bg-amber-50 border border-amber-200 dark:bg-amber-900/20 dark:border-amber-800/40 flex items-center justify-center">
              <svg className="h-4 w-4 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">Improvement Suggestions</h2>
          </div>

          <div className="bg-white border border-slate-200 dark:bg-gray-900/80 dark:border-gray-700/60 rounded-xl overflow-hidden shadow-sm">
            {threatModelData.result?.raw_response?.improvement_suggestions?.length > 0 ? (
              <ul className="divide-y divide-slate-100 dark:divide-gray-800/60">
                {threatModelData.result.raw_response.improvement_suggestions.map((suggestion: string, index: number) => (
                  <li key={index} className="flex items-start gap-3 px-5 py-4 hover:bg-slate-50/70 dark:hover:bg-gray-800/40 transition-colors">
                    <span className="flex-shrink-0 w-5 h-5 rounded-full bg-amber-100 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400 text-xs font-bold flex items-center justify-center mt-0.5">
                      {index + 1}
                    </span>
                    <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">{suggestion}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="p-10 text-center">
                <p className="text-sm text-slate-500 dark:text-slate-400">No improvement suggestions available</p>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};

export default ViewThreatModel;
