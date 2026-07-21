import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
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
  const navigate = useNavigate();
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
    department: string;
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
        setError(null);
        setDreadData(null);
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
      fetchAllData();
    }
  }, [assessment_id, setContextDreadData]);

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
    if (score >= 8) return { text: 'High', bg: 'bg-red-50', text_color: 'text-red-600', border: 'border-red-200' };
    if (score >= 6) return { text: 'Medium', bg: 'bg-amber-50', text_color: 'text-amber-600', border: 'border-amber-200' };
    return { text: 'Low', bg: 'bg-emerald-50', text_color: 'text-emerald-600', border: 'border-emerald-200' };
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
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-14 h-14">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700"></div>
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin"></div>
          </div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Loading DREAD assessment...</p>
        </div>
      </div>
    );
  }

  if (error || !dreadData) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center p-6">
        <div className="bg-white dark:bg-gray-900/80 border border-red-100 dark:border-red-900/40 rounded-2xl p-10 text-center max-w-md shadow-sm">
          <div className="w-14 h-14 rounded-2xl bg-red-50 dark:bg-red-900/20 border border-red-100 dark:border-red-800/40 flex items-center justify-center mx-auto mb-4">
            <svg className="h-7 w-7 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100 mb-2">Failed to Load DREAD Assessment</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">{error || 'Failed to load DREAD assessment data.'}</p>
        </div>
      </div>
    );
  }

  const SortIcon = ({ field }: { field: string }) => {
    if (sortField !== field) return null;
    return (
      <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 ml-1 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sortDirection === 'asc' ? "M5 15l7-7 7 7" : "M19 9l-7 7-7-7"} />
      </svg>
    );
  };

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
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                </div>
                <h1 className="text-2xl font-bold text-slate-800 dark:text-slate-100">DREAD Risk Assessment</h1>
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
              currentPage="view-dread"
              viewMode={true}
              hasAttackTree={!!attackTreeData}
              hasDread={!!dreadData}
              hasMitigation={!!mitigationData}
            />
          </div>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
          {[
            { label: 'Total Threats', value: sortedAssessments.length, accent: false },
            {
              label: 'High Risk',
              value: sortedAssessments.filter(a => calculateRiskScore(a) >= 8).length,
              accent: true,
              accentColor: 'text-red-600 dark:text-red-400',
              borderColor: 'border-red-100 dark:border-red-900/40'
            },
            {
              label: 'Medium Risk',
              value: sortedAssessments.filter(a => { const s = calculateRiskScore(a); return s >= 6 && s < 8; }).length,
              accent: true,
              accentColor: 'text-amber-600 dark:text-amber-400',
              borderColor: 'border-amber-100 dark:border-amber-900/40'
            },
            {
              label: 'Low Risk',
              value: sortedAssessments.filter(a => calculateRiskScore(a) < 6).length,
              accent: true,
              accentColor: 'text-emerald-600 dark:text-emerald-400',
              borderColor: 'border-emerald-100 dark:border-emerald-900/40'
            },
          ].map((stat, i) => (
            <div key={i} className={`bg-white dark:bg-gray-900/80 border ${stat.borderColor || 'border-slate-200 dark:border-gray-700/60'} rounded-xl p-4 shadow-sm`}>
              <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">{stat.label}</p>
              <p className={`text-2xl font-bold ${stat.accentColor || 'text-slate-800 dark:text-slate-100'}`}>{stat.value}</p>
            </div>
          ))}
        </div>

        {/* DREAD Explanation (collapsible) */}
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm mb-6 overflow-hidden">
          <div
            className="flex items-center gap-3 px-6 py-4 border-b border-slate-100 dark:border-gray-800 cursor-pointer select-none"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            <div className="w-7 h-7 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/40 flex items-center justify-center flex-shrink-0">
              <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider flex-1">Understanding DREAD</h2>
            <svg
              className={`h-4 w-4 text-slate-400 transform transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
              fill="none" viewBox="0 0 24 24" stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </div>

          <div className={`transition-all duration-300 ease-in-out overflow-hidden ${isExpanded ? 'max-h-[2000px] opacity-100' : 'max-h-0 opacity-0'}`}>
            <div className="p-6">
              <p className="text-sm text-slate-600 dark:text-slate-300 mb-5">
                DREAD is a risk assessment model used to calculate risk scores for identified security threats. Each threat is rated on a scale of 1–10 across five categories:
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3 mb-5">
                {[
                  { letter: 'D', label: 'Damage Potential', desc: 'How much damage could be caused if the vulnerability is exploited?' },
                  { letter: 'R', label: 'Reproducibility', desc: 'How easy is it to reproduce the attack?' },
                  { letter: 'E', label: 'Exploitability', desc: 'How much effort and expertise is needed to exploit the vulnerability?' },
                  { letter: 'A', label: 'Affected Users', desc: 'How many users would be affected if the vulnerability is exploited?' },
                  { letter: 'D', label: 'Discoverability', desc: 'How easy is it to discover the vulnerability?' },
                ].map((item, i) => (
                  <div key={i} className="bg-slate-50 dark:bg-gray-800/60 rounded-lg p-4 border border-slate-100 dark:border-gray-700/60">
                    <h3 className="font-semibold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
                      <span className="bg-[#0052cc] text-white w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold">{item.letter}</span>
                      {item.label}
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">{item.desc}</p>
                  </div>
                ))}
              </div>
              <div className="bg-blue-50/50 dark:bg-blue-950/20 p-4 rounded-lg border border-blue-100 dark:border-blue-900/30">
                <p className="text-sm text-slate-600 dark:text-slate-300">
                  <strong>Risk Score</strong> is calculated as the average of all five ratings. Higher scores indicate higher risk.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* DREAD Assessment Table */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-7 h-7 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/40 flex items-center justify-center">
              <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">Risk Assessment Results</h2>
          </div>

          <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-slate-50 dark:bg-gray-800/60 border-b border-slate-200 dark:border-gray-800">
                    <th
                      className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 cursor-pointer hover:text-slate-700 dark:hover:text-slate-200 select-none"
                      onClick={() => handleSort('Threat Type')}
                    >
                      Threat Type <SortIcon field="Threat Type" />
                    </th>
                    <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3">Scenario</th>
                    {['Damage Potential', 'Reproducibility', 'Exploitability', 'Affected Users', 'Discoverability'].map((col, i) => (
                      <th
                        key={col}
                        className="text-center text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-3 py-3 cursor-pointer hover:text-slate-700 dark:hover:text-slate-200 select-none w-12"
                        onClick={() => handleSort(col)}
                        title={col}
                      >
                        {['D', 'R', 'E', 'A', 'D'][i]} <SortIcon field={col} />
                      </th>
                    ))}
                    <th
                      className="text-center text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-5 py-3 cursor-pointer hover:text-slate-700 dark:hover:text-slate-200 select-none"
                      onClick={() => handleSort('Risk Score')}
                    >
                      Risk Score <SortIcon field="Risk Score" />
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-gray-800">
                  {sortedAssessments.map((assessment, index) => {
                    const riskScore = calculateRiskScore(assessment);
                    const riskLevel = getRiskLevel(riskScore);
                    return (
                      <tr key={index} className="hover:bg-slate-50 dark:hover:bg-gray-800/40 transition-colors align-top">
                        <td className="px-5 py-3.5 font-medium text-slate-800 dark:text-slate-200">{assessment['Threat Type']}</td>
                        <td className="px-5 py-3.5 text-slate-600 dark:text-slate-300 text-sm leading-relaxed">{assessment['Scenario']}</td>
                        <td className="px-3 py-3.5 text-center text-slate-700 dark:text-slate-300">{assessment['Damage Potential']}</td>
                        <td className="px-3 py-3.5 text-center text-slate-700 dark:text-slate-300">{assessment['Reproducibility']}</td>
                        <td className="px-3 py-3.5 text-center text-slate-700 dark:text-slate-300">{assessment['Exploitability']}</td>
                        <td className="px-3 py-3.5 text-center text-slate-700 dark:text-slate-300">{assessment['Affected Users']}</td>
                        <td className="px-3 py-3.5 text-center text-slate-700 dark:text-slate-300">{assessment['Discoverability']}</td>
                        <td className="px-5 py-3.5 text-center">
                          <span className={`inline-flex items-center justify-center px-2.5 py-1 rounded-lg text-xs font-bold border ${riskLevel.bg} ${riskLevel.text_color} ${riskLevel.border}`}>
                            {riskScore.toFixed(1)}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Risk Distribution */}
        <div>
          <div className="flex items-center gap-3 mb-3">
            <div className="w-7 h-7 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/40 flex items-center justify-center">
              <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z" />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">Risk Distribution</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { level: 'High', bg: 'bg-red-50 dark:bg-red-950/20', text: 'text-red-800 dark:text-red-300', bar: 'bg-red-500', border: 'border-red-200 dark:border-red-900/40', barBg: 'bg-red-200 dark:bg-red-900/30' },
              { level: 'Medium', bg: 'bg-amber-50 dark:bg-amber-950/20', text: 'text-amber-800 dark:text-amber-300', bar: 'bg-amber-500', border: 'border-amber-200 dark:border-amber-900/40', barBg: 'bg-amber-200 dark:bg-amber-900/30' },
              { level: 'Low', bg: 'bg-emerald-50 dark:bg-emerald-950/20', text: 'text-emerald-800 dark:text-emerald-300', bar: 'bg-emerald-500', border: 'border-emerald-200 dark:border-emerald-900/40', barBg: 'bg-emerald-200 dark:bg-emerald-900/30' },
            ].map(({ level, bg, text, bar, border, barBg }) => {
              const count = sortedAssessments.filter(assessment => {
                const score = calculateRiskScore(assessment);
                if (level === 'High') return score >= 8;
                if (level === 'Medium') return score >= 6 && score < 8;
                return score < 6;
              }).length;
              const percentage = sortedAssessments.length > 0
                ? Math.round((count / sortedAssessments.length) * 100)
                : 0;
              return (
                <div key={level} className={`rounded-xl p-5 ${bg} border ${border}`}>
                  <h3 className={`text-sm font-semibold mb-2 ${text}`}>{level} Risk</h3>
                  <div className="flex items-end justify-between mb-3">
                    <div className={`text-3xl font-bold ${text}`}>{count}</div>
                    <div className={`text-lg font-semibold ${text} opacity-70`}>{percentage}%</div>
                  </div>
                  <div className={`rounded-full h-2 overflow-hidden ${barBg}`}>
                    <div className={`h-full ${bar} transition-all duration-500`} style={{ width: `${percentage}%` }}></div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

      </div>
    </div>
  );
};

export default Dread;
