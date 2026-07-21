import React, { useEffect, useState, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import NavigationButtons from '../components/common/NavigationButtons';
import { apiService } from '../services/api';

interface ASVSTestCase {
  'Threat Type'?: string;
  'Scenario': string;
  asvs_requirement: string;
  skipped?: boolean;
  skip_reason?: string;
  test_cases?: Array<{
    test_description: string;
    steps: string[];
    expected_result: string;
    pre_condition?: string;
    pass_condition?: string;
    prerequisites?: string;
    test_data?: string;
    validation_criteria?: string;
    validated?: boolean;
    validated_using_ai?: boolean;
  }>;
  test_description?: string;
  validated?: boolean;
  validated_using_ai?: boolean;
}

interface TestCase {
  'Threat Type': string;
  'Scenario': string;
  asvs_requirement: string;
  test_description: string;
  steps: string[];
  expected_result: string;
  pre_condition?: string;
  pass_condition?: string;
  prerequisites?: string;
  test_data?: string;
  validation_criteria?: string;
  validated?: boolean;
  validated_using_ai?: boolean;
}

interface AssessmentDetails {
  department: string;
  projectName: string;
  timestamp: string;
}

function parseAsvsRequirements(text: string): Array<{ code: string; description: string }> {
  const matches = [...text.matchAll(/V\d+\.\d+\.\d+/g)];
  if (matches.length === 0) {
    return [{ code: text.split(/[\s\-:]/)[0], description: text }];
  }
  return matches.map((match, i) => {
    const afterCode = match.index! + match[0].length;
    const nextCodeStart = matches[i + 1]?.index ?? text.length;
    const description = text.slice(afterCode, nextCodeStart).replace(/^\s*[-:]\s*/, '').trim();
    return { code: match[0], description };
  });
}

const THREAT_TYPE_COLORS: Record<string, string> = {
  Spoofing: 'bg-purple-50 dark:bg-purple-950/40 text-purple-700 dark:text-purple-300 border-purple-200 dark:border-purple-800/40',
  Tampering: 'bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800/40',
  Repudiation: 'bg-yellow-50 dark:bg-yellow-950/40 text-yellow-700 dark:text-yellow-300 border-yellow-200 dark:border-yellow-800/40',
  'Information Disclosure': 'bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 border-sky-200 dark:border-sky-800/40',
  'Denial of Service': 'bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800/40',
  'Elevation of Privilege': 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800/40',
};

function getThreatTypeColor(type: string): string {
  return THREAT_TYPE_COLORS[type] ?? 'bg-slate-100 dark:bg-gray-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-gray-700';
}

const toStr = (val: unknown): string => {
  if (val === null || val === undefined) return '';
  if (typeof val === 'object') return JSON.stringify(val, null, 2);
  return String(val);
};

const toStrArr = (val: unknown): string[] => {
  if (!Array.isArray(val)) return val ? [toStr(val)] : [];
  return val.map(toStr);
};

const ViewSecurityTestCases: React.FC = () => {
  const navigate = useNavigate();
  const { assessment_id } = useParams<{ assessment_id: string }>();
  const [isExpanded, setIsExpanded] = useState<boolean>(false);
  const [testCases, setTestCases] = useState<TestCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [assessmentDetails, setAssessmentDetails] = useState<AssessmentDetails | null>(null);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [testCasesExist, setTestCasesExist] = useState<boolean>(true);
  const [generatingTestCases, setGeneratingTestCases] = useState<boolean>(false);
  const [generationMessage, setGenerationMessage] = useState<string>('');
  const [generationError, setGenerationError] = useState<string>('');
  const [failedThreatTypes, setFailedThreatTypes] = useState<string[]>([]);
  const [originalTestCases, setOriginalTestCases] = useState<TestCase[]>([]);
  const [threatTypeFilter, setThreatTypeFilter] = useState<string>('All');
  const [validationFilter, setValidationFilter] = useState<'all' | 'validated' | 'invalidated'>('all');
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 3500);
    return () => clearTimeout(t);
  }, [toast]);

  useEffect(() => {
    const loadTestCases = async () => {
      try {
        const data = await apiService.getSecurityTestCases(assessment_id || '');
        if (data?.result?.test_cases && Array.isArray(data.result.test_cases)) {
          const failed: string[] = [];
          const transformed = data.result.test_cases
            .filter((tc: ASVSTestCase) => {
              if (tc.skipped) return false; // Low-confidence threats — excluded from test case view
              if (tc.asvs_requirement === 'Error') {
                let threatTypeName: string | null = tc['Threat Type'] || null;
                if (!threatTypeName && tc.test_description) {
                  const match = tc.test_description.match(/for\s+(.+?)$/);
                  threatTypeName = match ? match[1] : null;
                }
                if (!threatTypeName && tc.test_cases?.[0]?.test_description) {
                  const match = tc.test_cases[0].test_description.match(/for\s+(.+?)$/);
                  threatTypeName = match ? match[1] : null;
                }
                const finalName = threatTypeName || 'Unknown Threat Type';
                failed.push(finalName);
                return false;
              }
              return true;
            })
            .map((tc: ASVSTestCase) => {
              const main = tc.test_cases?.[0] || {
                test_description: 'No details',
                steps: [],
                expected_result: '',
                pre_condition: '',
                pass_condition: '',
                prerequisites: '',
                test_data: '',
                validation_criteria: ''
              };
              return {
                'Threat Type': tc['Threat Type'] || 'Unknown',
                'Scenario': tc['Scenario'],
                asvs_requirement: tc.asvs_requirement,
                test_description: main.test_description,
                steps: toStrArr(main.steps),
                expected_result: toStr(main.expected_result),
                pre_condition: toStr(main.pre_condition),
                pass_condition: toStr(main.pass_condition),
                prerequisites: toStr(main.prerequisites),
                test_data: toStr(main.test_data),
                validation_criteria: main.validation_criteria || '',
                validated: tc.validated || false,
                validated_using_ai: (tc as any).validated_using_ai || false
              };
            });
          setFailedThreatTypes(failed);
          setTestCases(transformed);
          setOriginalTestCases(JSON.parse(JSON.stringify(transformed)));
          setTestCasesExist(transformed.length > 0);
          if (transformed.length > 0) setSelectedIdx(0);
        }
      } catch (e) {
        console.error('Error loading test cases', e);
        setTestCasesExist(false);
      } finally {
        setLoading(false);
      }
    };
    loadTestCases();
  }, [assessment_id]);

  useEffect(() => {
    const fetchDetails = async () => {
      if (!assessment_id) return;
      try {
        const res = await apiService.getStorageHistory();
        const report = res.data.find(r => r.id === assessment_id);
        if (report?.details) {
          setAssessmentDetails(report.details);
        }
      } catch {
        // ignore
      }
    };
    fetchDetails();
  }, [assessment_id]);

  const handleValidationChange = (idx: number, checked: boolean) => {
    const copy = [...testCases];
    copy[idx].validated = checked;
    setTestCases(copy);
  };

  const handleSubmit = async () => {
    try {
      const modifiedTestCases: Array<{ scenario: string; threat: string; validated: boolean; idx: number }> = [];
      testCases.forEach((tc, idx) => {
        const original = originalTestCases[idx];
        if (original && original.validated !== tc.validated) {
          modifiedTestCases.push({
            scenario: tc['Scenario'],
            threat: tc['Threat Type'],
            validated: !!tc.validated,
            idx
          });
        }
      });

      if (modifiedTestCases.length === 0) {
        setToast({ message: 'No changes to submit.', type: 'info' });
        return;
      }

      const batchPayload = {
        test_cases: modifiedTestCases.map(({ scenario, threat, validated }) => ({
          scenario,
          threat,
          validated
        }))
      };

      await apiService.updateMultipleTestCaseValidations(assessment_id || '', batchPayload);
      setToast({ message: `Successfully updated ${modifiedTestCases.length} test case${modifiedTestCases.length !== 1 ? 's' : ''}.`, type: 'success' });
      setOriginalTestCases(JSON.parse(JSON.stringify(testCases)));

      try {
        const refreshedData = await apiService.getSecurityTestCases(assessment_id || '');
        if (refreshedData?.result?.test_cases && Array.isArray(refreshedData.result.test_cases)) {
          const transformed = refreshedData.result.test_cases
            .filter((tc: ASVSTestCase) => !tc.skipped)
            .map((tc: ASVSTestCase) => {
              const main = tc.test_cases?.[0] || {
                test_description: 'No details',
                steps: [],
                expected_result: '',
                pre_condition: '',
                pass_condition: '',
                prerequisites: '',
                test_data: '',
                validation_criteria: ''
              };
              return {
                'Threat Type': tc['Threat Type'] || 'Unknown',
                'Scenario': tc['Scenario'],
                asvs_requirement: tc.asvs_requirement,
                test_description: main.test_description,
                steps: toStrArr(main.steps),
                expected_result: toStr(main.expected_result),
                pre_condition: toStr(main.pre_condition),
                pass_condition: toStr(main.pass_condition),
                prerequisites: toStr(main.prerequisites),
                test_data: toStr(main.test_data),
                validation_criteria: main.validation_criteria || '',
                validated: tc.validated || false,
                validated_using_ai: (tc as any).validated_using_ai || false
              };
            });
          setTestCases(transformed);
          setOriginalTestCases(JSON.parse(JSON.stringify(transformed)));
        }
      } catch (refreshError) {
        console.error('[SUBMIT] Error refreshing test cases:', refreshError);
      }
    } catch (error) {
      console.error('[SUBMIT] Error submitting validation:', error);
      setToast({ message: 'Failed to update test cases. Please try again.', type: 'error' });
    }
  };

  const handleGenerateTestCases = async () => {
    try {
      setGeneratingTestCases(true);
      setGenerationMessage('');
      setGenerationError('');
      const data = await apiService.generateASVSTestCases(assessment_id || '');
      if (data?.result?.test_cases && Array.isArray(data.result.test_cases)) {
        const failed: string[] = [];
        const transformed = data.result.test_cases
          .filter((tc: ASVSTestCase) => {
            if (tc.asvs_requirement === 'Error') {
              let threatTypeName: string | null = tc['Threat Type'] || null;
              if (!threatTypeName && tc.test_description) {
                const match = tc.test_description.match(/for\s+(.+?)$/);
                threatTypeName = match ? match[1] : null;
              }
              if (!threatTypeName && tc.test_cases?.[0]?.test_description) {
                const match = tc.test_cases[0].test_description.match(/for\s+(.+?)$/);
                threatTypeName = match ? match[1] : null;
              }
              const finalName = threatTypeName || 'Unknown Threat Type';
              failed.push(finalName);
              return false;
            }
            return true;
          })
          .map((tc: ASVSTestCase) => {
            const main = tc.test_cases?.[0] || {
              test_description: 'No details',
              steps: [],
              expected_result: '',
              prerequisites: '',
              test_data: '',
              validation_criteria: ''
            };
            return {
              'Threat Type': tc['Threat Type'] || 'Unknown',
              'Scenario': tc['Scenario'],
              asvs_requirement: tc.asvs_requirement,
              test_description: main.test_description,
              steps: toStrArr(main.steps),
              expected_result: toStr(main.expected_result),
              prerequisites: toStr(main.prerequisites),
              test_data: toStr(main.test_data),
              validation_criteria: main.validation_criteria || '',
              validated: tc.validated || false,
              validated_using_ai: (tc as any).validated_using_ai || false
            };
          });
        setFailedThreatTypes(failed);
        setTestCases(transformed);
        setTestCasesExist(transformed.length > 0);
        if (transformed.length > 0) setSelectedIdx(0);
        const successCount = transformed.length;
        const failureCount = failed.length;
        setGenerationMessage(
          `Successfully generated ${successCount} security test cases!${failureCount > 0 ? ` (${failureCount} threat type(s) failed)` : ''}`
        );
      }
    } catch (e) {
      console.error('Error generating test cases', e);
      setGenerationError('Failed to generate security test cases. Please try again.');
    } finally {
      setGeneratingTestCases(false);
    }
  };

  const threatTypes = useMemo(() => {
    const types = Array.from(new Set(testCases.map(tc => tc['Threat Type'])));
    return types.sort();
  }, [testCases]);

  const filteredTestCases = useMemo(() => {
    return testCases
      .map((tc, idx) => ({ ...tc, originalIdx: idx }))
      .filter(tc => {
        if (threatTypeFilter !== 'All' && tc['Threat Type'] !== threatTypeFilter) return false;
        if (validationFilter === 'validated' && !tc.validated) return false;
        if (validationFilter === 'invalidated' && tc.validated) return false;
        return true;
      });
  }, [testCases, threatTypeFilter, validationFilter]);

  const selectedTestCase = selectedIdx !== null ? testCases[selectedIdx] : null;
  const validatedCount = testCases.filter(tc => tc.validated).length;

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-14 h-14">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700"></div>
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin"></div>
          </div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Loading security test cases...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      <div className="max-w-screen-2xl mx-auto px-6 py-8">

        {/* Page Header */}
        <div className="mb-6">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
                  <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
                  </svg>
                </div>
                <h1 className="text-2xl font-bold text-slate-800 dark:text-slate-100">Security Test Cases</h1>
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

            <div className="flex items-start gap-3 flex-shrink-0">
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
          </div>

          <div className="mt-5">
            <NavigationButtons
              assessment_id={assessment_id || ''}
              currentPage="view-security-test-cases"
              viewMode={true}
              hasAttackTree={true}
              hasDread={true}
              hasMitigation={true}
            />
          </div>
        </div>

        {/* Generation errors banner */}
        {failedThreatTypes.length > 0 && (
          <div className="mb-4 p-4 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/40 rounded-xl">
            <div className="flex items-start justify-between">
              <div className="flex items-start flex-1">
                <svg className="w-5 h-5 text-red-600 dark:text-red-400 mt-0.5 mr-3 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
                <div>
                  <h3 className="text-red-800 dark:text-red-300 font-semibold text-sm">Generation Errors</h3>
                  <p className="text-red-700 dark:text-red-400 text-sm mt-1">
                    The following threat type(s) failed to generate test cases: <strong>{failedThreatTypes.join(', ')}</strong>
                  </p>
                </div>
              </div>
              <button
                onClick={handleGenerateTestCases}
                disabled={generatingTestCases}
                className="ml-4 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white rounded-lg font-medium text-sm transition-colors duration-200 flex-shrink-0"
              >
                {generatingTestCases ? (
                  <span className="flex items-center gap-2">
                    <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Regenerating...
                  </span>
                ) : 'Regenerate All'}
              </button>
            </div>
          </div>
        )}

        {testCases.length === 0 ? (
          <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-16 text-center">
            <div className="w-12 h-12 rounded-xl bg-slate-50 dark:bg-gray-800 border border-slate-200 dark:border-gray-700 flex items-center justify-center mx-auto mb-4">
              <svg className="w-6 h-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
            </div>
            <p className="text-slate-500 dark:text-slate-400 mb-6 text-sm">No test cases generated yet.</p>
            {!testCasesExist && (
              <div>
                <button
                  onClick={handleGenerateTestCases}
                  disabled={generatingTestCases}
                  className="px-5 py-2.5 bg-[#0052cc] text-white rounded-lg hover:bg-[#0047b3] disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors duration-200 font-medium text-sm"
                >
                  {generatingTestCases ? (
                    <span className="flex items-center gap-2">
                      <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Generating Test Cases...
                    </span>
                  ) : (
                    <span className="flex items-center gap-2">
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                      </svg>
                      Generate Security Test Cases
                    </span>
                  )}
                </button>
                {generationMessage && (
                  <div className="mt-4 p-4 bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/40 rounded-xl">
                    <p className="text-emerald-700 dark:text-emerald-400 font-medium text-sm">{generationMessage}</p>
                  </div>
                )}
                {generationError && (
                  <div className="mt-4 p-4 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/40 rounded-xl">
                    <p className="text-red-700 dark:text-red-400 font-medium text-sm">{generationError}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <>
            {/* ASVS Explanation */}
            <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm mb-4 overflow-hidden">
              <div
                className="flex items-center gap-3 px-5 py-3.5 border-b border-slate-100 dark:border-gray-800 cursor-pointer select-none"
                onClick={() => setIsExpanded(!isExpanded)}
              >
                <div className="w-6 h-6 rounded-md bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/40 flex items-center justify-center flex-shrink-0">
                  <svg className="h-3.5 w-3.5 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h2 className="text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider flex-1">
                  What are Security Test Cases as per ASVS?
                </h2>
                <svg
                  className={`h-4 w-4 text-slate-400 transform transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
                  fill="none" viewBox="0 0 24 24" stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </div>
              <div className={`transition-all duration-300 ease-in-out overflow-hidden ${isExpanded ? 'max-h-[500px] opacity-100' : 'max-h-0 opacity-0'}`}>
                <div className="px-5 py-4">
                  <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                    Security test cases in threat modeling are structured checks derived from identified threats, ensuring that each potential risk has a corresponding validation step to confirm security controls are in place. The OWASP Application Security Verification Standard (ASVS) is a framework that defines comprehensive security requirements, guiding the creation of these test cases to align with industry best practices.
                  </p>
                </div>
              </div>
            </div>

            {/* Filters + Progress bar row */}
            <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm mb-4 px-5 py-3.5">
              <div className="flex items-center gap-4 flex-wrap">
                {/* Threat Type filter */}
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap">Threat Type</span>
                  <div className="relative">
                    <select
                      value={threatTypeFilter}
                      onChange={e => { setThreatTypeFilter(e.target.value); setSelectedIdx(null); }}
                      className="appearance-none pl-3 pr-7 py-1.5 text-sm font-medium rounded-lg border border-slate-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-slate-700 dark:text-slate-200 cursor-pointer focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc]"
                    >
                      <option value="All">All Types</option>
                      {threatTypes.map(type => (
                        <option key={type} value={type}>{type}</option>
                      ))}
                    </select>
                    <svg className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </div>
                </div>

                {/* Validation filter */}
                <div className="flex items-center gap-1.5">
                  <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap">Status</span>
                  <div className="flex rounded-lg overflow-hidden border border-slate-200 dark:border-gray-700">
                    {(['all', 'validated', 'invalidated'] as const).map(f => (
                      <button
                        key={f}
                        onClick={() => { setValidationFilter(f); setSelectedIdx(null); }}
                        className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                          validationFilter === f
                            ? f === 'validated'
                              ? 'bg-emerald-500 text-white'
                              : f === 'invalidated'
                              ? 'bg-slate-500 text-white'
                              : 'bg-[#0052cc] text-white'
                            : 'bg-white dark:bg-gray-800 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-gray-700'
                        }`}
                      >
                        {f === 'all' ? 'All' : f === 'validated' ? 'Validated' : 'Pending'}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Progress */}
                <div className="flex items-center gap-2 ml-auto">
                  <span className="text-xs text-slate-500 dark:text-slate-400">{validatedCount}/{testCases.length} validated</span>
                  <div className="w-24 bg-slate-100 dark:bg-gray-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className="h-full bg-[#0052cc] rounded-full transition-all duration-500"
                      style={{ width: `${testCases.length > 0 ? (validatedCount / testCases.length) * 100 : 0}%` }}
                    />
                  </div>
                  <button
                    onClick={handleSubmit}
                    className="px-3 py-1.5 text-xs font-semibold bg-[#0052cc] text-white rounded-lg hover:bg-[#0047b3] transition-all"
                  >
                    Submit Validation
                  </button>
                </div>
              </div>
            </div>

            {/* Split pane */}
            <div className="flex gap-4" style={{ height: 'calc(125vh - 372px)', minHeight: '480px' }}>
              {/* Left pane — test case list */}
              <div className="w-80 flex-shrink-0 bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm flex flex-col overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-100 dark:border-gray-800 flex-shrink-0">
                  <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                    {filteredTestCases.length} test case{filteredTestCases.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <div className="overflow-y-auto flex-1">
                  {filteredTestCases.length === 0 ? (
                    <div className="flex items-center justify-center h-32 text-slate-400 dark:text-slate-500 text-sm">
                      No test cases match filters
                    </div>
                  ) : (
                    <div className="divide-y divide-slate-100 dark:divide-gray-800">
                      {filteredTestCases.map((tc) => {
                        const isSelected = selectedIdx === tc.originalIdx;
                        return (
                          <div
                            key={tc.originalIdx}
                            className={`group px-4 py-3 cursor-pointer transition-colors ${
                              isSelected
                                ? 'bg-blue-50 dark:bg-blue-950/30 border-l-2 border-l-[#0052cc]'
                                : tc.validated
                                ? 'bg-emerald-50/60 dark:bg-emerald-900/10 hover:bg-emerald-50 dark:hover:bg-emerald-900/20'
                                : 'hover:bg-slate-50 dark:hover:bg-gray-800/40'
                            }`}
                            onClick={() => setSelectedIdx(tc.originalIdx)}
                          >
                            <div className="flex items-start gap-2.5">
                              {/* Checkbox */}
                              <div
                                className="flex-shrink-0 mt-0.5"
                                onClick={e => { e.stopPropagation(); handleValidationChange(tc.originalIdx, !tc.validated); }}
                              >
                                <input
                                  type="checkbox"
                                  checked={!!tc.validated}
                                  onChange={e => handleValidationChange(tc.originalIdx, e.target.checked)}
                                  className="h-3.5 w-3.5 rounded text-[#0052cc] border-slate-300 dark:border-gray-600 cursor-pointer accent-[#0052cc]"
                                  onClick={e => e.stopPropagation()}
                                />
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className={`text-xs font-medium leading-snug line-clamp-2 ${
                                  isSelected
                                    ? 'text-[#0052cc] dark:text-blue-300'
                                    : 'text-slate-700 dark:text-slate-200'
                                }`}>
                                  {tc['Scenario']}
                                </p>
                                <div className="flex items-center gap-1.5 mt-1.5">
                                  <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border ${getThreatTypeColor(tc['Threat Type'])}`}>
                                    {tc['Threat Type']}
                                  </span>
                                  {tc.validated && (
                                    <span className="inline-flex items-center gap-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-400">
                                      <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                                      </svg>
                                      {tc.validated_using_ai ? 'Validated using AI' : 'Validated'}
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              {/* Right pane — details */}
              <div className="flex-1 bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm flex flex-col overflow-hidden">
                {selectedTestCase ? (
                  <>
                    {/* Details header */}
                    <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800 flex-shrink-0">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1.5">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${getThreatTypeColor(selectedTestCase['Threat Type'])}`}>
                              {selectedTestCase['Threat Type']}
                            </span>
                            {selectedTestCase.validated && (
                              <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-600 dark:text-emerald-400">
                                <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20">
                                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                                </svg>
                                {selectedTestCase.validated_using_ai ? 'Validated using AI' : 'Validated'}
                              </span>
                            )}
                          </div>
                          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100 leading-snug">
                            {selectedTestCase['Scenario']}
                          </h3>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <button
                            onClick={() => handleValidationChange(selectedIdx!, !selectedTestCase.validated)}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                              selectedTestCase.validated
                                ? 'bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/40 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-100 dark:hover:bg-emerald-900/40'
                                : 'bg-slate-50 dark:bg-gray-800 border border-slate-200 dark:border-gray-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-gray-700'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={!!selectedTestCase.validated}
                              readOnly
                              className="h-3.5 w-3.5 rounded accent-[#0052cc] pointer-events-none"
                            />
                            {selectedTestCase.validated
                              ? (selectedTestCase.validated_using_ai ? 'Validated using AI' : 'Validated')
                              : 'Mark as Validated'}
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Details body */}
                    <div className="overflow-y-auto flex-1 px-6 py-5 space-y-5">
                      {/* ASVS Clause */}
                      <div>
                        <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">ASVS Clause</p>
                        <div className="flex flex-wrap gap-2">
                          {parseAsvsRequirements(selectedTestCase.asvs_requirement).map(({ code, description }, i) => (
                            <div key={i} className="relative group/asvs">
                              <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-blue-50 dark:bg-blue-950/30 border border-blue-100 dark:border-blue-800/40">
                                <span className="text-xs font-bold font-mono text-[#0052cc] dark:text-blue-300">{code}</span>
                                {description && (
                                  <span className="text-xs text-slate-600 dark:text-slate-300 leading-tight">{description}</span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Test Case Description */}
                      <div>
                        <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Test Case</p>
                        <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed bg-slate-50 dark:bg-gray-800/60 rounded-lg px-4 py-3 border border-slate-100 dark:border-gray-700/60">
                          {selectedTestCase.test_description}
                        </p>
                      </div>

                      {/* Steps */}
                      {selectedTestCase.steps && selectedTestCase.steps.length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Steps</p>
                          <ol className="space-y-2">
                            {selectedTestCase.steps.map((step, i) => (
                              <li key={i} className="flex items-start gap-3 text-sm text-slate-700 dark:text-slate-200">
                                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-[#0052cc]/10 dark:bg-blue-900/30 text-[#0052cc] dark:text-blue-300 text-xs font-bold flex items-center justify-center mt-0.5">
                                  {i + 1}
                                </span>
                                <span className="leading-relaxed">{step.replace(/^\d+\.\s*/, '')}</span>
                              </li>
                            ))}
                          </ol>
                        </div>
                      )}

                      {/* Expected Result */}
                      {selectedTestCase.expected_result && (
                        <div>
                          <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Expected Result</p>
                          <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed bg-emerald-50/60 dark:bg-emerald-950/20 rounded-lg px-4 py-3 border border-emerald-100 dark:border-emerald-900/30">
                            {selectedTestCase.expected_result}
                          </p>
                        </div>
                      )}

                      {/* Pre-condition (new) or Prerequisites (legacy) */}
                      {(selectedTestCase.pre_condition || selectedTestCase.prerequisites) && (
                        <div>
                          <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                            {selectedTestCase.pre_condition ? 'Pre-condition' : 'Prerequisites'}
                          </p>
                          <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed">
                            {selectedTestCase.pre_condition || selectedTestCase.prerequisites}
                          </p>
                        </div>
                      )}

                      {/* Test Data */}
                      {selectedTestCase.test_data && (
                        <div>
                          <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Test Data</p>
                          <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed font-mono bg-slate-50 dark:bg-gray-800/60 rounded-lg px-4 py-3 border border-slate-100 dark:border-gray-700/60">
                            {selectedTestCase.test_data}
                          </p>
                        </div>
                      )}

                      {/* Pass Condition (new) or Validation Criteria (legacy) */}
                      {(selectedTestCase.pass_condition || selectedTestCase.validation_criteria) && (
                        <div>
                          <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                            {selectedTestCase.pass_condition ? 'Pass Condition' : 'Validation Criteria'}
                          </p>
                          <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed">
                            {selectedTestCase.pass_condition || selectedTestCase.validation_criteria}
                          </p>
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-center px-8">
                    <div className="w-12 h-12 rounded-xl bg-slate-50 dark:bg-gray-800 border border-slate-200 dark:border-gray-700 flex items-center justify-center mb-3">
                      <svg className="w-6 h-6 text-slate-300 dark:text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                      </svg>
                    </div>
                    <p className="text-sm font-medium text-slate-400 dark:text-slate-500">Select a test case to view details</p>
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {/* Toast notification */}
      {toast && (
        <div className={`fixed bottom-6 right-6 z-50 flex items-start gap-3 px-4 py-3.5 rounded-xl shadow-lg border max-w-sm transition-all duration-300 ${
          toast.type === 'success'
            ? 'bg-emerald-50 dark:bg-emerald-950/90 border-emerald-200 dark:border-emerald-800/60 text-emerald-800 dark:text-emerald-200'
            : toast.type === 'error'
            ? 'bg-red-50 dark:bg-red-950/90 border-red-200 dark:border-red-800/60 text-red-800 dark:text-red-200'
            : 'bg-blue-50 dark:bg-blue-950/90 border-blue-200 dark:border-blue-800/60 text-blue-800 dark:text-blue-200'
        }`}>
          {toast.type === 'success' && (
            <svg className="w-4 h-4 flex-shrink-0 mt-0.5 text-emerald-600 dark:text-emerald-400" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          )}
          {toast.type === 'error' && (
            <svg className="w-4 h-4 flex-shrink-0 mt-0.5 text-red-600 dark:text-red-400" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
          )}
          {toast.type === 'info' && (
            <svg className="w-4 h-4 flex-shrink-0 mt-0.5 text-blue-600 dark:text-blue-400" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
          )}
          <p className="text-sm font-medium leading-snug">{toast.message}</p>
          <button
            onClick={() => setToast(null)}
            className="ml-auto flex-shrink-0 opacity-60 hover:opacity-100 transition-opacity"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}
    </div>
  );
}

export default ViewSecurityTestCases;
