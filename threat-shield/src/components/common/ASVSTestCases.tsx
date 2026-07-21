import React, { useState, useEffect } from 'react';
import { apiService } from '../../services/api';

interface ASVSTestCaseDetail {
  test_description: string;
  steps: string[];
  expected_result: string;
  prerequisites?: string;
  test_data?: string;
  validation_criteria?: string;
  validated?: boolean;
}

interface ASVSTestCase {
  'Threat Type': string;
  'Scenario': string;
  asvs_requirement: string;  // Changed to match actual data
  test_cases: ASVSTestCaseDetail[];
}

interface ASVSTestCasesProps {
  assessmentId: string;
  threatScenario: string; // The scenario of the currently selected threat
}

const ASVSTestCases: React.FC<ASVSTestCasesProps> = ({ assessmentId, threatScenario }) => {
  const [testCases, setTestCases] = useState<ASVSTestCaseDetail[]>([]);
  const [requirement, setRequirement] = useState<string>('');  // Changed to single string
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [debugInfo, setDebugInfo] = useState<any>(null);

  useEffect(() => {
    const fetchASVSTestCases = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await apiService.getSecurityTestCases(assessmentId);
        console.log('ASVS response:', response);
        if (response?.result?.test_cases) {
          const testCases = response.result.test_cases;
          console.log('Looking for test case with scenario:', threatScenario);

          // Store debug info
          setDebugInfo({
            searchingFor: threatScenario,
            availableTestCases: testCases.map(tc => ({
              scenario: tc['Scenario'],
              type: tc['Threat Type']
            })),
            apiResponse: response
          });

          // Find the test case that matches the threat scenario exactly
          const matchingTestCase = testCases.find(tc => {
            const scenarioMatches = tc['Scenario'].trim() === threatScenario.trim();
            console.log('Comparing scenarios:', {
              testCase: tc['Scenario'].trim(),
              threatScenario: threatScenario.trim(),
              matches: scenarioMatches,
              lengthDiff: tc['Scenario'].length - threatScenario.length
            });
            return scenarioMatches;
          });

          if (matchingTestCase) {
            console.log('Found matching test case:', {
              scenario: matchingTestCase['Scenario'],
              type: matchingTestCase['Threat Type'],
              requirement: matchingTestCase.asvs_requirement,
              testCases: matchingTestCase.test_cases
            });
            setTestCases(matchingTestCase.test_cases);
            setRequirement(matchingTestCase.asvs_requirement);
          } else {
            console.log('No matching test case found');
            setTestCases([]);
            setRequirement('');
          }
        } else {
          console.log('No test cases in response');
          setTestCases([]);
          setRequirement('');
        }
      } catch (err) {
        console.error('Error fetching ASVS test cases:', err);
        setError('No test cases generated.');
      } finally {
        setLoading(false);
      }
    };

    if (assessmentId && threatScenario) {
      fetchASVSTestCases();
    }
  }, [assessmentId, threatScenario]);

  const handleValidationChange = async (index: number, validated: boolean) => {
    const updatedTestCases = [...testCases];
    updatedTestCases[index].validated = validated;
    setTestCases(updatedTestCases);

    try {
      await apiService.updateTestCaseValidation(assessmentId, threatScenario, validated);
      console.log(`Test case for scenario "${threatScenario}" marked as ${validated ? 'validated' : 'not validated'}.`);
    } catch (err) {
      console.error('Error updating ASVS test case validation status:', err);
      setError('Failed to update validation status.');
      // Revert the change if API call fails
      updatedTestCases[index].validated = !validated;
      setTestCases(updatedTestCases);
    }
  };

  const handleSubmit = async (index: number) => {
    try {
      await apiService.updateTestCaseValidation(assessmentId, threatScenario, true);
      const updated = [...testCases];
      updated[index].validated = true;
      setTestCases(updated);
    } catch (err) {
      console.error('Error updating ASVS test case validation status:', err);
      setError('Failed to update validation status.');
    }
  };

  if (loading) {
    return <div className="text-center text-gray-500 dark:text-slate-400 py-8">Loading ASVS test cases...</div>;
  }

  if (error) {
    return (
      <div className="space-y-4 p-8">
        <div className="text-center text-red-500 dark:text-red-400">{error}</div>
        {debugInfo && (
          <div className="mt-4 bg-gray-50 dark:bg-gray-800/60 p-4 rounded text-sm">
            <p className="font-medium text-gray-700 dark:text-slate-300 mb-2">Debug Information:</p>
            <pre className="whitespace-pre-wrap text-gray-600 dark:text-slate-400 overflow-auto">
              {JSON.stringify(debugInfo, null, 2)}
            </pre>
          </div>
        )}
      </div>
    );
  }

  if (testCases.length === 0) {
    return (
      <div className="space-y-4 p-8">
        <div className="text-center text-gray-500 dark:text-slate-400">No ASVS test cases found for this threat scenario.</div>
        <div className="mt-4 bg-gray-50 dark:bg-gray-800/60 p-4 rounded text-sm">
          <p className="font-medium text-gray-700 dark:text-slate-300 mb-2">Debug Information:</p>
          <div className="space-y-4 text-gray-600 dark:text-slate-400">
            <div>
              <p className="font-medium">Searching for scenario:</p>
              <pre className="mt-1 p-2 bg-white dark:bg-gray-900/60 rounded border border-gray-200 dark:border-gray-700 whitespace-pre-wrap">
                {threatScenario}
              </pre>
            </div>
            {debugInfo && (
              <div>
                <p className="font-medium">Available test cases:</p>
                <pre className="mt-1 p-2 bg-white dark:bg-gray-900/60 rounded border border-gray-200 dark:border-gray-700 whitespace-pre-wrap overflow-auto max-h-60">
                  {JSON.stringify(debugInfo, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* ASVS Requirements */}
      <div className="mb-4">
        <h3 className="text-lg font-semibold text-gray-800 dark:text-slate-100 mb-2">ASVS Requirements</h3>
        <div className="bg-gray-50 dark:bg-gray-800/60 p-4 rounded-lg border border-gray-200 dark:border-gray-700/60">
          <div className="text-gray-700 dark:text-slate-300">{requirement}</div>
        </div>
      </div>

      {/* Test Cases */}
      <div>
        <h3 className="text-lg font-semibold text-gray-800 dark:text-slate-100 mb-4">Test Cases</h3>
        <div className="space-y-6">
          {testCases.map((testCase, index) => (
            <div key={index} className="border border-gray-200 dark:border-gray-700/60 rounded-lg p-4 shadow-sm bg-white dark:bg-gray-900/60">
              <div className="flex items-center justify-between mb-4">
                <h4 className="font-semibold text-md text-gray-800 dark:text-slate-100">Test Case {index + 1}</h4>
                {testCase.validated ? (
                  <span className="text-sm font-medium text-green-600 dark:text-green-400">Validated</span>
                ) : (
                  <button
                    onClick={() => handleSubmit(index)}
                    className="px-3 py-1 bg-blue-500 hover:bg-blue-600 text-white text-sm rounded transition-colors"
                  >
                    Mark as Validated
                  </button>
                )}
              </div>
              <div className="space-y-4">
                <div>
                  <p className="font-medium text-sm text-gray-700 dark:text-slate-300">Description:</p>
                  <p className="text-sm text-gray-600 dark:text-slate-400">{testCase.test_description}</p>
                </div>

                {testCase.steps && testCase.steps.length > 0 && (
                  <div>
                    <p className="font-medium text-sm text-gray-700 dark:text-slate-300">Steps:</p>
                    <div className="text-sm text-gray-600 dark:text-slate-400 space-y-1">
                      {testCase.steps.map((step, i) => (
                        <p key={i}>{step}</p>
                      ))}
                    </div>
                  </div>
                )}

                {testCase.expected_result && (
                  <div>
                    <p className="font-medium text-sm text-gray-700 dark:text-slate-300">Expected Result:</p>
                    <p className="text-sm text-gray-600 dark:text-slate-400">{testCase.expected_result}</p>
                  </div>
                )}

                {testCase.prerequisites && (
                  <div>
                    <p className="font-medium text-sm text-gray-700 dark:text-slate-300">Prerequisites:</p>
                    <p className="text-sm text-gray-600 dark:text-slate-400">{testCase.prerequisites}</p>
                  </div>
                )}

                {testCase.test_data && (
                  <div>
                    <p className="font-medium text-sm text-gray-700 dark:text-slate-300">Test Data:</p>
                    <p className="text-sm text-gray-600 dark:text-slate-400">{testCase.test_data}</p>
                  </div>
                )}

                {testCase.validation_criteria && (
                  <div>
                    <p className="font-medium text-sm text-gray-700 dark:text-slate-300">Validation Criteria:</p>
                    <p className="text-sm text-gray-600 dark:text-slate-400">{testCase.validation_criteria}</p>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ASVSTestCases;
