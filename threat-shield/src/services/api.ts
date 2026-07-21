import { 
  ReportResponse,
  ThreatModelResponse,
  DreadAssessmentResponse,
  MitigationResponse,
  AttackTreeResponse,
  ReportMetadata,
  ASVSTestCaseResponse
} from '../types/reportTypes';

const DEPLOYMENT_TYPE = process.env.REACT_APP_DEPLOYMENT_TYPE ?? 'dev';

const API_URL_MAP: Record<string, string> = {
  dev:   process.env.REACT_APP_API_URL_DEV   ?? 'http://localhost:5001/api',
  stage: process.env.REACT_APP_API_URL_STAGE ?? 'http://localhost:5001/api',
  prod:  process.env.REACT_APP_API_URL_PROD  ?? 'http://localhost:5001/api',
};

export const API_BASE_URL = API_URL_MAP[DEPLOYMENT_TYPE] ?? API_URL_MAP['dev'];


export const apiService = {
  getStorageHistory: async (): Promise<{ timestamp: string; data: ReportMetadata[] }> => {
    try {
      console.log('Fetching storage history...');
      const response = await fetch(`${API_BASE_URL}/storage`).catch(err => {
        console.error('Network error:', err);
        throw new Error(`Network error: ${err.message || 'Failed to connect to server'}`);
      });
      
      if (!response) {
        throw new Error('No response from server');
      }
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || `Server error: ${response.status} ${response.statusText}`);
      }
      
      const responseData = await response.json();
      // console.log('Raw storage history response:', JSON.stringify(responseData, null, 2));
      
      // The backend returns { timestamp, data: [...] }
      if (!responseData.data || !Array.isArray(responseData.data)) {
        console.error('Invalid response format:', responseData);
        throw new Error('Invalid response format from server');
      }
      
      // Filter out reports with no data and log DREAD data
      const validReports = responseData.data.filter((report: any) => {
        if (report?.dread_assessment) {
          // console.log('Found DREAD assessment in report:', report.id);
          // console.log('DREAD data structure:', JSON.stringify(report.dread_assessment, null, 2));
        }
        
        const status = report?.details?.status;
        const isActive = status === 'failed' || status === 'completed' || status === 'pending' || status === 'queued' || status === 'processing';
        return report && report.id && (
          isActive ||
          report.threat_model ||
          report.dread_assessment ||
          report.mitigation ||
          report.attack_tree
        );
      });
      
      // console.log('Valid reports:', validReports);
      return {
        timestamp: responseData.timestamp,
        data: validReports
      };
    } catch (error) {
      console.error('Error in getStorageHistory:', error);
      throw error;
    }
  },

  getAnalyticsData: async (): Promise<{ timestamp: string; data: any[] }> => {
    const response = await fetch(`${API_BASE_URL}/analytics-data`);
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || `Server error: ${response.status}`);
    }
    const responseData = await response.json();
    if (!responseData.data || !Array.isArray(responseData.data)) {
      throw new Error('Invalid response format from server');
    }
    return responseData;
  },

  getMetrics: async (params: { period?: string; start_date?: string; end_date?: string } = {}): Promise<any> => {
    const qs = new URLSearchParams();
    if (params.period) qs.set('period', params.period);
    if (params.start_date) qs.set('start_date', params.start_date);
    if (params.end_date) qs.set('end_date', params.end_date);
    const response = await fetch(`${API_BASE_URL}/metrics?${qs.toString()}`);
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || `Server error: ${response.status}`);
    }
    return response.json();
  },


  uploadDocuments: async (formData: FormData) => {
    const response = await fetch(`${API_BASE_URL}/upload`, {
      method: 'POST',
      body: formData
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      // Create an error object with response data for better error handling
      const error: any = new Error(errorData?.error || 'Upload failed');
      error.response = { data: errorData };
      throw error;
    }
    const data = await response.json();
    
    // Store page counts in sessionStorage for use in the loading screen
    if (data.pdf_page_counts) {
      sessionStorage.setItem('pdf_page_counts', JSON.stringify(data.pdf_page_counts));
    }
    
    return data;
  },
  
  generateThreatModel: async (assessmentId: string): Promise<ThreatModelResponse> => {
    try {
      // Generate new threat model
      const response = await fetch(`${API_BASE_URL}/threat-model?assessment_id=${assessmentId}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        // Create an error object with response data for better error handling
        const error: any = new Error(errorData?.error || 'Failed to generate threat model');
        error.response = { data: errorData };
        throw error;
      }
      return response.json();
    } catch (error) {
      console.error('Error generating threat model:', error);
      throw error;
    }
  },

  generateDreadAssessment: async (assessmentId: string): Promise<DreadAssessmentResponse> => {
    try {
      const response = await fetch(`${API_BASE_URL}/dread-assessment?assessment_id=${assessmentId}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        // Create an error object with response data for better error handling
        const error: any = new Error(errorData?.error || 'Failed to generate DREAD assessment');
        error.response = { data: errorData };
        throw error;
      }
      return response.json();
    } catch (error) {
      console.error('Error generating DREAD assessment:', error);
      throw error;
    }
  },

  generateMitigation: async (assessmentId: string): Promise<MitigationResponse> => {
    try {
      const response = await fetch(`${API_BASE_URL}/mitigations?assessment_id=${assessmentId}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        // Create an error object with response data for better error handling
        const error: any = new Error(errorData?.error || 'Failed to generate mitigation');
        error.response = { data: errorData };
        throw error;
      }
      return response.json();
    } catch (error) {
      console.error('Error generating mitigation:', error);
      throw error;
    }
  },

  generateAttackTree: async (assessmentId: string): Promise<AttackTreeResponse> => {
    try {
      const response = await fetch(`${API_BASE_URL}/attack-tree?assessment_id=${assessmentId}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        // Create an error object with response data for better error handling
        const error: any = new Error(errorData?.error || 'Failed to generate attack tree');
        error.response = { data: errorData };
        throw error;
      }
      return response.json();
    } catch (error) {
      console.error('Error generating attack tree:', error);
      throw error;
    }
  },
  
  getDreadAssessment: async (assessmentId: string): Promise<DreadAssessmentResponse> => {
    try {
      // Fetch existing DREAD assessment from storage
      const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=dread_assessment`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to fetch DREAD assessment');
      }
      
      const data = await response.json();
      
      // Return the data directly as it's already in the correct format
      return data;
    } catch (error) {
      console.error('Error fetching DREAD assessment:', error);
      throw error;
    }
  },
  
  getMitigations: async (assessmentId: string): Promise<MitigationResponse> => {
    try {
      // Fetch existing mitigations from storage
      const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=mitigation`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to fetch mitigations');
      }
      
      const data = await response.json();
      
      // Return the data directly as it's already in the correct format
      return data;
    } catch (error) {
      console.error('Error fetching mitigations:', error);
      throw error;
    }
  },
  
  getStoredThreatModel: async (assessmentId: string): Promise<ThreatModelResponse> => {
    try {
      // Fetch existing threat model from storage
      const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=threat_model`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to fetch threat model from storage');
      }
      return response.json();
    } catch (error) {
      console.error('Error fetching threat model from storage:', error);
      throw error;
    }
  },

  getStoredDreadAssessment: async (assessmentId: string): Promise<DreadAssessmentResponse> => {
    try {
      const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=dread_assessment`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to fetch DREAD assessment from storage');
      }
      return response.json();
    } catch (error) {
      console.error('Error fetching DREAD assessment from storage:', error);
      throw error;
    }
  },

  getStoredMitigation: async (assessmentId: string): Promise<MitigationResponse> => {
    try {
      const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=mitigation`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to fetch mitigation from storage');
      }
      return response.json();
    } catch (error) {
      console.error('Error fetching mitigation from storage:', error);
      throw error;
    }
  },

  getStoredAttackTree: async (assessmentId: string): Promise<AttackTreeResponse> => {
    try {
      const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=attack_tree`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to fetch attack tree from storage');
      }
      return response.json();
    } catch (error) {
      console.error('Error fetching attack tree from storage:', error);
      throw error;
    }
  },

  generateASVSTestCases: async (assessmentId: string): Promise<ASVSTestCaseResponse> => {
    try {
      console.log('Generating ASVS test cases for assessment:', assessmentId);
      const response = await fetch(`${API_BASE_URL}/asvs-test-cases?assessment_id=${assessmentId}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to generate ASVS test cases');
      }
      const data = await response.json();
      console.log('ASVS test cases generated successfully:', data);
      return data;
    } catch (error) {
      console.error('Error generating ASVS test cases:', error);
      throw error;
    }
  },

  updateTestCaseValidation: async (assessmentId: string, scenario: string, validated: boolean, threat?: string): Promise<any> => {
    try {
      const response = await fetch(`${API_BASE_URL}/update-asvs-test-cases?assessment_id=${assessmentId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ validated, scenario, threat })
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to update test case validation');
      }
      return response.json();
    } catch (error) {
      console.error('Error updating test case validation:', error);
      throw error;
    }
  },

  updateMultipleTestCaseValidations: async (assessmentId: string, batchPayload: { test_cases: Array<{ scenario: string; threat: string; validated: boolean }> }): Promise<any> => {
    try {
      const response = await fetch(`${API_BASE_URL}/update-asvs-test-cases?assessment_id=${assessmentId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(batchPayload)
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to update test cases');
      }
      return response.json();
    } catch (error) {
      console.error('Error updating multiple test cases:', error);
      throw error;
    }
  },

  getSecurityTestCases: async (assessmentId: string): Promise<ASVSTestCaseResponse> => {
    try {
      console.log('Fetching security test cases for:', assessmentId);
      const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=test_cases`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to fetch security test cases');
      }
      // Unwrap nested result
      const raw = await response.json();
      console.log('Security test cases raw response:', raw);
      const unwrapped: ASVSTestCaseResponse = raw.result;
      console.log('Unwrapped security test cases:', unwrapped);

      // Backend stores test cases under unwrapped.result.test_cases
      if (!unwrapped?.result?.test_cases || !Array.isArray(unwrapped.result.test_cases)) {
        throw new Error('Invalid test cases data format');
      }

      // Normalize any singular test_case fields
      unwrapped.result.test_cases = unwrapped.result.test_cases.map((tc: any) => ({
        ...tc,
        test_cases: tc.test_cases || tc.test_case || []
      }));

      return unwrapped;
    } catch (error) {
      console.error('Error fetching security test cases:', error);
      throw error;
    }
  },

  getAttackTree: async (assessmentId: string): Promise<AttackTreeResponse> => {
    try {
      // Fetch existing attack tree from storage
      const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=attack_tree`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to fetch attack tree');
      }
      
      const data = await response.json();
      
      // Return the data directly as it's already in the correct format
      return data;
    } catch (error) {
      console.error('Error fetching attack tree:', error);
      throw error;
    }
  },

  getAdditionalInfo: async (assessmentId: string): Promise<any> => {
    try {
      console.log(`Fetching additional info for assessment ID: ${assessmentId}`);
      const url = `${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=additionalinfo`;
      console.log(`Request URL: ${url}`);
      
      const response = await fetch(url);
      console.log(`Response status: ${response.status}`);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        console.error('Error response data:', errorData);
        throw new Error(errorData?.error || `Failed to fetch additional info: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log('Additional info data received:', JSON.stringify(data, null, 2));
      
      return data;
    } catch (error) {
      console.error('Error fetching additional info:', error);
      throw error;
    }
  },

  getRAGResult: async (assessmentId: string): Promise<any> => {
    try {
      console.log(`Fetching RAG result for assessment ID: ${assessmentId}`);
      // Fetch RAG result from storage
      const url = `${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=rag_result`;
      console.log(`Request URL: ${url}`);
      
      const response = await fetch(url);
      console.log(`Response status: ${response.status}`);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        console.error('Error response data:', errorData);
        throw new Error(errorData?.error || `Failed to fetch RAG result: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log('RAG result data received:', JSON.stringify(data, null, 2));
      
      // Accept any valid JSON response, even if it doesn't have the expected structure
      return data;
    } catch (error) {
      console.error('Error fetching RAG result:', error);
      throw error;
    }
  },

  queryAI: async (assessmentId: string, message: string) => {
    const response = await fetch(`${API_BASE_URL}/query-ai`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessment_id: assessmentId, user_query: message })
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to query AI');
    }
    return response.json();
  },

  getReport: async (assessmentId: string): Promise<ReportResponse> => {
    try {
      console.log('Fetching report data for:', assessmentId);
      
      // Create an object to store all report data
      const result: any = {};
      const timestamp = new Date().toISOString();

      // Fetch all report types in parallel
      const reportTypes = ['threat_model', 'dread_assessment', 'mitigation', 'attack_tree'];
      console.log('Making parallel requests for report types:', reportTypes);
      const responses = await Promise.all(
        reportTypes.map(type => {
          const url = `${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=${type}`;
          console.log(`Fetching ${type} from: ${url}`);
          return fetch(url)
            .then(async response => {
              console.log(`Response status for ${type}:`, response.status);
              if (!response.ok) {
                console.log(`No ${type} data available or failed to fetch (${response.status})`);
                return { type, data: null };
              }
              const data = await response.json();
              console.log(`Received data for ${type}:`, data);
              return { type, data };
            })
            .catch(err => {
              console.error(`Error fetching ${type}:`, err);
              return { type, data: null };
            });
        })
      );

      // Process all responses
      responses.forEach(({ type, data }) => {
        if (data && data.result) {
          result[type] = data;
          console.log(`Added ${type} data to result:`, data);
        } else {
          console.log(`No valid data for ${type}`);
        }
      });

      console.log('Final result object:', result);

      // Check if we got any data
      if (Object.keys(result).length === 0) {
        throw new Error('No report data found');
      }

      console.log('Successfully fetched all report data');
      return {
        timestamp,
        result
      };
    } catch (error) {
      console.error('Error fetching report:', error);
      throw error;
    }
  },

  downloadReport: async (assessmentId: string) => {
    const response = await fetch(`${API_BASE_URL}/report/download?assessment_id=${assessmentId}`);
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to download report');
    }
    return response.blob();
  },

  downloadCombinedJson: async (assessmentId: string) => {
    const response = await fetch(`${API_BASE_URL}/report/download-json?assessment_id=${assessmentId}`);
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to download combined JSON');
    }
    return response.blob();
  },

  downloadPdf: async (assessmentId: string) => {
    const response = await fetch(`${API_BASE_URL}/report/download-pdf?assessment_id=${assessmentId}`);
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to download PDF report');
    }
    return response.blob();
  },

  getTmBom: async (assessmentId: string): Promise<any> => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/tmbom?assessment_id=${assessmentId}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      const err: any = new Error(errorData?.error || 'Failed to fetch TM-BOM');
      err.notGenerated = errorData?.not_generated === true;
      throw err;
    }
    return response.json();
  },

  generateTmBom: async (assessmentId: string): Promise<any> => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/tmbom/generate?assessment_id=${assessmentId}`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to generate TM-BOM');
    }
    return response.json();
  },

  downloadTmBom: async (assessmentId: string): Promise<Blob> => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/tmbom/download?assessment_id=${assessmentId}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to download TM-BOM');
    }
    return response.blob();
  },

  validateConnections: async (data: { confluence_url: string | null, slack_url: string | null }) => {
    const response = await fetch(`${API_BASE_URL}/validate-connections`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to validate connections');
    }
    return response.json();
  },

  getDetails: async (assessmentId: string): Promise<any> => {
    try {
      const response = await fetch(`${API_BASE_URL}/details?assessment_id=${assessmentId}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to fetch details');
      }
      return response.json();
    } catch (error) {
      console.error('Error fetching details:', error);
      throw error;
    }
  },

  storeDetails: async (assessmentId: string, details: any) => {
    const response = await fetch(`${API_BASE_URL}/store-details`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        assessment_id: assessmentId,
        details: details
      })
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to store details');
    }
    return response.json();
  },

  // Get settings from settings.json
  getSettings: async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/settings`);
      if (!response.ok) {
        // If settings don't exist yet, return default settings
        if (response.status === 404) {
          return {
            data: {
              defaultMethodology: 'STRIDE',
              enabledMethodologies: {
                STRIDE: true,
                PASTA: true,
                OCTAVE: true
              }
            }
          };
        }
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to get settings');
      }
      return response.json();
    } catch (error) {
      console.error('Error getting settings:', error);
      // Return default settings if there's an error
      return {
        data: {
          defaultMethodology: 'STRIDE',
          enabledMethodologies: {
            STRIDE: true,
            PASTA: true,
            OCTAVE: true
          }
        }
      };
    }
  },

  // Save settings to settings.json
  saveSettings: async (settings: any) => {
    try {
      const response = await fetch(`${API_BASE_URL}/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to save settings');
      }
      return response.json();
    } catch (error) {
      console.error('Error saving settings:', error);
      throw error;
    }
  },

  // Bootstrap: set first admin when none are configured
  bootstrapAdmin: async (email: string): Promise<{ message: string; admins: string[] }> => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/setup/bootstrap-admin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ email }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to set admin');
    return data;
  },

  // Admin: get LLM config (no secrets)
  getAdminLlmConfig: async () => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/admin/llm-config`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to get LLM config');
    }
    return response.json();
  },

  // Admin: save LLM config (method, model, base_url — no keys)
  saveAdminLlmConfig: async (llmConfig: { method: string; model: string; large_output_model?: string; base_url?: string; tested?: boolean }) => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/admin/llm-config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(llmConfig),
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to save LLM config');
    }
    return response.json();
  },

  // Public: get general app config (e.g. display timezone)
  getGeneralConfig: async (): Promise<{ generalConfig: { timezone: string } }> => {
    const response = await fetch(`${API_BASE_URL}/general-config`);
    if (!response.ok) {
      throw new Error('Failed to get general config');
    }
    return response.json();
  },

  // Admin: save general app config (display timezone)
  saveGeneralConfig: async (config: { timezone: string }) => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/admin/general-config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(config),
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to save general config');
    }
    return response.json();
  },

  // Admin: test LLM with optional pre-save config override
  testAdminLlm: async (llmConfig?: { method: string; model: string; large_output_model?: string; base_url?: string }): Promise<{ success: boolean; response?: string; model?: string; error?: string }> => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/admin/test-llm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(llmConfig ? { llmConfig } : {}),
    });
    return response.json();
  },

  // Admin: test GitHub token from .env
  testGitHub: async (): Promise<{ success: boolean; login?: string; name?: string; scopes?: string[]; error?: string }> => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/admin/test-github`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    return response.json();
  },

  // Admin: get admin email list
  getAdminList: async (): Promise<{ admins: string[] }> => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/admin/admins`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to get admin list');
    }
    return response.json();
  },

  // Admin: save admin email list
  saveAdminList: async (admins: string[]): Promise<{ admins: string[] }> => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/admin/admins`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ admins }),
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to save admin list');
    }
    return response.json();
  },

  deleteThreatModel: async (assessmentId: string): Promise<{ message: string }> => {
    try {
      const token = localStorage.getItem('ts_auth_token');
      const response = await fetch(`${API_BASE_URL}/threat-model/${assessmentId}`, {
        method: 'DELETE',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || `Failed to delete threat model: ${response.status} ${response.statusText}`);
      }

      return response.json();
    } catch (error) {
      console.error('Error deleting threat model:', error);
      throw error;
    }
  },

  retriggerThreatModel: async (assessmentId: string): Promise<{ message: string }> => {
    try {
      const token = localStorage.getItem('ts_auth_token');
      const response = await fetch(`${API_BASE_URL}/admin/retrigger/${assessmentId}`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || `Failed to retrigger threat model: ${response.status} ${response.statusText}`);
      }

      return response.json();
    } catch (error) {
      console.error('Error retriggering threat model:', error);
      throw error;
    }
  },

  generateDiagrams: async (assessmentId: string): Promise<any> => {
    try {
      console.log('Generating diagrams for assessment:', assessmentId);
      const response = await fetch(`${API_BASE_URL}/generate-diagrams?assessment_id=${assessmentId}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'Failed to generate diagrams');
      }
      const data = await response.json();
      console.log('Diagrams generated successfully:', data);
      return data;
    } catch (error) {
      console.error('Error generating diagrams:', error);
      throw error;
    }
  },

  // Admin: get threat filter / false-positive suppression config
  getThreatFilterConfig: async (): Promise<{ threatFilterConfig: any }> => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/admin/threat-filter-config`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to get threat filter config');
    }
    return response.json();
  },

  // Admin: save threat filter / false-positive suppression config
  saveThreatFilterConfig: async (config: any): Promise<{ message: string; timestamp: string }> => {
    const token = localStorage.getItem('ts_auth_token');
    const response = await fetch(`${API_BASE_URL}/admin/threat-filter-config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(config),
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(errorData?.error || 'Failed to save threat filter config');
    }
    return response.json();
  },

};
