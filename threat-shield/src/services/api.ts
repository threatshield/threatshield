import { 
  ReportResponse,
  ThreatModelResponse,
  DreadAssessmentResponse,
  MitigationResponse,
  AttackTreeResponse,
  ReportMetadata
} from '../types/reportTypes';

export const API_BASE_URL = 'http://localhost:5001/api';

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
      console.log('Raw storage history response:', JSON.stringify(responseData, null, 2));
      
      // The backend returns { timestamp, data: [...] }
      if (!responseData.data || !Array.isArray(responseData.data)) {
        console.error('Invalid response format:', responseData);
        throw new Error('Invalid response format from server');
      }
      
      // Filter out reports with no data and log DREAD data
      const validReports = responseData.data.filter((report: any) => {
        if (report?.dread_assessment) {
          console.log('Found DREAD assessment in report:', report.id);
          console.log('DREAD data structure:', JSON.stringify(report.dread_assessment, null, 2));
        }
        
        return report && report.id && (
          report.threat_model ||
          report.dread_assessment ||
          report.mitigation ||
          report.attack_tree
        );
      });
      
      console.log('Valid reports:', validReports);
      return {
        timestamp: responseData.timestamp,
        data: validReports
      };
    } catch (error) {
      console.error('Error in getStorageHistory:', error);
      throw error;
    }
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

  deleteThreatModel: async (assessmentId: string): Promise<{ message: string }> => {
    try {
      const response = await fetch(`${API_BASE_URL}/threat-model/${assessmentId}`, {
        method: 'DELETE',
        credentials: 'include' // Important to include cookies
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
  }
};