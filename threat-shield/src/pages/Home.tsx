import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import DragDropUpload from '../components/common/DragDropUpload';
import LoadingScreen from '../components/common/LoadingScreen';
import { useAssessment } from '../context/AssessmentContext';
import { apiService, API_BASE_URL } from '../services/api';
import { LoaderState, stageMessages } from '../types/loader';
import axios from 'axios';

interface FormData {
  projectName: string;
  description: string;
  documentSource: 'pdf';
  confluenceUrl: string;
  architectureDiagrams: FileList | null;
  department: string;
  applicationType: string;
  isInternetFacing: boolean;
  dataSensitivityLevel: 'Highest' | 'High' | 'Medium' | 'Low';
  authenticationMethod: 'BEARER TOKEN' | 'SSO' | 'MFA' | 'OAUTH' | 'BASIC' | 'JWT';
  selectedMethodology: 'STRIDE' | 'PASTA' | 'OCTAVE';
  // Additional document sources
  hasConfluenceDoc: boolean;
  confluenceDocContent: string;
  hasSlackThread: boolean;
  slackThreadContent: string;
  hasMeetingTranscript: boolean;
  meetingTranscriptContent: string;
}

// Constants for dropdown options
const DATA_SENSITIVITY_OPTIONS = ['Highest', 'High', 'Medium', 'Low'] as const;
const AUTHENTICATION_OPTIONS = ['BEARER TOKEN', 'SSO', 'MFA', 'OAUTH', 'BASIC', 'JWT'] as const;

const Home: React.FC = () => {
  const navigate = useNavigate();
  // State for Department options
  const [departmentOptions, setDepartmentOptions] = useState<string[]>([]);

  // Fetch Team options when component mounts
  useEffect(() => {
    const fetchTeamOptions = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/teams`);
        if (!response.ok) throw new Error('Failed to fetch teams');
        const data = await response.json();
        setDepartmentOptions(data.teams || []);
      } catch (error) {
        console.error('Error fetching teams:', error);
        setDepartmentOptions([]);
      }
    };
    fetchTeamOptions();
  }, []);

  const [formData, setFormData] = useState<FormData>({
    projectName: '',
    description: '',
    documentSource: 'pdf',
    confluenceUrl: '',
    architectureDiagrams: null,
    department: '',
    applicationType: 'web',
    isInternetFacing: false,
    dataSensitivityLevel: 'High',
    authenticationMethod: 'BEARER TOKEN',
    selectedMethodology: 'STRIDE',
    // Additional document sources
    hasConfluenceDoc: false,
    confluenceDocContent: '',
    hasSlackThread: false,
    slackThreadContent: '',
    hasMeetingTranscript: false,
    meetingTranscriptContent: '',
  });

  const [showSetupPopup, setShowSetupPopup] = useState(false);
  const [setupEmail, setSetupEmail] = useState('');
  const [setupEmailError, setSetupEmailError] = useState('');
  const [setupLoading, setSetupLoading] = useState(false);
  const [setupSuccess, setSetupSuccess] = useState(false);

  // Show setup popup once if setup hasn't been dismissed and no admins are configured.
  // The dismissed flag is persisted server-side in storage/data/settings/settings.json.
  useEffect(() => {
    apiService.getSettings().then((res: any) => {
      const data = res?.data ?? {};
      if (data.setupDismissed) return;
      const admins: string[] = data.admins ?? [];
      if (admins.length === 0) setShowSetupPopup(true);
    }).catch(() => {});
  }, []);

  const handleSetupSubmit = async () => {
    const email = setupEmail.trim().toLowerCase();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setSetupEmailError('Please enter a valid email address.');
      return;
    }
    setSetupEmailError('');
    setSetupLoading(true);
    try {
      await apiService.bootstrapAdmin(email);
      setSetupSuccess(true);
      // Dismissed flag is now persisted server-side by the bootstrap-admin endpoint.
    } catch (err: any) {
      setSetupEmailError(err.message || 'Failed to set admin. Please try again.');
    } finally {
      setSetupLoading(false);
    }
  };

  const [isLoading, setIsLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [pdfError, setPdfError] = useState<boolean>(false);
  const [selectedPdfFiles, setSelectedPdfFiles] = useState<FileList | null>(null);
  const pdfFileRef = useRef<HTMLInputElement>(null);
  const loadingAssessmentIdRef = useRef<string | null>(null);
  const isCancelledRef = useRef(false);

  // Context functions
  const {
    setAssessmentId: setContextAssessmentId,
    setThreatModelData: setContextThreatModelData,
    setDreadData: setContextDreadData,
    setMitigationData: setContextMitigationData
  } = useAssessment();

  // Function to add a new log entry
  const addLog = (text: string, indent?: number, type: 'info' | 'success' | 'warning' | 'error' | 'task' = 'info') => {
    setLoaderState(prevState => ({
      ...prevState,
      logs: [
        ...prevState.logs,
        {
          id: `${Date.now()}-${Math.random()}`,
          text,
          timestamp: Date.now(),
          indent,
          type
        }
      ]
    }));
  };

  // Loading state
  const [loaderState, setLoaderState] = useState<LoaderState>({
    stage: 'upload',
    progress: 0,
    message: 'Preparing to process documents...',
    logs: []
  });
  const [showLoader, setShowLoader] = useState(false);
  const [isCancelling, setIsCancelling] = useState(false);

  const handleCancelLoading = async () => {
    isCancelledRef.current = true;
    const id = loadingAssessmentIdRef.current;
    if (!id) {
      setShowLoader(false);
      setIsLoading(false);
      return;
    }
    try {
      setIsCancelling(true);
      await fetch(`${API_BASE_URL}/cancel-assessment/${id}`, { method: 'POST' });
    } catch {
      // best-effort cancel
    } finally {
      setIsCancelling(false);
      setShowLoader(false);
      setIsLoading(false);
      loadingAssessmentIdRef.current = null;
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
  };

  const handleCheckboxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, checked } = e.target;
    setFormData({
      ...formData,
      [name]: checked,
    });
  };

  const handleMethodologyChange = (methodology: 'STRIDE' | 'PASTA' | 'OCTAVE') => {
    setFormData(prevFormData => ({
      ...prevFormData,
      selectedMethodology: methodology
    }));
  };


  const handlePdfFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedPdfFiles(e.target.files);
      console.log("PDF files selected:", e.target.files.length);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validate that a PRD document has been uploaded
    if (!selectedPdfFiles || selectedPdfFiles.length === 0) {
      setPdfError(true);
      window.scrollTo(0, 0);
      return;
    }

    setShowLoader(true);
    setIsLoading(true);
    isCancelledRef.current = false;

    try {
      console.log("Starting form submission process");
      const submitData = new FormData();

      // Map form fields to API parameters
      submitData.append('name', formData.projectName);
      submitData.append('description', formData.description);
      submitData.append('department', formData.department);
      submitData.append('app_type', formData.applicationType);
      submitData.append('sensitivity_level', formData.dataSensitivityLevel);
      submitData.append('internet_facing', formData.isInternetFacing ? 'Yes' : 'No');
      submitData.append('authentication[]', formData.authenticationMethod);

      // Add Confluence URL if provided in additional documents
      if (formData.hasConfluenceDoc && formData.confluenceDocContent) {
        submitData.append('confluence_url', formData.confluenceDocContent);
      }

      // Handle architecture diagrams
      if (formData.architectureDiagrams) {
        for (let i = 0; i < formData.architectureDiagrams.length; i++) {
          submitData.append('image_files', formData.architectureDiagrams[i]);
        }
      }

      // Handle PDF files if selected - this is the PRD document
      console.log("Adding PDF files to form data:", selectedPdfFiles?.length || 0, "files");
      if (selectedPdfFiles) {
        for (let i = 0; i < selectedPdfFiles.length; i++) {
          console.log(`Adding PDF file ${i+1}:`, selectedPdfFiles[i].name, selectedPdfFiles[i].size, "bytes");
          submitData.append('pdf_file', selectedPdfFiles[i]);
        }
      }

      // Handle additional document sources
      const additionalInfo = {
        confluenceDoc: formData.hasConfluenceDoc ? formData.confluenceDocContent : null,
        slackThread: formData.hasSlackThread ? formData.slackThreadContent : null,
        meetingTranscript: formData.hasMeetingTranscript ? formData.meetingTranscriptContent : null
      };

      submitData.append('additional_info', JSON.stringify(additionalInfo));

      let currentAssessmentId: string | null = null;

      try {
        // 1. Upload documents
        console.log("Step 1: Uploading documents");
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'upload',
          progress: 25,
          message: 'Uploading and processing documents...'
        }));
        // Set initial stage
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'upload',
          message: stageMessages['upload']
        }));

        // Initial logs will be added in the API call sections

        const uploadResult = await apiService.uploadDocuments(submitData);
        console.log("Upload successful, received assessment_id:", uploadResult.assessment_id);
        currentAssessmentId = uploadResult.assessment_id;
        loadingAssessmentIdRef.current = currentAssessmentId;
        if (currentAssessmentId) {
          console.log("Setting assessment ID in context:", currentAssessmentId);
          setContextAssessmentId(currentAssessmentId);
          // Set flag to indicate this is a new assessment
          sessionStorage.setItem('isNewAssessment', currentAssessmentId);

          // Store form details in a JSON file
          try {
            const detailsToStore = {
              projectName: formData.projectName,
              description: formData.description,
              documentSource: formData.documentSource,
              confluenceUrl: formData.hasConfluenceDoc ? formData.confluenceDocContent : '',
              department: formData.department,
              applicationType: formData.applicationType,
              isInternetFacing: formData.isInternetFacing,
              dataSensitivityLevel: formData.dataSensitivityLevel,
              authenticationMethod: formData.authenticationMethod,
              threatModelingMethodology: formData.selectedMethodology,
              additionalDocuments: {
                confluenceDoc: formData.hasConfluenceDoc ? formData.confluenceDocContent : null,
                slackThread: formData.hasSlackThread ? formData.slackThreadContent : null,
                meetingTranscript: formData.hasMeetingTranscript ? formData.meetingTranscriptContent : null
              },
              timestamp: new Date().toISOString()
            };

            const storeDetailsResponse = await apiService.storeDetails(currentAssessmentId, detailsToStore);
            console.log("Successfully stored project details in storage/", currentAssessmentId, "/details.json");
          } catch (detailsError) {
            console.error("Error storing project details:", detailsError);
            // Continue with the process even if storing details fails
          }
        }
      } catch (error) {
        console.error("Error during document upload:", error);
        // Add error to loading screen logs
        addLog(`Error during document upload: ${error instanceof Error ? error.message : 'Unknown error'}`, 0, 'error');

        // Check if the error response contains traceback information
        if (error instanceof Error && 'response' in error) {
          const errorResponse = (error as any).response;
          if (errorResponse && errorResponse.data && errorResponse.data.traceback) {
            // Log the traceback information
            addLog('Error details:', 1, 'error');
            addLog(errorResponse.data.traceback.split('\n').slice(-3).join('\n'), 2, 'error');
          }
        }

        throw new Error(`Upload failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }

      try {
        // 2. Generate Threat Model
        console.log("Step 2: Generating threat model for assessment_id:", currentAssessmentId);
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'threat-model',
          progress: 40,
          message: 'Generating threat model...'
        }));
        // Step 1: Collecting Application Details
        addLog('Collecting Application Details...', 0, 'task');
        await new Promise(resolve => setTimeout(resolve, 3000));

        // Step 2: Fetching Security Bugs
        addLog(`Fetching existing/open Security bugs for the ${formData.department} team...`, 0, 'task');
        await new Promise(resolve => setTimeout(resolve, 3000));

        // Step 3: Parsing PRD
        addLog('Parsing the PRD provided...', 0, 'task');

        // Parse each PDF file
        if (selectedPdfFiles) {
          for (let i = 0; i < selectedPdfFiles.length; i++) {
            const fileName = selectedPdfFiles[i].name;
            addLog(`File: ${fileName}`, 1);
            await new Promise(resolve => setTimeout(resolve, 1000));

            // Try to get the actual page count from sessionStorage
            let pageCount = 3; // Default fallback
            try {
              const pdfPageCounts = JSON.parse(sessionStorage.getItem('pdf_page_counts') || '{}');
              if (pdfPageCounts[selectedPdfFiles[i].name]) {
                pageCount = pdfPageCounts[selectedPdfFiles[i].name];
                console.log(`Using actual page count for ${selectedPdfFiles[i].name}: ${pageCount} pages`);
              } else {
                // If we don't have the actual count yet, estimate based on file size
                const fileSize = selectedPdfFiles[i].size;
                pageCount = Math.max(1, Math.ceil(fileSize / (100 * 1024)));
                console.log(`Estimating page count for ${selectedPdfFiles[i].name}: ${pageCount} pages`);
              }
            } catch (error) {
              console.error("Error getting page count:", error);
              // Fallback to a reasonable default
              pageCount = Math.max(1, Math.ceil(selectedPdfFiles[i].size / (100 * 1024)));
            }

            // Show page count based on actual data or estimate
            for (let page = 1; page <= pageCount; page++) {
              addLog(`Parsing page ${page}`, 2);
              await new Promise(resolve => setTimeout(resolve, 500)); // Reduced delay for better UX with larger files
            }
          }

          addLog('Extracting key requirements', 1);
          await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Step 4: Architecture image parsing (if provided)
        if (formData.architectureDiagrams && formData.architectureDiagrams.length > 0) {
          addLog('Parsing the Architecture Image...', 0, 'task');
          await new Promise(resolve => setTimeout(resolve, 1000));

          addLog('Identifying components', 1);
          await new Promise(resolve => setTimeout(resolve, 1000));

          addLog('Analyzing relationships', 1);
          await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Step 5-7: Handle additional documents (if provided)
        if (formData.hasConfluenceDoc) {
          addLog('Parsing Confluence documents...', 0, 'task');
          await new Promise(resolve => setTimeout(resolve, 1000));
          addLog(`URL: ${formData.confluenceDocContent}`, 1);
          await new Promise(resolve => setTimeout(resolve, 1000));
          addLog('Extracting content', 1);
          await new Promise(resolve => setTimeout(resolve, 1000));
        }

        if (formData.hasSlackThread) {
          addLog('Parsing Slack threads...', 0, 'task');
          await new Promise(resolve => setTimeout(resolve, 1000));
          addLog(`Thread: ${formData.slackThreadContent}`, 1);
          await new Promise(resolve => setTimeout(resolve, 1000));
          addLog('Extracting messages', 1);
          await new Promise(resolve => setTimeout(resolve, 1000));
        }

        if (formData.hasMeetingTranscript) {
          addLog('Parsing meeting transcripts...', 0, 'task');
          await new Promise(resolve => setTimeout(resolve, 1000));
          addLog('Extracting discussion points', 1);
          await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Step 8: RAG creation — wait for background processing to actually complete
        addLog('Creating RAG...', 0, 'task');
        addLog('Generating embeddings', 1);
        addLog('Building knowledge base', 1);

        if (!currentAssessmentId) {
          throw new Error("Assessment ID is missing");
        }

        // Poll assessment status until background RAG thread finishes (up to 10 minutes)
        const RAG_POLL_INTERVAL_MS = 3000;
        const RAG_POLL_MAX_ATTEMPTS = 200; // 200 * 3s = 10 minutes
        let ragReady = false;
        for (let attempt = 0; attempt < RAG_POLL_MAX_ATTEMPTS; attempt++) {
          if (isCancelledRef.current) throw new Error('CANCELLED');
          await new Promise(resolve => setTimeout(resolve, RAG_POLL_INTERVAL_MS));
          if (isCancelledRef.current) throw new Error('CANCELLED');
          try {
            const statusResponse = await fetch(
              `${API_BASE_URL}/storage?assessment_id=${currentAssessmentId}&assessment_name=details`
            );
            if (statusResponse.ok) {
              const statusData = await statusResponse.json();
              const assessmentStatus = statusData?.result?.status;
              console.log(`RAG polling attempt ${attempt + 1}: status = ${assessmentStatus}`);
              if (assessmentStatus === 'completed') {
                ragReady = true;
                break;
              } else if (assessmentStatus === 'cancelled') {
                throw new Error('CANCELLED');
              } else if (assessmentStatus === 'error' || assessmentStatus === 'failed') {
                throw new Error(`Background processing failed with status: ${assessmentStatus}`);
              }
            }
          } catch (pollErr) {
            if (pollErr instanceof Error && (pollErr.message.startsWith('Background processing failed') || pollErr.message === 'CANCELLED')) {
              throw pollErr;
            }
            console.warn(`Status poll error (attempt ${attempt + 1}):`, pollErr);
          }
        }
        if (!ragReady) {
          addLog('RAG processing is taking longer than expected, proceeding anyway...', 0, 'warning');
        }

        if (isCancelledRef.current) throw new Error('CANCELLED');
        const threatModelResult = await apiService.generateThreatModel(currentAssessmentId);
        console.log("Threat model generation successful:", threatModelResult);
        setContextThreatModelData(threatModelResult);

        // 3–6. Generate Attack Tree, DREAD, Mitigations and Test Cases in parallel
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'parallel-analysis',
          progress: 65,
          message: stageMessages['parallel-analysis'],
        }));

        addLog('Launching parallel analysis...', 0, 'task');
        addLog('Attack Tree generation started', 1);
        addLog('DREAD assessment started', 1);
        addLog('Mitigation generation started', 1);
        addLog('ASVS test case generation started', 1);
        addLog('Data flow diagram generation started', 1);

        // Direct Home-page uploads (is_queue_item=False) run RAG only on the backend; the
        // frontend drives each analysis. The DFD step must be triggered here too, otherwise
        // these assessments never get a diagram. It has the same dependency as attack
        // tree/DREAD (needs the threat model), so running it in this batch is correct.
        // A diagram failure is non-fatal — swallow it so the assessment still completes.
        const [attackTreeResult, dreadResult, mitigationResult, testCasesResult] = await Promise.all([
          apiService.generateAttackTree(currentAssessmentId),
          apiService.generateDreadAssessment(currentAssessmentId),
          apiService.generateMitigation(currentAssessmentId),
          apiService.generateASVSTestCases(currentAssessmentId),
          apiService.generateDiagrams(currentAssessmentId).catch((err) => {
            console.warn('Data flow diagram generation failed (non-fatal):', err);
            return null;
          }),
        ]);

        setContextDreadData(dreadResult);
        setContextMitigationData(mitigationResult);
        addLog('All parallel analyses complete', 0, 'success');
        console.log("Parallel generation complete:", { attackTreeResult, dreadResult, mitigationResult, testCasesResult });

      } catch (error) {
        console.error("Error during generation process:", error);
        // Add error to loading screen logs
        addLog(`Error during generation process: ${error instanceof Error ? error.message : 'Unknown error'}`, 0, 'error');

        // Check if the error response contains traceback information
        if (error instanceof Error && 'response' in error) {
          const errorResponse = (error as any).response;
          if (errorResponse && errorResponse.data && errorResponse.data.traceback) {
            // Log the traceback information
            addLog('Error details:', 1, 'error');
            addLog(errorResponse.data.traceback.split('\n').slice(-3).join('\n'), 2, 'error');
          }
        }

        throw new Error(`Generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }

      // Complete
      console.log("All steps completed successfully");
      setLoaderState(prevState => ({
        ...prevState,
        stage: 'complete',
        progress: 100,
        message: 'Assessment complete!'
      }));

      // Step 13: Final step - completion stage
      setLoaderState(prevState => ({
        ...prevState,
        stage: 'complete',
        message: stageMessages['complete']
      }));

      addLog('Consolidating results...', 0, 'task');
      await new Promise(resolve => setTimeout(resolve, 2000));
      addLog('Process completed successfully!', 0, 'success');

      // Wait a moment to show completion before redirecting
      setTimeout(() => {
        console.log("Redirecting to threat model page");
        if (currentAssessmentId) {
          navigate(`/view-threat-model/${currentAssessmentId}`);
        } else {
          console.error("Cannot navigate: Assessment ID is missing");
          setError("Assessment ID is missing. Please try again.");
        }
      }, 1000);
    } catch (error) {
      console.error('Error in submission process:', error);
      if (!(error instanceof Error && error.message === 'CANCELLED')) {
        setError(error instanceof Error ? error.message : 'Failed to submit data. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const validateConnections = async (): Promise<boolean> => {
    // Only validate if optional document sources are selected
    if (!formData.hasConfluenceDoc && !formData.hasSlackThread) {
      return true;
    }

    try {
      setIsLoading(true);

      // Prepare validation data
      const validationData = {
        confluence_url: formData.hasConfluenceDoc ? formData.confluenceDocContent : null,
        slack_url: formData.hasSlackThread ? formData.slackThreadContent : null
      };

      // Call the validation endpoint using apiService
      const data = await apiService.validateConnections(validationData);

      // Check for validation errors
      let hasErrors = false;
      let errorMessage = "";

      if (formData.hasConfluenceDoc && !data.confluence.valid) {
        hasErrors = true;
        errorMessage += `Confluence: ${data.confluence.message}\n`;
      }

      if (formData.hasSlackThread && !data.slack.valid) {
        hasErrors = true;
        errorMessage += `Slack: ${data.slack.message}\n`;
      }

      if (hasErrors) {
        setError(`Connection validation failed:\n${errorMessage}`);
        // Scroll to the error message
        window.scrollTo({
          top: 0,
          behavior: 'smooth'
        });
        return false;
      }

      return true;
    } catch (error) {
      console.error("Connection validation error:", error);
      setError("Failed to validate connections. Please check your URLs and try again.");
      // Scroll to the error message
      window.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const handleNextStep = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate that a PRD document has been uploaded
    if (!selectedPdfFiles || selectedPdfFiles.length === 0) {
      setPdfError(true);
      window.scrollTo(0, 0);
      return;
    }

    // Validate connections if optional document sources are selected
    const connectionsValid = await validateConnections();
    if (!connectionsValid) {
      return;
    }

    // Clear any previous errors
    setError(null);
    setPdfError(false);
    setCurrentStep(2);
    window.scrollTo(0, 0);
  };

  const handlePrevStep = () => {
    setCurrentStep(1);
    window.scrollTo(0, 0);
  };

  const handleBrowseClick = () => {
    if (pdfFileRef.current) {
      pdfFileRef.current.click();
    }
  };

  // Function to handle individual file removal
  const handlePdfFileRemove = (index: number) => {
    if (selectedPdfFiles) {
      // Create a new array without the removed file
      const files = Array.from(selectedPdfFiles);
      files.splice(index, 1);

      if (files.length === 0) {
        // If no files left, set to null
        setSelectedPdfFiles(null);
      } else {
        // Convert array back to FileList-like object
        const dataTransfer = new DataTransfer();
        files.forEach(file => {
          dataTransfer.items.add(file);
        });

        setSelectedPdfFiles(dataTransfer.files);
      }
    }
  };

  // Shared input className
  const inputCls = "w-full px-3 py-2.5 text-sm border border-slate-200 dark:border-blue-900/40 rounded-lg bg-white dark:bg-[#0d1e38] text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc] transition-all";
  const selectCls = "w-full px-3 py-2.5 text-sm border border-slate-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc] transition-all";
  const labelCls = "block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5";

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      {showLoader && <LoadingScreen state={loaderState} onCancel={handleCancelLoading} isCancelling={isCancelling} />}

      {/* First-time setup popup — shown once when no admins are configured */}
      {showSetupPopup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-white dark:bg-gray-900 rounded-2xl shadow-2xl border border-slate-200 dark:border-gray-700 max-w-md w-full mx-4 p-8">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm flex-shrink-0">
                <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                </svg>
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-800 dark:text-slate-100">Setup ThreatShield</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">One-time configuration required</p>
              </div>
            </div>

            {setupSuccess ? (
              <div className="text-center py-4">
                <div className="w-12 h-12 rounded-full bg-emerald-100 dark:bg-emerald-900/30 flex items-center justify-center mx-auto mb-4">
                  <svg className="w-6 h-6 text-emerald-600 dark:text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <p className="text-sm font-semibold text-slate-800 dark:text-slate-100 mb-1">Admin configured!</p>
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-6">You can now configure the LLM provider and start running assessments.</p>
                <button
                  onClick={() => { setShowSetupPopup(false); navigate('/admin'); }}
                  className="w-full px-4 py-2.5 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] transition-colors"
                >
                  Go to Admin Dashboard
                </button>
              </div>
            ) : (
              <>
                <p className="text-sm text-slate-600 dark:text-slate-300 mb-5">
                  No admin users are configured yet. Enter an email address to set the first admin and unlock all features.
                </p>
                <div className="space-y-3 mb-5">
                  <div className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-5 h-5 rounded-full bg-[#0052cc] text-white text-xs font-bold flex items-center justify-center mt-0.5">1</span>
                    <div>
                      <p className="text-sm font-medium text-slate-700 dark:text-slate-200">Set first admin</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400">The admin can manage users and configure the LLM provider</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-5 h-5 rounded-full bg-slate-200 dark:bg-gray-700 text-slate-500 dark:text-slate-400 text-xs font-bold flex items-center justify-center mt-0.5">2</span>
                    <div>
                      <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Configure LLM provider</p>
                      <p className="text-xs text-slate-400 dark:text-slate-500">Connect an AI model to power threat analysis</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-5 h-5 rounded-full bg-slate-200 dark:bg-gray-700 text-slate-500 dark:text-slate-400 text-xs font-bold flex items-center justify-center mt-0.5">3</span>
                    <div>
                      <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Run your first assessment</p>
                      <p className="text-xs text-slate-400 dark:text-slate-500">Upload a PRD and generate a threat model</p>
                    </div>
                  </div>
                </div>
                <div className="mb-4">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1.5">Admin email address</label>
                  <input
                    type="email"
                    value={setupEmail}
                    onChange={e => { setSetupEmail(e.target.value); setSetupEmailError(''); }}
                    onKeyDown={e => e.key === 'Enter' && handleSetupSubmit()}
                    placeholder="admin@example.com"
                    className="w-full px-3 py-2.5 text-sm rounded-lg border border-slate-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc] transition-colors"
                  />
                  {setupEmailError && (
                    <p className="mt-1.5 text-xs text-red-600 dark:text-red-400 flex items-center gap-1">
                      <svg className="w-3 h-3 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                      {setupEmailError}
                    </p>
                  )}
                </div>
                <button
                  onClick={handleSetupSubmit}
                  disabled={setupLoading}
                  className="w-full px-4 py-2.5 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] disabled:opacity-60 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
                >
                  {setupLoading ? (
                    <>
                      <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      Configuring...
                    </>
                  ) : 'Set as First Admin'}
                </button>
              </>
            )}
          </div>
        </div>
      )}

      <div className="max-w-screen-2xl mx-auto px-6 py-10">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-slate-800 dark:text-slate-100 tracking-tight">New Threat Assessment</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Provide project details and documentation to generate a comprehensive threat model.</p>
        </div>

        {/* Global error banner */}
        {error && !error.includes('Connection validation failed') && (
          <div className="mb-6 px-4 py-3 rounded-lg text-sm font-medium flex items-start gap-2 bg-red-50 text-red-700 border border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800">
            <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div className="flex-1">
              <span>{error}</span>
              <button
                className="block mt-1 text-xs underline opacity-70 hover:opacity-100"
                onClick={() => setError(null)}
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        <div className="space-y-6">
          {currentStep === 1 ? (
            <>
              {/* Step indicator */}
              <div className="flex items-center gap-3 mb-2">
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-[#0052cc] text-white text-xs font-bold">1</span>
                <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">Project Information</span>
                <span className="text-slate-300 dark:text-gray-600 mx-1">›</span>
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-slate-200 dark:bg-gray-700 text-slate-400 dark:text-slate-500 text-xs font-bold">2</span>
                <span className="text-sm text-slate-400 dark:text-slate-500">Additional Details</span>
              </div>

              <form onSubmit={handleNextStep}>
                {/* Two-column grid layout for Step 1 */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">

                  {/* Left column: Project Details + Methodology */}
                  <div className="flex flex-col gap-6">

                    {/* Project Details Card */}
                    <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
                      <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
                        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Project Details</h2>
                      </div>
                      <div className="px-6 py-5 space-y-5">
                        <div>
                          <label htmlFor="projectName" className={labelCls}>
                            Project Name <span className="text-red-500">*</span>
                          </label>
                          <input
                            type="text"
                            id="projectName"
                            name="projectName"
                            value={formData.projectName}
                            onChange={handleInputChange}
                            className={inputCls}
                            placeholder="Enter project name"
                            required
                          />
                        </div>

                        <div>
                          <label htmlFor="description" className={labelCls}>
                            Description <span className="text-red-500">*</span>
                          </label>
                          <textarea
                            id="description"
                            name="description"
                            value={formData.description}
                            onChange={handleInputChange}
                            rows={5}
                            className={`${inputCls} resize-none`}
                            placeholder="Describe the project, its purpose, and key features"
                            required
                          />
                        </div>
                      </div>
                    </div>

                    {/* Threat Modeling Methodology Card */}
                    <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
                      <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
                        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Threat Modeling Methodology</h2>
                      </div>
                      <div className="px-6 py-5 space-y-3">

                        {/* STRIDE */}
                        <label className={`flex items-start justify-between gap-4 p-4 rounded-lg border cursor-pointer transition-colors ${
                          formData.selectedMethodology === 'STRIDE'
                            ? 'border-[#0052cc] bg-blue-50/60 dark:bg-blue-900/20 dark:border-blue-600'
                            : 'border-slate-200 dark:border-gray-700 hover:bg-slate-50 dark:hover:bg-gray-800/60'
                        }`}>
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">STRIDE</span>
                              <div className="relative group">
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-slate-400 dark:text-slate-500 cursor-help" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <div className="absolute z-10 invisible group-hover:visible bg-gray-800 dark:bg-gray-700 text-white text-xs rounded-lg p-2.5 w-64 bottom-full left-1/2 transform -translate-x-1/2 -translate-y-2 shadow-lg">
                                  Use STRIDE when you need a systematic approach to identify threats across six categories. Best for most applications, especially those with clear security boundaries.
                                  <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 translate-y-1 border-8 border-transparent border-t-gray-800 dark:border-t-gray-700"></div>
                                </div>
                              </div>
                            </div>
                            <p className="text-xs text-slate-500 dark:text-slate-400">Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege</p>
                          </div>
                          <input
                            type="radio"
                            name="selectedMethodology"
                            checked={formData.selectedMethodology === 'STRIDE'}
                            onChange={() => handleMethodologyChange('STRIDE')}
                            className="h-4 w-4 mt-0.5 text-[#0052cc] border-slate-300 dark:border-gray-600 focus:ring-[#0052cc]"
                          />
                        </label>

                        {/* PASTA */}
                        <label className={`flex items-start justify-between gap-4 p-4 rounded-lg border cursor-pointer transition-colors ${
                          formData.selectedMethodology === 'PASTA'
                            ? 'border-[#0052cc] bg-blue-50/60 dark:bg-blue-900/20 dark:border-blue-600'
                            : 'border-slate-200 dark:border-gray-700 hover:bg-slate-50 dark:hover:bg-gray-800/60'
                        }`}>
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">PASTA</span>
                              <div className="relative group">
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-slate-400 dark:text-slate-500 cursor-help" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <div className="absolute z-10 invisible group-hover:visible bg-gray-800 dark:bg-gray-700 text-white text-xs rounded-lg p-2.5 w-64 bottom-full left-1/2 transform -translate-x-1/2 -translate-y-2 shadow-lg">
                                  Use PASTA for risk-centric threat modeling with business impact analysis. Ideal for complex applications where understanding business risk is crucial.
                                  <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 translate-y-1 border-8 border-transparent border-t-gray-800 dark:border-t-gray-700"></div>
                                </div>
                              </div>
                            </div>
                            <p className="text-xs text-slate-500 dark:text-slate-400">Process for Attack Simulation and Threat Analysis</p>
                          </div>
                          <input
                            type="radio"
                            name="selectedMethodology"
                            checked={formData.selectedMethodology === 'PASTA'}
                            onChange={() => handleMethodologyChange('PASTA')}
                            className="h-4 w-4 mt-0.5 text-[#0052cc] border-slate-300 dark:border-gray-600 focus:ring-[#0052cc]"
                          />
                        </label>

                        {/* OCTAVE */}
                        <div className="flex items-start justify-between gap-4 p-4 rounded-lg border border-slate-200 dark:border-gray-700 opacity-60 cursor-not-allowed">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">OCTAVE</span>
                              <div className="relative group">
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-slate-400 dark:text-slate-500 cursor-help" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <div className="absolute z-10 invisible group-hover:visible bg-gray-800 dark:bg-gray-700 text-white text-xs rounded-lg p-2.5 w-64 bottom-full left-1/2 transform -translate-x-1/2 -translate-y-2 shadow-lg">
                                  Use OCTAVE for organizational risk assessment focusing on strategic and practice-related issues. Best for enterprise-wide security assessments.
                                  <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 translate-y-1 border-8 border-transparent border-t-gray-800 dark:border-t-gray-700"></div>
                                </div>
                              </div>
                            </div>
                            <p className="text-xs text-slate-500 dark:text-slate-400">Operationally Critical Threat, Asset, and Vulnerability Evaluation</p>
                          </div>
                          <span className="text-xs text-slate-400 dark:text-slate-500 font-medium mt-0.5 whitespace-nowrap">Coming Soon</span>
                        </div>

                      </div>
                    </div>

                  </div>

                  {/* Right column: PRD Document + Additional Document Sources */}
                  <div className="flex flex-col gap-6">

                    {/* PRD Document Card */}
                    <div className="bg-white dark:bg-[#0d1e38]/80 rounded-xl border border-slate-200 dark:border-blue-900/40 shadow-sm overflow-hidden">
                      <div className="px-6 py-4 border-b border-slate-100 dark:border-blue-900/30">
                        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">PRD Document <span className="text-red-500 normal-case font-medium text-xs ml-1">Required</span></h2>
                      </div>
                      <div className="px-6 py-5">
                        <DragDropUpload
                          onFilesSelected={(files) => {
                            // Merge new files with existing files
                            if (selectedPdfFiles) {
                              const existingFiles = Array.from(selectedPdfFiles);
                              const newFiles = Array.from(files);
                              const mergedFiles = [...existingFiles, ...newFiles];
                              const dataTransfer = new DataTransfer();
                              mergedFiles.forEach(file => {
                                dataTransfer.items.add(file);
                              });
                              setSelectedPdfFiles(dataTransfer.files);
                              console.log("PDF files selected:", dataTransfer.files.length);
                            } else {
                              setSelectedPdfFiles(files);
                              console.log("PDF files selected:", files.length);
                            }
                          }}
                          onFileRemove={handlePdfFileRemove}
                          accept=".pdf"
                          multiple={true}
                          initialFiles={selectedPdfFiles}
                        />

                        {pdfError && (
                          <div className="mt-3 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-sm text-center">
                            Please upload a PRD document before proceeding.
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Additional Document Sources Card */}
                    <div className="bg-white dark:bg-[#0d1e38]/80 rounded-xl border border-slate-200 dark:border-blue-900/40 shadow-sm overflow-hidden">
                      <div className="px-6 py-4 border-b border-slate-100 dark:border-blue-900/30">
                        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Additional Document Sources <span className="normal-case font-normal text-slate-400 dark:text-slate-500 text-xs ml-1">Optional</span></h2>
                      </div>
                      <div className="px-6 py-5 space-y-4">

                        {/* Confluence Doc */}
                        <div>
                          <label className="flex items-center gap-2.5 cursor-pointer group">
                            <input
                              type="checkbox"
                              name="hasConfluenceDoc"
                              checked={formData.hasConfluenceDoc}
                              onChange={handleCheckboxChange}
                              className="h-4 w-4 rounded text-[#0052cc] border-slate-300 dark:border-gray-600 focus:ring-[#0052cc]"
                            />
                            <span className="text-sm font-medium text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-slate-100 transition-colors">Confluence Doc</span>
                          </label>
                          {formData.hasConfluenceDoc && (
                            <div className="mt-2.5">
                              <input
                                type="url"
                                name="confluenceDocContent"
                                value={formData.confluenceDocContent}
                                onChange={handleInputChange}
                                className={inputCls}
                                placeholder="Enter Confluence document link... (Please make sure that the document has a page_id)"
                              />
                            </div>
                          )}
                        </div>

                        <div className="border-t border-slate-100 dark:border-blue-900/20" />

                        {/* Slack Thread */}
                        <div>
                          <label className="flex items-center gap-2.5 cursor-pointer group">
                            <input
                              type="checkbox"
                              name="hasSlackThread"
                              checked={formData.hasSlackThread}
                              onChange={handleCheckboxChange}
                              className="h-4 w-4 rounded text-[#0052cc] border-slate-300 dark:border-gray-600 focus:ring-[#0052cc]"
                            />
                            <span className="text-sm font-medium text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-slate-100 transition-colors">Slack Thread</span>
                          </label>
                          {formData.hasSlackThread && (
                            <div className="mt-2.5">
                              <input
                                type="url"
                                name="slackThreadContent"
                                value={formData.slackThreadContent}
                                onChange={handleInputChange}
                                className={inputCls}
                                placeholder="Enter Slack thread link..."
                              />
                            </div>
                          )}
                        </div>

                        <div className="border-t border-slate-100 dark:border-blue-900/20" />

                        {/* Meeting Transcript */}
                        <div>
                          <label className="flex items-center gap-2.5 cursor-pointer group">
                            <input
                              type="checkbox"
                              name="hasMeetingTranscript"
                              checked={formData.hasMeetingTranscript}
                              onChange={handleCheckboxChange}
                              className="h-4 w-4 rounded text-[#0052cc] border-slate-300 dark:border-gray-600 focus:ring-[#0052cc]"
                            />
                            <span className="text-sm font-medium text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-slate-100 transition-colors">Meeting Transcript</span>
                          </label>
                          {formData.hasMeetingTranscript && (
                            <div className="mt-2.5">
                              <textarea
                                name="meetingTranscriptContent"
                                value={formData.meetingTranscriptContent}
                                onChange={handleInputChange}
                                rows={4}
                                className={`${inputCls} resize-none`}
                                placeholder="Paste meeting transcript content here..."
                              />
                            </div>
                          )}
                        </div>

                      </div>
                    </div>

                  </div>
                </div>

                {/* Connection Validation Error — full width */}
                {error && error.includes('Connection validation failed') && (
                  <div className="mt-6 px-4 py-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
                    <div className="flex items-start gap-2">
                      <svg className="h-4 w-4 text-red-500 dark:text-red-400 flex-shrink-0 mt-0.5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                      </svg>
                      <div>
                        <h3 className="text-sm font-semibold text-red-800 dark:text-red-300">Connection Validation Failed</h3>
                        <div className="mt-1 text-sm text-red-700 dark:text-red-400 whitespace-pre-line">
                          {error.replace('Connection validation failed:', '')}
                        </div>
                        <button
                          type="button"
                          onClick={() => setError(null)}
                          className="mt-2 text-xs font-medium text-red-700 dark:text-red-400 underline hover:no-underline"
                        >
                          Dismiss
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Next Button — full width row */}
                <div className="flex justify-end mt-6">
                  <button
                    type="submit"
                    disabled={isLoading}
                    className="px-6 py-2.5 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] focus:outline-none focus:ring-2 focus:ring-[#0052cc] focus:ring-offset-2 dark:focus:ring-offset-transparent transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-sm flex items-center gap-2"
                  >
                    {isLoading ? (
                      <>
                        <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        Validating...
                      </>
                    ) : (
                      <>
                        Next
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                        </svg>
                      </>
                    )}
                  </button>
                </div>

              </form>
            </>
          ) : (
            <>
              {/* Step indicator */}
              <div className="flex items-center gap-3 mb-2">
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500 text-white text-xs font-bold">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                  </svg>
                </span>
                <span className="text-sm text-slate-400 dark:text-slate-500">Project Information</span>
                <span className="text-slate-300 dark:text-gray-600 mx-1">›</span>
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-[#0052cc] text-white text-xs font-bold">2</span>
                <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">Additional Details</span>
              </div>

              <form onSubmit={handleSubmit} className="space-y-6">

                {/* Architecture Diagrams Card — full width spanning both columns */}
                <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
                  <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
                    <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Architecture Diagrams <span className="normal-case font-normal text-slate-400 dark:text-slate-500 text-xs ml-1">Optional</span></h2>
                  </div>
                  <div className="px-6 py-5">
                    <DragDropUpload
                      onFilesSelected={(files) => {
                        setFormData({
                          ...formData,
                          architectureDiagrams: files
                        });
                      }}
                      accept="image/*,.pdf"
                      multiple={true}
                    />
                  </div>
                </div>

                {/* Two-column grid: Application Details + Step 1 Summary */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">

                  {/* Left: Application Details */}
                  <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden h-full">
                    <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
                      <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Application Details</h2>
                    </div>
                    <div className="px-6 py-5 space-y-5">

                      <div>
                        <label htmlFor="department" className={labelCls}>
                          Team <span className="text-red-500">*</span>
                        </label>
                        {departmentOptions.length > 0 ? (
                          <select
                            id="department"
                            name="department"
                            value={formData.department}
                            onChange={handleInputChange}
                            className={selectCls}
                            required
                          >
                            <option value="">Select a team</option>
                            {departmentOptions.map((option) => (
                              <option key={option} value={option}>{option}</option>
                            ))}
                          </select>
                        ) : (
                          <input
                            id="department"
                            name="department"
                            type="text"
                            value={formData.department}
                            onChange={handleInputChange}
                            placeholder="Enter team name"
                            className={inputCls}
                            required
                          />
                        )}
                      </div>

                      <div>
                        <label htmlFor="applicationType" className={labelCls}>
                          Application Type <span className="text-red-500">*</span>
                        </label>
                        <select
                          id="applicationType"
                          name="applicationType"
                          value={formData.applicationType}
                          onChange={handleInputChange}
                          className={selectCls}
                          required
                        >
                          <option value="web">Web</option>
                          <option value="mobile">Mobile</option>
                          <option value="desktop">Desktop</option>
                          <option value="cloud">Cloud</option>
                          <option value="cli">CLI</option>
                        </select>
                      </div>

                      <div>
                        <label htmlFor="dataSensitivityLevel" className={labelCls}>
                          Data Sensitivity Level <span className="text-red-500">*</span>
                        </label>
                        <select
                          id="dataSensitivityLevel"
                          name="dataSensitivityLevel"
                          value={formData.dataSensitivityLevel}
                          onChange={handleInputChange}
                          className={selectCls}
                          required
                        >
                          {DATA_SENSITIVITY_OPTIONS.map((option) => (
                            <option key={option} value={option}>{option}</option>
                          ))}
                        </select>
                      </div>

                      <div>
                        <label htmlFor="authenticationMethod" className={labelCls}>
                          Authentication Method <span className="text-red-500">*</span>
                        </label>
                        <select
                          id="authenticationMethod"
                          name="authenticationMethod"
                          value={formData.authenticationMethod}
                          onChange={handleInputChange}
                          className={selectCls}
                          required
                        >
                          {AUTHENTICATION_OPTIONS.map((option) => (
                            <option key={option} value={option}>{option}</option>
                          ))}
                        </select>
                      </div>

                      <div className="pt-1">
                        <label className="flex items-center gap-2.5 cursor-pointer group">
                          <input
                            type="checkbox"
                            name="isInternetFacing"
                            checked={formData.isInternetFacing}
                            onChange={handleCheckboxChange}
                            className="h-4 w-4 rounded text-[#0052cc] border-slate-300 dark:border-gray-600 focus:ring-[#0052cc]"
                          />
                          <span className="text-sm font-medium text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-slate-100 transition-colors">
                            Is app internet facing?
                          </span>
                        </label>
                      </div>

                    </div>
                  </div>

                  {/* Right: Step 1 Summary (read-only) */}
                  <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden h-full">
                    <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800 flex items-center justify-between">
                      <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Assessment Summary</h2>
                      <button
                        type="button"
                        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setCurrentStep(1); window.scrollTo(0, 0); }}
                        className="text-xs text-[#0052cc] dark:text-blue-400 hover:underline font-medium"
                      >
                        Edit
                      </button>
                    </div>
                    <div className="px-6 py-5 space-y-5">

                      {/* Project name */}
                      <div>
                        <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Project Name</p>
                        <p className="text-sm font-semibold text-slate-800 dark:text-slate-200 truncate">
                          {formData.projectName || <span className="text-slate-400 dark:text-slate-500 font-normal italic">Not provided</span>}
                        </p>
                      </div>

                      {/* Description */}
                      <div>
                        <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Description</p>
                        <p className="text-sm text-slate-600 dark:text-slate-400 line-clamp-3 leading-relaxed">
                          {formData.description || <span className="italic">Not provided</span>}
                        </p>
                      </div>

                      {/* Methodology */}
                      <div>
                        <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1.5">Methodology</p>
                        <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold ${
                          formData.selectedMethodology === 'STRIDE'
                            ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300'
                            : formData.selectedMethodology === 'PASTA'
                            ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300'
                            : 'bg-slate-100 text-slate-600 dark:bg-gray-700 dark:text-slate-400'
                        }`}>
                          {formData.selectedMethodology}
                        </span>
                      </div>

                      {/* PRD files */}
                      <div>
                        <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1.5">PRD Documents</p>
                        {selectedPdfFiles && selectedPdfFiles.length > 0 ? (
                          <div className="space-y-1.5">
                            {Array.from(selectedPdfFiles).map((file, idx) => (
                              <div key={idx} className="flex items-center gap-2">
                                <svg className="w-3.5 h-3.5 text-red-400 flex-shrink-0" fill="currentColor" viewBox="0 0 24 24">
                                  <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6zm4 18H6V4h7v5h5v11z"/>
                                </svg>
                                <span className="text-xs text-slate-600 dark:text-slate-400 truncate">{file.name}</span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-xs text-slate-400 dark:text-slate-500 italic">No files uploaded</p>
                        )}
                      </div>

                      {/* Additional sources */}
                      <div>
                        <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1.5">Additional Sources</p>
                        {!formData.hasConfluenceDoc && !formData.hasSlackThread && !formData.hasMeetingTranscript ? (
                          <p className="text-xs text-slate-400 dark:text-slate-500 italic">None selected</p>
                        ) : (
                          <div className="flex flex-wrap gap-1.5">
                            {formData.hasConfluenceDoc && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-teal-50 text-teal-700 dark:bg-teal-900/30 dark:text-teal-400 border border-teal-100 dark:border-teal-800">
                                Confluence
                              </span>
                            )}
                            {formData.hasSlackThread && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400 border border-amber-100 dark:border-amber-800">
                                Slack
                              </span>
                            )}
                            {formData.hasMeetingTranscript && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-violet-50 text-violet-700 dark:bg-violet-900/30 dark:text-violet-400 border border-violet-100 dark:border-violet-800">
                                Transcript
                              </span>
                            )}
                          </div>
                        )}
                      </div>

                    </div>
                  </div>

                </div>

                {/* Navigation Buttons — full width */}
                <div className="flex items-center justify-between pt-1">
                  <button
                    type="button"
                    onClick={(e) => { e.preventDefault(); e.stopPropagation(); setCurrentStep(1); window.scrollTo(0, 0); }}
                    className="px-5 py-2.5 bg-white dark:bg-gray-800 text-[#0052cc] dark:text-blue-400 text-sm font-semibold rounded-lg border border-[#0052cc] dark:border-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 focus:outline-none focus:ring-2 focus:ring-[#0052cc] focus:ring-offset-2 dark:focus:ring-offset-transparent transition-all flex items-center gap-2"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 17l-5-5m0 0l5-5m-5 5h12" />
                    </svg>
                    Previous
                  </button>

                  <button
                    type="submit"
                    disabled={isLoading}
                    className="px-6 py-2.5 bg-[#0052cc] text-white text-sm font-semibold rounded-lg hover:bg-[#0047b3] focus:outline-none focus:ring-2 focus:ring-[#0052cc] focus:ring-offset-2 dark:focus:ring-offset-transparent transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-sm flex items-center gap-2"
                  >
                    {isLoading ? (
                      <>
                        <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        Generating Threat Model...
                      </>
                    ) : (
                      <>
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        Generate Threat Model
                      </>
                    )}
                  </button>
                </div>

              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default Home;
