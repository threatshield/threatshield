import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import DragDropUpload from '../components/common/DragDropUpload';
import LoadingScreen from '../components/common/LoadingScreen';
import { useAssessment } from '../context/AssessmentContext';
import { apiService } from '../services/api';
import { LoaderState, stageMessages } from '../types/loader';
import axios from 'axios';

interface FormData {
  projectName: string;
  description: string;
  documentSource: 'pdf';
  confluenceUrl: string;
  architectureDiagrams: FileList | null;
  applicationType: string;
  isInternetFacing: boolean;
  dataSensitivityLevel: 'Highest' | 'High' | 'Medium' | 'Low';
  authenticationMethod: 'BEARER TOKEN' | 'SSO' | 'MFA' | 'OAUTH' | 'BASIC' | 'JWT';
  selectedMethodology: 'STRIDE';
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
  
  const [formData, setFormData] = useState<FormData>({
    projectName: '',
    description: '',
    documentSource: 'pdf',
    confluenceUrl: '',
    architectureDiagrams: null,
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

  const [isLoading, setIsLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [pdfError, setPdfError] = useState<boolean>(false);
  const [selectedPdfFiles, setSelectedPdfFiles] = useState<FileList | null>(null);
  const pdfFileRef = useRef<HTMLInputElement>(null);
  
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
    
    try {
      console.log("Starting form submission process");
      const submitData = new FormData();
      
      // Map form fields to API parameters
      submitData.append('name', formData.projectName);
      submitData.append('description', formData.description);
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
        
        // Step 2: Parsing PRD
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
        
        // Step 3: Architecture image parsing (if provided)
        if (formData.architectureDiagrams && formData.architectureDiagrams.length > 0) {
          addLog('Parsing the Architecture Image...', 0, 'task');
          await new Promise(resolve => setTimeout(resolve, 1000));
          
          addLog('Identifying components', 1);
          await new Promise(resolve => setTimeout(resolve, 1000));
          
          addLog('Analyzing relationships', 1);
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
        
        // Step 4-6: Handle additional documents (if provided)
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
        
        // Step 7: RAG creation
        addLog('Creating RAG...', 0, 'task');
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Generating embeddings', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Building knowledge base', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        if (!currentAssessmentId) {
          throw new Error("Assessment ID is missing");
        }
        const threatModelResult = await apiService.generateThreatModel(currentAssessmentId);
        console.log("Threat model generation successful:", threatModelResult);
        setContextThreatModelData(threatModelResult);

        // 3. Generate Attack Tree
        console.log("Step 3: Generating attack tree");
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'attack-tree',
          progress: 60,
          message: 'Generating attack tree...'
        }));
        
        // Step 9: Threat model generation - synchronized with API call
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'threat-model',
          message: stageMessages['threat-model']
        }));
        
        addLog('Generating threat model...', 0, 'task');
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Identifying potential threats', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Analyzing attack vectors', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Evaluating security controls', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const attackTreeResult = await apiService.generateAttackTree(currentAssessmentId);
        console.log("Attack tree generation successful:", attackTreeResult);

        // 4. Generate DREAD Assessment
        console.log("Step 4: Generating DREAD assessment");
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'dread',
          progress: 80,
          message: 'Performing DREAD assessment...'
        }));
        
        // Step 10: Attack tree generation - synchronized with API call
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'attack-tree',
          message: stageMessages['attack-tree']
        }));
        
        addLog('Generating Attack Tree...', 0, 'task');
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Mapping attack paths', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Calculating path complexity', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const dreadResult = await apiService.generateDreadAssessment(currentAssessmentId);
        console.log("DREAD assessment generation successful:", dreadResult);
        setContextDreadData(dreadResult);

        // 5. Generate Mitigations
        console.log("Step 5: Generating mitigations");
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'mitigation',
          progress: 95,
          message: 'Generating mitigations...'
        }));
        
        // Step 11: DREAD assessment - synchronized with API call
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'dread',
          message: stageMessages['dread']
        }));
        
        addLog('Generating DREAD assessment...', 0, 'task');
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Calculating Damage potential', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Evaluating Reproducibility', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Assessing Exploitability', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Measuring Affected users', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Determining Discoverability', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Step 12: Mitigations - synchronized with API call
        setLoaderState(prevState => ({
          ...prevState,
          stage: 'mitigation',
          message: stageMessages['mitigation']
        }));
        
        addLog('Generating mitigations...', 0, 'task');
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Researching best practices', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        addLog('Prioritizing countermeasures', 1);
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const mitigationResult = await apiService.generateMitigation(currentAssessmentId);
        console.log("Mitigations generation successful:", mitigationResult);
        setContextMitigationData(mitigationResult);

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
      setError(error instanceof Error ? error.message : 'Failed to submit data. Please try again.');
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

  return (
    <div className="min-h-screen bg-gray-50 relative">
      {showLoader && <LoadingScreen state={loaderState} />}
      {/* Header */}
      <div className="py-4">
        <div className="max-w-5xl mx-auto px-4 relative z-10">
          <div className="text-center">
            <h1 className="text-4xl font-bold mb-2">
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-[#0052cc]">
                Threat Shield
              </span>
            </h1>
            <p className="text-xl text-[#0052cc]">Advanced Threat Modeling Platform</p>
          </div>
        </div>
      </div>
      
      <div className="max-w-5xl mx-auto px-4 relative z-10">
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md text-red-700">
            <div className="flex items-center">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-red-500" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              <span className="font-medium">{error}</span>
            </div>
            <button 
              className="mt-2 text-sm text-red-600 hover:text-red-800"
              onClick={() => setError(null)}
            >
              Dismiss
            </button>
          </div>
        )}
        
        <div className="card bg-white shadow-lg border border-blue-100 p-8">
          {currentStep === 1 ? (
            <>
              <div className="flex items-center mb-8 pb-4 border-b border-blue-100">
                <div className="bg-blue-100 p-2 rounded-full mr-3">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <h2 className="text-2xl font-semibold text-[#172b4d]">Project Information</h2>
              </div>
              
              <form onSubmit={handleNextStep}>
                {/* Project Details */}
                <div className="mb-8 space-y-2">
                  <label htmlFor="projectName" className="block text-sm font-medium text-gray-700 mb-1">
                    Project Name *
                  </label>
                  <input
                    type="text"
                    id="projectName"
                    name="projectName"
                    value={formData.projectName}
                    onChange={handleInputChange}
                    className="input"
                    required
                  />
                </div>

                <div className="mb-6">
                  <label htmlFor="description" className="block text-sm font-medium text-gray-700 mb-1">
                    Description *
                  </label>
                  <textarea
                    id="description"
                    name="description"
                    value={formData.description}
                    onChange={handleInputChange}
                    rows={4}
                    className="input"
                    required
                  />
                </div>

                {/* Threat Modeling Methodologies */}
                <div className="mb-6">
                  <div className="flex items-center mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-[#0052cc] mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <h3 className="text-lg font-medium text-[#172b4d]">Threat Modeling Methodologies</h3>
                  </div>
                  <div className="mb-8 p-8 border border-blue-100 rounded-lg bg-blue-50/50 shadow-sm">
                    <div className="space-y-4">
                      {/* STRIDE */}
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center">
                            <h3 className="text-base font-medium text-gray-700">STRIDE</h3>
                            <div className="relative ml-2 group">
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-gray-500 cursor-help" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                              <div className="absolute z-10 invisible group-hover:visible bg-gray-800 text-white text-xs rounded p-2 w-64 bottom-full left-1/2 transform -translate-x-1/2 -translate-y-2">
                                Use STRIDE when you need a systematic approach to identify threats across six categories. Best for most applications, especially those with clear security boundaries.
                                <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 translate-y-1 border-8 border-transparent border-t-gray-800"></div>
                              </div>
                            </div>
                          </div>
                          <p className="text-sm text-gray-600">Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege</p>
                        </div>
                        <div className="flex items-center">
                          <input 
                            type="radio" 
                            id="strideDefault" 
                            name="selectedMethodology" 
                            checked={formData.selectedMethodology === 'STRIDE'}
                            className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300"
                          />
                        </div>
                      </div>
                      
                      {/* PASTA */}
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center">
                            <h3 className="text-base font-medium text-gray-700">PASTA</h3>
                            <div className="relative ml-2 group">
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-gray-500 cursor-help" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                              <div className="absolute z-10 invisible group-hover:visible bg-gray-800 text-white text-xs rounded p-2 w-64 bottom-full left-1/2 transform -translate-x-1/2 -translate-y-2">
                                Use PASTA for risk-centric threat modeling with business impact analysis. Ideal for complex applications where understanding business risk is crucial.
                                <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 translate-y-1 border-8 border-transparent border-t-gray-800"></div>
                              </div>
                            </div>
                          </div>
                          <p className="text-sm text-gray-600">Process for Attack Simulation and Threat Analysis</p>
                        </div>
                        <div className="flex items-center">
                          <p className="text-sm text-gray-600">Coming Soon</p>
                        </div>
                      </div>
                      
                      {/* OCTAVE */}
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center">
                            <h3 className="text-base font-medium text-gray-700">OCTAVE</h3>
                            <div className="relative ml-2 group">
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-gray-500 cursor-help" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                              <div className="absolute z-10 invisible group-hover:visible bg-gray-800 text-white text-xs rounded p-2 w-64 bottom-full left-1/2 transform -translate-x-1/2 -translate-y-2">
                                Use OCTAVE for organizational risk assessment focusing on strategic and practice-related issues. Best for enterprise-wide security assessments.
                                <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 translate-y-1 border-8 border-transparent border-t-gray-800"></div>
                              </div>
                            </div>
                          </div>
                          <p className="text-sm text-gray-600">Operationally Critical Threat, Asset, and Vulnerability Evaluation</p>
                        </div>
                        <div className="flex items-center">
                          <p className="text-sm text-gray-600">Coming Soon</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Document Source - PDF only */}
                <div className="mb-8">
                  <label className="block text-sm font-medium text-gray-700 mb-3">
                    Document Source *
                  </label>
                  {/* <div className="flex space-x-6">
                    <div className="inline-flex items-center bg-white border border-blue-100 rounded-md px-4 py-2">
                      <span className="font-medium">PDF Upload</span>
                    </div>
                  </div> */}
                </div>

                {/* PDF Upload */}
                <div className="mb-8 p-8 border border-blue-100 rounded-lg bg-blue-50/50 shadow-sm">
                    <div className="flex items-center mb-4">
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-[#0052cc] mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                      </svg>
                      <h3 className="text-lg font-medium text-[#172b4d]">PRD Document (Required)</h3>
                    </div>
                    
                    <DragDropUpload
                      onFilesSelected={(files) => {
                        // Merge new files with existing files
                        if (selectedPdfFiles) {
                          // Create a new array with all files
                          const existingFiles = Array.from(selectedPdfFiles);
                          const newFiles = Array.from(files);
                          const mergedFiles = [...existingFiles, ...newFiles];
                          
                          // Convert merged array back to FileList-like object
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
                    
                  </div>

                {/* PDF Upload Error - only shown after attempting to proceed without a file */}
                {pdfError && (
                  <div className="mb-4 p-2 bg-red-50 border border-red-200 rounded-md text-red-700 text-center">
                    <span className="text-sm font-medium">Please upload a PRD document before proceeding</span>
                  </div>
                )}
                
                {/* Additional Document Sources */}
                <div className="mb-8 p-8 border border-blue-100 rounded-lg bg-blue-50/50 shadow-sm">
                  <div className="flex items-center mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-[#0052cc] mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <h3 className="text-lg font-medium text-[#172b4d]">Additional Document Sources (Optional)</h3>
                  </div>
                  
                  {/* Confluence Doc */}
                  <div className="mb-4">
                    <label className="flex items-center bg-white border border-blue-100 rounded-md px-4 py-2 cursor-pointer hover:bg-blue-50 transition-colors inline-block mb-2">
                      <input
                        type="checkbox"
                        name="hasConfluenceDoc"
                        checked={formData.hasConfluenceDoc}
                        onChange={handleCheckboxChange}
                        className="mr-2 h-4 w-4 text-[#0052cc] focus:ring-[#0052cc] rounded"
                      />
                      <span className="text-sm font-medium text-gray-700">Confluence Doc</span>
                    </label>
                    
                    {formData.hasConfluenceDoc && (
                      <input
                        type="url"
                        name="confluenceDocContent"
                        value={formData.confluenceDocContent}
                        onChange={handleInputChange}
                        className="input w-full"
                        placeholder="Enter Confluence document link... (Please make sure that the document has a page_id)"
                      />
                    )}
                  </div>
                  
                  {/* Slack Thread */}
                  <div className="mb-4">
                    <label className="flex items-center bg-white border border-blue-100 rounded-md px-4 py-2 cursor-pointer hover:bg-blue-50 transition-colors inline-block mb-2">
                      <input
                        type="checkbox"
                        name="hasSlackThread"
                        checked={formData.hasSlackThread}
                        onChange={handleCheckboxChange}
                        className="mr-2 h-4 w-4 text-[#0052cc] focus:ring-[#0052cc] rounded"
                      />
                      <span className="text-sm font-medium text-gray-700">Slack Thread</span>
                    </label>
                    
                    {formData.hasSlackThread && (
                      <input
                        type="url"
                        name="slackThreadContent"
                        value={formData.slackThreadContent}
                        onChange={handleInputChange}
                        className="input w-full"
                        placeholder="Enter Slack thread link..."
                      />
                    )}
                  </div>
                  
                  {/* Meeting Transcript */}
                  <div>
                    <label className="flex items-center bg-white border border-blue-100 rounded-md px-4 py-2 cursor-pointer hover:bg-blue-50 transition-colors inline-block mb-2">
                      <input
                        type="checkbox"
                        name="hasMeetingTranscript"
                        checked={formData.hasMeetingTranscript}
                        onChange={handleCheckboxChange}
                        className="mr-2 h-4 w-4 text-[#0052cc] focus:ring-[#0052cc] rounded"
                      />
                      <span className="text-sm font-medium text-gray-700">Meeting Transcript</span>
                    </label>
                    
                    {formData.hasMeetingTranscript && (
                      <textarea
                        name="meetingTranscriptContent"
                        value={formData.meetingTranscriptContent}
                        onChange={handleInputChange}
                        rows={4}
                        className="input w-full"
                        placeholder="Paste meeting transcript content here..."
                      />
                    )}
                  </div>
                </div>
                
                {/* Connection Validation Error - displayed above Next button */}
                {error && error.includes('Connection validation failed') && (
                  <div className="mt-4 p-4 bg-red-50 border-l-4 border-red-500 rounded-md">
                    <div className="flex">
                      <div className="flex-shrink-0">
                        <svg className="h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                        </svg>
                      </div>
                      <div className="ml-3">
                        <h3 className="text-sm font-medium text-red-800">Connection Validation Failed</h3>
                        <div className="mt-2 text-sm text-red-700 whitespace-pre-line">
                          {error.replace('Connection validation failed:', '')}
                        </div>
                        <div className="mt-4">
                          <div className="-mx-2 -my-1.5 flex">
                            <button
                              type="button"
                              onClick={() => setError(null)}
                              className="px-2 py-1.5 rounded-md text-sm font-medium text-red-800 hover:bg-red-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                            >
                              Dismiss
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Next Button */}
                <div className="mt-8 flex justify-center">
                  <button
                    type="submit"
                    className="btn bg-[#0052cc] hover:bg-[#0747a6] text-white w-full sm:w-auto min-w-[200px] flex items-center justify-center transform transition-all duration-300 hover:scale-105 border-0 shadow-md hover:shadow-lg"
                    disabled={isLoading}
                  >
                    {isLoading ? (
                      <div className="flex items-center justify-center">
                        <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        <span>Validating...</span>
                      </div>
                    ) : (
                      <div className="flex items-center justify-center">
                        <span>Next</span>
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 ml-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                        </svg>
                      </div>
                    )}
                  </button>
                </div>
              </form>
            </>
          ) : (
            <>
              <div className="flex items-center mb-6 pb-4 border-b border-blue-100">
                <div className="bg-blue-100 p-2 rounded-full mr-3">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
                  </svg>
                </div>
                <h2 className="text-2xl font-semibold text-[#172b4d]">Additional Details</h2>
              </div>
              
              <form onSubmit={handleSubmit}>
                {/* Architecture Diagrams */}
                <div className="mb-6">
                  <label htmlFor="architectureDiagrams" className="block text-sm font-medium text-gray-700 mb-2">
                    Architecture Diagrams
                  </label>
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

                {/* Application Details */}
                <div className="mb-6 p-6 border border-blue-100 rounded-lg bg-blue-50/50 shadow-sm">
                  <div className="flex items-center mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-[#0052cc] mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
                    </svg>
                    <h3 className="text-lg font-medium text-[#172b4d]">Application Details</h3>
                  </div>
                  

                  <div className="mb-4">
                    <label htmlFor="applicationType" className="block text-sm font-medium text-gray-700 mb-1">
                      Application Type *
                    </label>
                    <select
                      id="applicationType"
                      name="applicationType"
                      value={formData.applicationType}
                      onChange={handleInputChange}
                      className="select"
                      required
                    >
                      <option value="web">Web</option>
                      <option value="mobile">Mobile</option>
                      <option value="desktop">Desktop</option>
                      <option value="cloud">Cloud</option>
                      <option value="cli">CLI</option>
                    </select>
                  </div>

                  <div className="mb-4">
                    <label className="flex items-center bg-white border border-blue-100 rounded-md px-4 py-2 cursor-pointer hover:bg-blue-50 transition-colors inline-block">
                      <input
                        type="checkbox"
                        name="isInternetFacing"
                        checked={formData.isInternetFacing}
                        onChange={handleCheckboxChange}
                        className="mr-2 h-4 w-4 text-[#0052cc] focus:ring-[#0052cc] rounded"
                      />
                      <span className="text-sm font-medium text-gray-700">Is app internet facing?</span>
                    </label>
                  </div>

                  <div className="mb-4">
                    <label htmlFor="dataSensitivityLevel" className="block text-sm font-medium text-gray-700 mb-1">
                      Data Sensitivity Level *
                    </label>
                    <select
                      id="dataSensitivityLevel"
                      name="dataSensitivityLevel"
                      value={formData.dataSensitivityLevel}
                      onChange={handleInputChange}
                      className="select"
                      required
                    >
                      {DATA_SENSITIVITY_OPTIONS.map((option) => (
                        <option key={option} value={option}>{option}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label htmlFor="authenticationMethod" className="block text-sm font-medium text-gray-700 mb-1">
                      Authentication Method *
                    </label>
                    <select
                      id="authenticationMethod"
                      name="authenticationMethod"
                      value={formData.authenticationMethod}
                      onChange={handleInputChange}
                      className="select"
                      required
                    >
                      {AUTHENTICATION_OPTIONS.map((option) => (
                        <option key={option} value={option}>{option}</option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* Navigation Buttons */}
                <div className="mt-10 flex justify-between">
                  <button
                    type="button"
                    onClick={handlePrevStep}
                    className="btn bg-white hover:bg-gray-50 text-[#0052cc] border border-[#0052cc] w-full sm:w-auto flex items-center justify-center transform transition-all duration-300 hover:scale-105"
                  >
                    <div className="flex items-center justify-center">
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 17l-5-5m0 0l5-5m-5 5h12" />
                      </svg>
                      <span>Previous</span>
                    </div>
                  </button>
                  
                  <button
                    type="submit"
                    className="btn bg-[#0052cc] hover:bg-[#0747a6] text-white w-full sm:w-auto flex items-center justify-center transform transition-all duration-300 hover:scale-105 border-0"
                    disabled={isLoading}
                  >
                    {isLoading ? (
                      <div className="flex items-center justify-center">
                        <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        <span>Generating Threat Model...</span>
                      </div>
                    ) : (
                      <div className="flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        <span>Generate Threat Model</span>
                      </div>
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