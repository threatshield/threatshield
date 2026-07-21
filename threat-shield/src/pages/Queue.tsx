import React, { useState, useEffect } from 'react';
import { apiService, API_BASE_URL } from '../services/api';
import { useNavigate } from 'react-router-dom';

interface QueueItem {
  id: string;
  secreview_id: string;
  assessment_id: string;
  initiated_by: string;
  prd_url: string;
  service_name: string;
  slack_thread: string;
  department?: string;
  created_at: string;
  updated_at?: string;
  status: 'pending' | 'processing' | 'queued' | 'completed' | 'failed' | 'cancelled';
  current_step?: string;
  threat_model_status?: string;
  error_message?: string;
  additional_data?: Record<string, any>;
}

interface StorageItem {
  assessment_id: string;
  projectName: string;
  description: string;
  source: string;
  status: string;
  timestamp: string;
  [key: string]: any;
}

const STEP_LABELS: Record<string, string> = {
  rag: 'Processing documents (RAG)...',
  threat_model: 'Generating threat model...',
  parallel_analysis: 'Generating Attack Tree, DREAD, Mitigations & Test Cases...',
  attack_tree: 'Generating attack tree...',
  dread: 'Calculating DREAD scores...',
  mitigation: 'Generating mitigations...',
  test_cases: 'Generating test cases...',
  completed: 'Completed',
};

const STEP_PERCENT: Record<string, number> = {
  rag: 10,
  threat_model: 30,
  parallel_analysis: 65,
  attack_tree: 50,
  dread: 65,
  mitigation: 80,
  test_cases: 95,
  completed: 100,
};

const Queue: React.FC = () => {
  const [queueItems, setQueueItems] = useState<QueueItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedItem, setSelectedItem] = useState<QueueItem | null>(null);
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [retryingDocType, setRetryingDocType] = useState<string | null>(null);
  const [editingDocUrl, setEditingDocUrl] = useState<{ docType: string; url: string } | null>(null);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [showNoDocModal, setShowNoDocModal] = useState(false);
  const [pendingSecreviewId, setPendingSecreviewId] = useState<string | null>(null);

  // Filter state
  const [filterSecreviewId, setFilterSecreviewId] = useState('');
  const [filterServiceName, setFilterServiceName] = useState('');
  const [filterDepartment, setFilterDepartment] = useState('');
  const [filterStatuses, setFilterStatuses] = useState<string[]>([]);
  const [filterInitiatedBy, setFilterInitiatedBy] = useState<string[]>([]);
  const [filterDateFrom, setFilterDateFrom] = useState('');
  const [filterDateTo, setFilterDateTo] = useState('');
  const [showInitiatedByDropdown, setShowInitiatedByDropdown] = useState(false);

  const navigate = useNavigate();

  useEffect(() => {
    loadQueue();
  }, []);

  useEffect(() => {
    // Only refresh if there are items being processed or queued
    const hasProcessing = queueItems.some(item => item.status === 'processing' || item.status === 'queued');
    if (!hasProcessing) return;

    const interval = setInterval(loadQueue, 5000);
    return () => clearInterval(interval);
  }, [queueItems]);

  useEffect(() => {
    // Nudge the backend every 10s when there are queued-but-not-yet-running items
    const hasQueued = queueItems.some(item => item.status === 'queued');
    if (!hasQueued) return;
    const interval = setInterval(() => {
      fetch(`${API_BASE_URL}/nudge-queued`, { method: 'POST' }).catch(() => {});
    }, 10000);
    return () => clearInterval(interval);
  }, [queueItems]);

  // Clear inline URL edit state when the Details modal is closed
  useEffect(() => {
    if (!selectedItem) setEditingDocUrl(null);
  }, [selectedItem]);

  // Unique initiated-by values for the multi-select dropdown
  const allInitiatedBy = Array.from(new Set(queueItems.map(i => i.initiated_by).filter(Boolean)));
  // Unique TEAM values for the TEAM dropdown
  const allDepartments = Array.from(new Set(queueItems.map(i => i.department).filter(Boolean))) as string[];
  const allStatuses: Array<'pending' | 'processing' | 'queued' | 'completed' | 'failed' | 'cancelled'> = ['pending', 'queued', 'processing', 'completed', 'failed', 'cancelled'];

  const filteredItems = queueItems.filter(item => {
    if (filterSecreviewId && !item.secreview_id.toLowerCase().includes(filterSecreviewId.toLowerCase())) return false;
    if (filterServiceName && !item.service_name.toLowerCase().includes(filterServiceName.toLowerCase())) return false;
    if (filterDepartment && (item.department || '') !== filterDepartment) return false;
    if (filterStatuses.length > 0 && !filterStatuses.includes(item.status)) return false;
    if (filterInitiatedBy.length > 0 && !filterInitiatedBy.includes(item.initiated_by)) return false;
    if (filterDateFrom) {
      const from = new Date(filterDateFrom);
      if (new Date(item.created_at) < from) return false;
    }
    if (filterDateTo) {
      const to = new Date(filterDateTo);
      to.setHours(23, 59, 59, 999);
      if (new Date(item.created_at) > to) return false;
    }
    return true;
  }).sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  const hasActiveFilters = filterSecreviewId || filterServiceName || filterDepartment ||
    filterStatuses.length > 0 || filterInitiatedBy.length > 0 || filterDateFrom || filterDateTo;

  const clearFilters = () => {
    setFilterSecreviewId('');
    setFilterServiceName('');
    setFilterDepartment('');
    setFilterStatuses([]);
    setFilterInitiatedBy([]);
    setFilterDateFrom('');
    setFilterDateTo('');
  };

  const toggleStatus = (s: string) =>
    setFilterStatuses(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]);

  const toggleInitiatedBy = (v: string) =>
    setFilterInitiatedBy(prev => prev.includes(v) ? prev.filter(x => x !== v) : [...prev, v]);

  const loadQueue = async () => {
    try {
      // Try loading from storage first
      const storageItems = await loadFromStorage();
      if (storageItems.length > 0) {
        setQueueItems(storageItems);
        setLoading(false);
        return;
      }

      // Fallback to API
      const response = await fetch(`${API_BASE_URL}/queue`);
      if (!response.ok) throw new Error('Failed to load queue');
      const data = await response.json();
      setQueueItems(data.data || []);
      setLoading(false);
    } catch (error) {
      console.error('Error loading queue:', error);
      setLoading(false);
    }
  };

  const loadFromStorage = async (): Promise<QueueItem[]> => {
    try {
      const response = await fetch(`${API_BASE_URL}/storage-queue-items`);
      if (!response.ok) throw new Error('Failed to load from storage');
      const data = await response.json();
      return data.items || [];
    } catch (error) {
      console.error('Error loading from storage:', error);
      return [];
    }
  };

  const triggerThreatModel = async (secreviewId: string) => {
    try {
      setProcessingId(secreviewId);

      // Get the queue item
      const queueItem = queueItems.find(item => item.secreview_id === secreviewId);
      if (!queueItem) {
        throw new Error('Queue item not found');
      }

      const assessmentId = queueItem.assessment_id;

      // Fetch stored details and additional info for this assessment
      const storageUrl = `${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=details`;
      const detailsResponse = await fetch(storageUrl);

      if (!detailsResponse.ok) {
        throw new Error('Failed to fetch assessment details');
      }

      const detailsData = await detailsResponse.json();
      const details = detailsData.result || {};

      // Fetch additional info
      const additionalUrl = `${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=additionalinfo`;
      const additionalResponse = await fetch(additionalUrl);
      const additionalData = additionalResponse.ok ? await additionalResponse.json() : {};
      const additionalInfo = additionalData.result || {};

      // Check if any documents were fetched successfully
      const hasConfluenceDoc = additionalInfo.confluenceDoc && !additionalInfo.confluenceDoc.error;
      const hasSlackThread = additionalInfo.slackThread && !additionalInfo.slackThread.error;
      const hasMeetingTranscript = additionalInfo.meetingTranscript && additionalInfo.meetingTranscript.content;
      const hasPrdDoc = additionalInfo.prdDoc && !additionalInfo.prdDoc.error;

      const hasAnyDocuments = hasConfluenceDoc || hasSlackThread || hasMeetingTranscript || hasPrdDoc;

      // If no documents were fetched, show UI modal for confirmation
      if (!hasAnyDocuments) {
        setProcessingId(null);
        setPendingSecreviewId(secreviewId);
        setShowNoDocModal(true);
        return;
      }

      // Proceed with threat model generation with documents
      await proceedWithThreatModel(secreviewId, details, queueItem, additionalInfo);
    } catch (error) {
      console.error('Error triggering threat model:', error);
      setStatusMessage({
        type: 'error',
        message: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
      });
    } finally {
      setProcessingId(null);
    }
  };

  const proceedWithThreatModel = async (secreviewId: string, details: any, queueItem: QueueItem, additionalInfo: any) => {
    try {
      const assessmentId = queueItem.assessment_id;

      // Create FormData to send to /api/upload
      const formData = new FormData();

      // Add assessment_id from queue (prevents creating new folder)
      formData.append('assessment_id', assessmentId);

      // Add threat modeling parameters
      formData.append('name', details.serviceName || queueItem.service_name);
      formData.append('description', `Queue-based assessment for ${queueItem.service_name}`);
      formData.append('department', details.department || queueItem.department || queueItem.additional_data?.department || 'Not specified');
      formData.append('app_type', details.applicationType || queueItem.additional_data?.app_type || 'Not specified');
      formData.append('sensitivity_level', details.dataSensitivityLevel || queueItem.additional_data?.sensitivity_level || 'Not specified');
      formData.append('internet_facing', details.isInternetFacing ? 'Yes' : 'No');
      formData.append('sensitive_data', details.dataSensitivityLevel || queueItem.additional_data?.sensitive_data || 'Not specified');
      formData.append('custom_prompt', queueItem.additional_data?.custom_prompt || '');

      // Add authentication methods
      const authRaw = queueItem.additional_data?.authentication;
      const authMethods: string[] = Array.isArray(authRaw) ? authRaw : authRaw ? [authRaw] : [];
      authMethods.forEach((auth: string) => {
        formData.append('authentication[]', auth);
      });

      // Add additional info (Confluence, Slack, meeting transcript)
      const additionalInfoJson = {
        confluenceDoc: additionalInfo.confluenceDoc || null,
        slackThread: additionalInfo.slackThread || null,
        meetingTranscript: additionalInfo.meetingTranscript || null
      };
      formData.append('additional_info', JSON.stringify(additionalInfoJson));

      // Call /api/upload with the collected data asynchronously (don't await)
      // This allows the threat model to be generated in the background
      void (async () => {
        try {
          const uploadResponse = await fetch(`${API_BASE_URL}/upload`, {
            method: 'POST',
            body: formData
          });
          if (!uploadResponse.ok) {
            const errData = await uploadResponse.json();
            throw new Error(errData.error || 'Failed to generate threat model');
          }
          await uploadResponse.json();
          // Show success message and reload queue after generation completes
          // setStatusMessage({
          //   type: 'success',
          //   message: `Threat model generation started for ${secreviewId}. Processing in background...`
          // });
          setTimeout(() => {
            loadQueue();
          }, 1000);
        } catch (error) {
          console.error('Error generating threat model:', error);
          setStatusMessage({
            type: 'error',
            message: `Error: ${error instanceof Error ? error.message : 'Failed to generate threat model'}`
          });
          loadQueue();
        }
      })();
    } catch (error) {
      console.error('Error triggering threat model:', error);
      setStatusMessage({
        type: 'error',
        message: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
      });
    } finally {
      setProcessingId(null);
    }
  };

//   const deleteQueueItem = async (secreviewId: string) => {
//     if (window.confirm(`Are you sure you want to delete queue item ${secreviewId}?`)) {
//       try {
//         const response = await fetch(`${API_BASE_URL}/queue/${secreviewId}`, {
//           method: 'DELETE'
//         });

//         if (!response.ok) throw new Error('Failed to delete queue item');

//         setStatusMessage({
//           type: 'success',
//           message: 'Queue item deleted successfully'
//         });

//         loadQueue();
//       } catch (error) {
//         console.error('Error deleting queue item:', error);
//         setStatusMessage({
//           type: 'error',
//           message: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
//         });
//       }
//     }
//   };

  const handleProceedWithoutDocs = async () => {
    if (!pendingSecreviewId) return;

    try {
      setShowNoDocModal(false);
      setProcessingId(pendingSecreviewId);

      // Get the queue item
      const queueItem = queueItems.find(item => item.secreview_id === pendingSecreviewId);
      if (!queueItem) {
        throw new Error('Queue item not found');
      }

      const assessmentId = queueItem.assessment_id;

      // Create FormData to send to /api/upload without documents
      const formData = new FormData();

      // Add assessment_id from queue (prevents creating new folder)
      formData.append('assessment_id', assessmentId);

      // Fetch stored details for this assessment
      const storageUrl = `${API_BASE_URL}/storage?assessment_id=${assessmentId}&assessment_name=details`;
      const detailsResponse = await fetch(storageUrl);

      let details: any = {};
      if (detailsResponse.ok) {
        const detailsData = await detailsResponse.json();
        details = detailsData.result || {};
      }

      // Add threat modeling parameters
      formData.append('name', details.serviceName || queueItem.service_name);
      formData.append('description', `Queue-based assessment for ${queueItem.service_name}`);
      formData.append('department', details.department || queueItem.department || queueItem.additional_data?.department || 'Not specified');
      formData.append('app_type', details.applicationType || queueItem.additional_data?.app_type || 'Not specified');
      formData.append('sensitivity_level', details.dataSensitivityLevel || queueItem.additional_data?.sensitivity_level || 'Not specified');
      formData.append('internet_facing', details.isInternetFacing ? 'Yes' : 'No');
      formData.append('sensitive_data', details.dataSensitivityLevel || queueItem.additional_data?.sensitive_data || 'Not specified');
      formData.append('custom_prompt', queueItem.additional_data?.custom_prompt || '');

      // Add authentication methods
      const authRaw2 = queueItem.additional_data?.authentication;
      const authMethods: string[] = Array.isArray(authRaw2) ? authRaw2 : authRaw2 ? [authRaw2] : [];
      authMethods.forEach((auth: string) => {
        formData.append('authentication[]', auth);
      });

      // Add empty additional info
      const additionalInfoJson = {
        confluenceDoc: null,
        slackThread: null,
        meetingTranscript: null
      };
      formData.append('additional_info', JSON.stringify(additionalInfoJson));

      // Optimistically update the item to 'processing' so the spinner and
      // polling kick in immediately without waiting for the backend round-trip
      setQueueItems(prev =>
        prev.map(item =>
          item.assessment_id === assessmentId
            ? { ...item, status: 'processing', current_step: 'rag', error_message: undefined }
            : item
        )
      );

      // Call /api/upload fire-and-forget (do not await — optimistic update already shows spinner)
      void (async () => {
        try {
          const uploadResponse = await fetch(`${API_BASE_URL}/upload`, {
            method: 'POST',
            body: formData
          });
          if (!uploadResponse.ok) {
            const errData = await uploadResponse.json();
            throw new Error(errData.error || 'Failed to generate threat model');
          }
          await uploadResponse.json();
          setTimeout(() => loadQueue(), 1000);
        } catch (error) {
          console.error('Error generating threat model:', error);
          setStatusMessage({
            type: 'error',
            message: `Error: ${error instanceof Error ? error.message : 'Failed to generate threat model'}`
          });
          loadQueue();
        }
      })();
    } catch (error) {
      console.error('Error proceeding without documents:', error);
      setStatusMessage({
        type: 'error',
        message: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
      });
    } finally {
      setProcessingId(null);
      setPendingSecreviewId(null);
    }
  };

  const cancelAssessment = async (assessmentId: string) => {
    try {
      setCancellingId(assessmentId);
      const response = await fetch(`${API_BASE_URL}/cancel-assessment/${assessmentId}`, { method: 'POST' });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to cancel');
      }
      setStatusMessage({ type: 'success', message: 'Assessment cancelled successfully.' });
      await loadQueue();
    } catch (error) {
      setStatusMessage({ type: 'error', message: `Cancel failed: ${error instanceof Error ? error.message : String(error)}` });
    } finally {
      setCancellingId(null);
    }
  };

  const retryFetchDoc = async (assessmentId: string, docType: string, newUrl?: string) => {
    setRetryingDocType(docType);
    try {
      const response = await fetch(`${API_BASE_URL}/retry-fetch-doc/${assessmentId}/${docType}`, {
        method: 'POST',
        ...(newUrl ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: newUrl }) } : {}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Retry failed');
      // Use server-authoritative URL values from response
      const updatedPrdUrl = data.prd_url !== undefined ? data.prd_url : (docType === 'prdDoc' && newUrl ? newUrl : undefined);
      const updatedSlackThread = data.slack_thread !== undefined ? data.slack_thread : (docType === 'slackThread' && newUrl ? newUrl : undefined);
      const urlUpdate: Partial<QueueItem> = {
        ...(updatedPrdUrl !== undefined ? { prd_url: updatedPrdUrl } : {}),
        ...(updatedSlackThread !== undefined ? { slack_thread: updatedSlackThread } : {}),
        ...(data.status ? { status: data.status } : {}),
      };
      const updater = (item: QueueItem) =>
        item.assessment_id === assessmentId
          ? { ...item, ...urlUpdate, additional_data: { ...item.additional_data, additionalDocuments: data.additionalDocuments } }
          : item;
      setSelectedItem(prev => prev ? updater(prev) as QueueItem : null);
      setQueueItems(prev => prev.map(updater));
      const docLabel = docType === 'prdDoc' ? 'PRD' : docType === 'slackThread' ? 'Slack Thread' : 'Document';
      const docStatus = data.additionalDocuments?.[docType];
      if (docStatus && !docStatus.error) {
        setStatusMessage({ type: 'success', message: `${docLabel} URL saved and fetched successfully.` });
      } else if (newUrl) {
        setStatusMessage({ type: 'success', message: `${docLabel} URL saved. Fetch attempt completed — check status below.` });
      }
    } catch (error) {
      setStatusMessage({ type: 'error', message: `Retry failed: ${error instanceof Error ? error.message : String(error)}` });
    } finally {
      setRetryingDocType(null);
    }
  };

  const handleCancelNoDocsModal = () => {
    setShowNoDocModal(false);
    setPendingSecreviewId(null);
  };

  const hasAnyFetchedDoc = (item: QueueItem): boolean => {
    const docs = item.additional_data?.additionalDocuments;
    if (!docs) return false;
    const ok = (doc: any) => doc && !doc.error && (doc.fetched || doc.stored || doc.content);
    return ok(docs.prdDoc) || ok(docs.confluenceDoc) || ok(docs.slackThread) || ok(docs.meetingTranscript);
  };

  const getStatusBadgeColor = (status: string) => {
    switch (status) {
      case 'pending':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300';
      case 'queued':
        return 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300';
      case 'processing':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300';
      case 'completed':
        return 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300';
      case 'failed':
        return 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300';
      case 'cancelled':
        return 'bg-gray-100 text-gray-600 dark:bg-gray-700/60 dark:text-gray-400';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700/60 dark:text-gray-300';
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      <div className="px-6 pt-8 pb-16">
        {/* Status Message with Close Button */}
        {statusMessage && (
          <div
            className={`mb-4 p-4 rounded-md flex items-center justify-between ${
              statusMessage.type === 'success'
                ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300'
                : 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300'
            }`}
          >
            <span>{statusMessage.message}</span>
            <button
              onClick={() => setStatusMessage(null)}
              className="ml-4 text-lg font-bold hover:opacity-70"
            >
              ✕
            </button>
          </div>
        )}

        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm p-6">
          <h1 className="text-2xl font-bold text-slate-800 dark:text-slate-100 mb-2">Security Review Queue</h1>
          <p className="text-slate-500 dark:text-slate-400 mb-6">
            Track and trigger threat model generation for queued security reviews
          </p>

          {queueItems.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-slate-500 dark:text-slate-400 text-lg">No items in queue</p>
            </div>
          ) : (
            <>
              {/* Filter Panel */}
              <div className="mb-5 p-4 bg-slate-50 dark:bg-gray-800/60 border border-slate-200 dark:border-gray-700 rounded-lg">
                <div className="flex items-center justify-between mb-3">
                  <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Filters</h2>
                  {hasActiveFilters && (
                    <button
                      onClick={clearFilters}
                      className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 font-medium"
                    >
                      Clear all
                    </button>
                  )}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
                  {/* Secreview ID */}
                  <div>
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Secreview ID</label>
                    <input
                      type="text"
                      value={filterSecreviewId}
                      onChange={e => setFilterSecreviewId(e.target.value)}
                      placeholder="Search..."
                      className="w-full px-2 py-1.5 text-xs border border-slate-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                  {/* Service Name */}
                  <div>
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Service Name</label>
                    <input
                      type="text"
                      value={filterServiceName}
                      onChange={e => setFilterServiceName(e.target.value)}
                      placeholder="Search..."
                      className="w-full px-2 py-1.5 text-xs border border-slate-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                  {/* TEAM dropdown */}
                  <div>
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">TEAM</label>
                    <select
                      value={filterDepartment}
                      onChange={e => setFilterDepartment(e.target.value)}
                      className="w-full px-2 py-1.5 text-xs border border-slate-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    >
                      <option value="">All</option>
                      {allDepartments.map(department => (
                        <option key={department} value={department}>{department}</option>
                      ))}
                    </select>
                  </div>
                  {/* Initiated By multi-select */}
                  <div className="relative">
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Initiated By</label>
                    <button
                      type="button"
                      onClick={() => setShowInitiatedByDropdown(v => !v)}
                      className="w-full px-2 py-1.5 text-xs border border-slate-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-left focus:outline-none focus:ring-1 focus:ring-blue-500 flex items-center justify-between"
                    >
                      <span className={filterInitiatedBy.length === 0 ? 'text-slate-400 dark:text-slate-500' : 'text-slate-700 dark:text-slate-200'}>
                        {filterInitiatedBy.length === 0 ? 'All' : `${filterInitiatedBy.length} selected`}
                      </span>
                      <svg className="h-3 w-3 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </button>
                    {showInitiatedByDropdown && (
                      <div className="absolute z-10 mt-1 w-full bg-white dark:bg-gray-800 border border-slate-200 dark:border-gray-600 rounded-md shadow-lg max-h-40 overflow-y-auto">
                        {allInitiatedBy.length === 0 ? (
                          <p className="px-3 py-2 text-xs text-slate-400 dark:text-slate-500">No values</p>
                        ) : allInitiatedBy.map(v => (
                          <label key={v} className="flex items-center px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-gray-700 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={filterInitiatedBy.includes(v)}
                              onChange={() => toggleInitiatedBy(v)}
                              className="mr-2 h-3 w-3"
                            />
                            <span className="text-xs text-slate-700 dark:text-slate-200 truncate">{v}</span>
                          </label>
                        ))}
                      </div>
                    )}
                  </div>
                  {/* Status multi-select */}
                  <div>
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Status</label>
                    <div className="flex flex-wrap gap-1">
                      {allStatuses.map(s => (
                        <button
                          key={s}
                          onClick={() => toggleStatus(s)}
                          className={`px-2 py-0.5 rounded-full text-xs font-medium border transition-colors ${
                            filterStatuses.includes(s)
                              ? getStatusBadgeColor(s) + ' border-transparent'
                              : 'bg-white dark:bg-gray-800 text-slate-500 dark:text-slate-400 border-slate-300 dark:border-gray-600 hover:border-slate-400 dark:hover:border-gray-500'
                          }`}
                        >
                          {s.charAt(0).toUpperCase() + s.slice(1)}
                        </button>
                      ))}
                    </div>
                  </div>
                  {/* Date From */}
                  <div>
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">From Date</label>
                    <input
                      type="date"
                      value={filterDateFrom}
                      onChange={e => setFilterDateFrom(e.target.value)}
                      className="w-full px-2 py-1.5 text-xs border border-slate-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                  {/* Date To */}
                  <div>
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">To Date</label>
                    <input
                      type="date"
                      value={filterDateTo}
                      onChange={e => setFilterDateTo(e.target.value)}
                      className="w-full px-2 py-1.5 text-xs border border-slate-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                </div>
              </div>

              {filteredItems.length === 0 ? (
                <div className="text-center py-10">
                  <p className="text-slate-500 dark:text-slate-400 text-sm">No items match the current filters.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-slate-50 dark:bg-gray-800/60 border-b border-slate-200 dark:border-gray-700">
                      <tr>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-500 dark:text-slate-400">Project Name</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-500 dark:text-slate-400">Sec Review</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-500 dark:text-slate-400">TEAM</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-500 dark:text-slate-400 max-w-[160px]">Service Name</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-500 dark:text-slate-400">Initiated By</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-500 dark:text-slate-400">Status</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-500 dark:text-slate-400">Created</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-500 dark:text-slate-400 min-w-[200px]">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-gray-800">
                      {filteredItems.map((item) => (
                        <tr key={item.assessment_id} className="hover:bg-slate-50 dark:hover:bg-gray-800/40 border-b border-slate-100 dark:border-gray-800">
                          <td className="px-6 py-4 text-sm text-slate-800 dark:text-slate-200 font-medium">{item.additional_data?.projectName || '—'}</td>
                          <td className="px-6 py-4 text-sm text-slate-500 dark:text-slate-400">{item.secreview_id}</td>
                          <td className="px-6 py-4 text-sm text-slate-500 dark:text-slate-400">{item.department || '—'}</td>
                          <td className="px-6 py-4 text-sm text-slate-800 dark:text-slate-200 font-medium max-w-[160px]">
                            <span className="block truncate" title={item.service_name}>{item.service_name}</span>
                          </td>
                          <td className="px-6 py-4 text-sm text-slate-500 dark:text-slate-400">{item.initiated_by}</td>
                          <td className="px-6 py-4 text-sm">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusBadgeColor(item.status)}`}>
                              {item.status.charAt(0).toUpperCase() + item.status.slice(1)}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm text-slate-500 dark:text-slate-400">
                            {new Date(item.created_at).toLocaleDateString()}
                          </td>
                          <td className="px-6 py-4 text-sm flex flex-wrap gap-1.5 items-center min-w-[200px]">
                            <button
                              onClick={() => setSelectedItem(item)}
                              className="inline-flex items-center px-3 py-1 rounded-md text-xs font-medium bg-blue-100 text-blue-700 hover:bg-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:hover:bg-blue-900/60"
                            >
                              Details
                            </button>
                            {item.status === 'processing' ? (
                              <span className="inline-flex flex-wrap items-center gap-1.5 text-xs text-blue-600 dark:text-blue-400 font-medium">
                                <span className="inline-flex items-center space-x-1">
                                  <svg className="animate-spin h-3 w-3 text-blue-600 dark:text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                                  </svg>
                                  <span>{STEP_LABELS[item.current_step || 'rag'] ?? 'Processing...'} ({STEP_PERCENT[item.current_step || 'rag'] ?? 0}%)</span>
                                </span>
                                <button
                                  onClick={() => cancelAssessment(item.assessment_id)}
                                  disabled={cancellingId === item.assessment_id}
                                  className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-700 hover:bg-red-200 dark:bg-red-900/40 dark:text-red-300 dark:hover:bg-red-900/60 disabled:opacity-50"
                                  title="Cancel processing"
                                >
                                  {cancellingId === item.assessment_id ? 'Cancelling…' : 'Cancel'}
                                </button>
                              </span>
                            ) : item.status === 'queued' ? (
                              <span className="inline-flex flex-wrap items-center gap-1.5 text-xs text-purple-600 dark:text-purple-400 font-medium">
                                <span className="inline-flex items-center space-x-1">
                                  <svg className="animate-spin h-3 w-3 text-purple-600 dark:text-purple-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                                  </svg>
                                  <span>Queued for processing...</span>
                                </span>
                                <button
                                  onClick={() => cancelAssessment(item.assessment_id)}
                                  disabled={cancellingId === item.assessment_id}
                                  className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-700 hover:bg-red-200 dark:bg-red-900/40 dark:text-red-300 dark:hover:bg-red-900/60 disabled:opacity-50"
                                  title="Cancel"
                                >
                                  {cancellingId === item.assessment_id ? 'Cancelling…' : 'Cancel'}
                                </button>
                              </span>
                            ) : item.status === 'completed' ? (
                              <button
                                onClick={() => navigate(`/view-threat-model/${item.assessment_id}`)}
                                className="inline-flex items-center px-3 py-1 rounded-md text-xs font-medium bg-green-100 text-green-700 hover:bg-green-200 dark:bg-green-900/40 dark:text-green-300 dark:hover:bg-green-900/60"
                              >
                                View Threat Model
                              </button>
                            ) : (item.status === 'pending' || item.status === 'failed' || item.status === 'cancelled') ? (
                              <span className="inline-flex items-center gap-1">
                                <button
                                  onClick={() => triggerThreatModel(item.secreview_id)}
                                  disabled={processingId === item.secreview_id}
                                  className="inline-flex items-center px-3 py-1 rounded-md text-xs font-medium bg-green-100 text-green-700 hover:bg-green-200 dark:bg-green-900/40 dark:text-green-300 dark:hover:bg-green-900/60 disabled:opacity-50"
                                >
                                  {processingId === item.secreview_id ? 'Starting...' : (item.status === 'failed' || item.status === 'cancelled') ? 'Retry' : 'Trigger'}
                                </button>
                                {item.status === 'pending' && !hasAnyFetchedDoc(item) && (
                                  <span className="relative group">
                                    <svg className="h-3.5 w-3.5 text-amber-500 cursor-pointer" fill="currentColor" viewBox="0 0 20 20">
                                      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                                    </svg>
                                    <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 hidden group-hover:block w-48 px-2 py-1.5 text-xs text-white bg-gray-800 dark:bg-gray-700 rounded shadow-lg z-10 whitespace-normal">
                                      No data fetched — auto-run was skipped
                                    </span>
                                  </span>
                                )}
                              </span>
                            ) : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>

        {/* Detail Modal */}
        {selectedItem && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white dark:bg-gray-900 border border-slate-200 dark:border-gray-700 rounded-xl shadow-lg max-w-2xl w-full max-h-[80vh] overflow-y-auto p-6">
              <div className="flex justify-between items-start mb-4">
                <h2 className="text-2xl font-bold text-slate-800 dark:text-slate-100">
                  {selectedItem.service_name}
                </h2>
                <button
                  onClick={() => setSelectedItem(null)}
                  className="text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Secreview ID
                  </label>
                  <p className="text-slate-800 dark:text-slate-200">{selectedItem.secreview_id}</p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Assessment ID
                  </label>
                  <p className="text-slate-800 dark:text-slate-200 break-all">{selectedItem.assessment_id}</p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Initiated By
                  </label>
                  <p className="text-slate-800 dark:text-slate-200">{selectedItem.initiated_by}</p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Team
                  </label>
                  <p className="text-slate-800 dark:text-slate-200">{selectedItem.department || selectedItem.additional_data?.department || '—'}</p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    PRD URL
                  </label>
                  {editingDocUrl?.docType === 'prdDoc' ? (
                    <div className="flex gap-1.5 items-center mt-1">
                      <input
                        type="text"
                        value={editingDocUrl.url}
                        onChange={e => setEditingDocUrl({ docType: 'prdDoc', url: e.target.value })}
                        placeholder="Enter PRD URL..."
                        autoFocus
                        className="flex-1 px-2 py-1 text-xs border border-slate-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      />
                      <button
                        onClick={() => { retryFetchDoc(selectedItem.assessment_id, 'prdDoc', editingDocUrl.url); setEditingDocUrl(null); }}
                        disabled={!editingDocUrl.url.trim() || retryingDocType === 'prdDoc'}
                        className="px-2 py-1 text-xs font-medium bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap"
                      >Save & Fetch</button>
                      <button onClick={() => setEditingDocUrl(null)} className="px-2 py-1 text-xs font-medium bg-slate-200 dark:bg-gray-700 text-slate-700 dark:text-slate-200 rounded hover:bg-slate-300 dark:hover:bg-gray-600">Cancel</button>
                    </div>
                  ) : (
                    <div className="flex items-start gap-2">
                      {selectedItem.prd_url ? (
                        <a href={selectedItem.prd_url} target="_blank" rel="noopener noreferrer" className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 break-all">{selectedItem.prd_url}</a>
                      ) : (
                        <p className="text-slate-400 dark:text-slate-500">—</p>
                      )}
                      {['cancelled', 'pending', 'failed'].includes(selectedItem.status) && (
                      <button onClick={() => setEditingDocUrl({ docType: 'prdDoc', url: selectedItem.prd_url || '' })} title="Edit PRD URL" className="flex-shrink-0 text-slate-400 hover:text-blue-500 dark:text-slate-500 dark:hover:text-blue-400 transition-colors">
                        <svg className="h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                      </button>
                      )}
                    </div>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Slack Thread
                  </label>
                  {editingDocUrl?.docType === 'slackThread' ? (
                    <div className="flex gap-1.5 items-center mt-1">
                      <input
                        type="text"
                        value={editingDocUrl.url}
                        onChange={e => setEditingDocUrl({ docType: 'slackThread', url: e.target.value })}
                        placeholder="Enter Slack Thread URL..."
                        autoFocus
                        className="flex-1 px-2 py-1 text-xs border border-slate-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 text-slate-800 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      />
                      <button
                        onClick={() => { retryFetchDoc(selectedItem.assessment_id, 'slackThread', editingDocUrl.url); setEditingDocUrl(null); }}
                        disabled={!editingDocUrl.url.trim() || retryingDocType === 'slackThread'}
                        className="px-2 py-1 text-xs font-medium bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap"
                      >Save & Fetch</button>
                      <button onClick={() => setEditingDocUrl(null)} className="px-2 py-1 text-xs font-medium bg-slate-200 dark:bg-gray-700 text-slate-700 dark:text-slate-200 rounded hover:bg-slate-300 dark:hover:bg-gray-600">Cancel</button>
                    </div>
                  ) : (
                    <div className="flex items-start gap-2">
                      {selectedItem.slack_thread ? (
                        <a href={selectedItem.slack_thread} target="_blank" rel="noopener noreferrer" className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 break-all">{selectedItem.slack_thread}</a>
                      ) : (
                        <p className="text-slate-400 dark:text-slate-500">—</p>
                      )}
                      {['cancelled', 'pending', 'failed'].includes(selectedItem.status) && (
                      <button onClick={() => setEditingDocUrl({ docType: 'slackThread', url: selectedItem.slack_thread || '' })} title="Edit Slack Thread URL" className="flex-shrink-0 text-slate-400 hover:text-blue-500 dark:text-slate-500 dark:hover:text-blue-400 transition-colors">
                        <svg className="h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                      </button>
                      )}
                    </div>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Status
                  </label>
                  <span
                    className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusBadgeColor(
                      selectedItem.status
                    )}`}
                  >
                    {selectedItem.status.charAt(0).toUpperCase() + selectedItem.status.slice(1)}
                  </span>
                </div>

                {selectedItem.status === 'failed' && selectedItem.error_message && (
                  <div className="bg-red-100 dark:bg-red-900/40 border border-red-400 dark:border-red-700 text-red-700 dark:text-red-300 px-4 py-3 rounded">
                    <p className="font-bold">Error:</p>
                    <p>{selectedItem.error_message}</p>
                  </div>
                )}

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Document Fetch Status
                  </label>
                  <div className="text-sm space-y-2">
                    {(['prdDoc', 'slackThread'] as const).map((key) => {
                      const labels: Record<string, string> = {
                        prdDoc: 'PRD Document',
                        slackThread: 'Slack Thread',
                      };
                      const doc = selectedItem.additional_data?.additionalDocuments?.[key];

                      return (
                        <div key={key}>
                          <div className="flex items-center gap-1.5">
                            {!doc ? (
                              <span className="text-slate-400 dark:text-slate-500 flex items-center gap-1.5">
                                <span>—</span>
                                <span>{labels[key]}: Not provided</span>
                              </span>
                            ) : doc.error ? (
                              <span className="text-red-600 dark:text-red-400 font-medium flex items-center gap-1">
                                <span>✗</span>
                                <span>{labels[key]}: Fetch failed</span>
                                <button
                                  onClick={() => retryFetchDoc(selectedItem.assessment_id, key)}
                                  disabled={retryingDocType === key}
                                  title="Retry with same URL"
                                  className="ml-1 text-blue-500 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 disabled:opacity-50 flex-shrink-0"
                                >
                                  <svg className={`h-3.5 w-3.5 ${retryingDocType === key ? 'animate-spin' : ''}`} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                  </svg>
                                </button>
                              </span>
                            ) : (
                              <span className="text-green-600 dark:text-green-400 font-medium flex items-center gap-1.5">
                                <span>✓</span>
                                <span>{labels[key]}: Fetched successfully</span>
                              </span>
                            )}
                          </div>
                          {doc?.error && (
                            <p className="text-xs text-red-500 dark:text-red-400 ml-4 break-all">{doc.error}</p>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Created
                  </label>
                  <p className="text-slate-800 dark:text-slate-200">
                    {new Date(selectedItem.created_at).toLocaleString()}
                  </p>
                </div>
              </div>

              <div className="mt-6 flex justify-end space-x-3">
                {(selectedItem.status === 'pending' || selectedItem.status === 'failed') && (
                  <button
                    onClick={() => {
                      triggerThreatModel(selectedItem.secreview_id);
                      setSelectedItem(null);
                    }}
                    disabled={processingId === selectedItem.secreview_id}
                    className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50"
                  >
                    {processingId === selectedItem.secreview_id ? 'Processing...' : selectedItem.status === 'failed' ? 'Retry Threat Model' : 'Trigger Threat Model'}
                  </button>
                )}
                <button
                  onClick={() => setSelectedItem(null)}
                  className="px-4 py-2 bg-slate-200 dark:bg-gray-700 text-slate-700 dark:text-slate-200 rounded-md hover:bg-slate-300 dark:hover:bg-gray-600"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}

        {/* No Documents Modal */}
        {showNoDocModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white dark:bg-gray-900 border border-slate-200 dark:border-gray-700 rounded-xl shadow-lg max-w-md w-full p-6">
              <div className="mb-4">
                <h2 className="text-xl font-bold text-slate-800 dark:text-slate-100">No Documents Found</h2>
              </div>

              <div className="mb-6">
                <p className="text-slate-700 dark:text-slate-300">
                  No Confluence documents or PRD were fetched. Do you want to proceed with threat model generation without these documents?
                </p>
                <p className="mt-3 text-sm font-semibold text-amber-700 dark:text-amber-400">
                  Note: Results might not be relevant without source documents. Please proceed with caution - this may lead to false positives and inaccurate threat scenarios.
                </p>
              </div>

              <div className="flex justify-end space-x-3">
                <button
                  onClick={handleCancelNoDocsModal}
                  className="px-4 py-2 bg-slate-200 dark:bg-gray-700 text-slate-700 dark:text-slate-200 rounded-md hover:bg-slate-300 dark:hover:bg-gray-600"
                >
                  Cancel
                </button>
                <button
                  onClick={handleProceedWithoutDocs}
                  className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
                >
                  Proceed
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Queue;
