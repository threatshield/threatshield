import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { ReportMetadata } from '../../../types/reportTypes';
import { useAssessment } from '../../../context/AssessmentContext';
import ReportHistoryItem from '../ReportHistory/ReportHistoryItem';
import { apiService } from '../../../services/api';

interface ReportHistoryPanelProps {
  onSelect?: (reportId: string) => void;
  onDelete?: (reportId: string) => void;
  className?: string;
  buttonText?: string;
}

const ReportHistoryPanel: React.FC<ReportHistoryPanelProps> = ({ onSelect, onDelete, className = '', buttonText = 'View Report' }) => {
  const [reports, setReports] = useState<ReportMetadata[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const navigate = useNavigate();

  useEffect(() => {
    const fetchReports = async () => {
      try {
        setLoading(true);
        console.log('Fetching reports...');
        const response = await apiService.getStorageHistory();
        console.log('API Response:', response);
        
        if (!response || !response.data) {
          console.error('Invalid response format:', response);
          throw new Error('Invalid response format from server');
        }
        
        // Reports are already filtered and sorted by the API service
        setReports(response.data);
      } catch (err) {
        console.error('Error fetching reports:', err);
        setError('No threat models found. Generate a threat model to view report history.');
      } finally {
        setLoading(false);
      }
    };

    fetchReports();
  }, []);

  // Filter reports based on search term
  const filteredReports = useMemo(() => {
    if (!searchTerm) return reports;
    const searchLower = searchTerm.toLowerCase();
    
    return reports.filter(report => {
      // Search in UUID
      if (report.id.toLowerCase().includes(searchLower)) return true;
      
      // Search in original name
      if (report.name?.toLowerCase().includes(searchLower)) return true;
      
      // Search in formatted name if details exist
      if (report.details) {
        const formattedName = `${report.details.projectName} - ${new Date(report.details.timestamp).toLocaleDateString()}`;
        if (formattedName.toLowerCase().includes(searchLower)) return true;
        
        // Search in individual fields
        if (report.details.projectName.toLowerCase().includes(searchLower)) return true;
      }
      
      return false;
    });
  }, [reports, searchTerm]);

  const { setThreatModelData, setDreadData, setMitigationData, setAttackTreeData } = useAssessment();

  const handleReportSelect = (reportId: string) => {
    // Find the selected report
    const selectedReport = reports.find(report => report.id === reportId);
    
    // Set the data in context if available
    if (selectedReport) {
      if (selectedReport.threat_model) {
        setThreatModelData(selectedReport.threat_model);
      }
      if (selectedReport.dread_assessment) {
        setDreadData(selectedReport.dread_assessment);
      }
      if (selectedReport.mitigation) {
        setMitigationData(selectedReport.mitigation);
      }
      if (selectedReport.attack_tree) {
        setAttackTreeData(selectedReport.attack_tree);
      }
    }

    // Call the onSelect prop or navigate
    if (onSelect) {
      onSelect(reportId);
    } else {
      navigate(`/report/${reportId}`);
    }
  };

  return (
    <div className={`bg-white shadow-lg rounded-lg p-4 border border-gray-200 mb-8 ${className}`}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-indigo-600">Threat Model History</h3>
        <div className="relative">
          <input
            type="text"
            placeholder="Search reports..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-48 px-3 py-1 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
          />
          <svg
            className="absolute right-3 top-2 h-4 w-4 text-gray-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
        </div>
      </div>
      {loading ? (
        <div className="flex flex-col items-center justify-center h-32 space-y-3">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-indigo-600"></div>
          <p className="text-sm text-gray-500">Loading reports...</p>
        </div>
      ) : error ? (
        <div className="p-4 bg-gray-50 text-gray-600 rounded-md">
          <div className="flex items-center mb-2">
            <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
            </svg>
            <p className="font-medium">No threat models found</p>
          </div>
          <p className="text-sm">Generate a threat model to view report history.</p>
        </div>
      ) : filteredReports.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-32 text-gray-500">
          <svg className="h-8 w-8 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <p>{searchTerm ? 'No matching reports found' : 'No reports found'}</p>
        </div>
      ) : (
        <div className="space-y-2 h-[calc(100vh-12rem)] overflow-y-auto pb-8">
          {filteredReports.map((report) => (
            <ReportHistoryItem 
              key={report.id} 
              report={report} 
              onClick={() => handleReportSelect(report.id)}
              onDelete={onDelete ? () => onDelete(report.id) : undefined}
              buttonText={buttonText}
            />
          ))}
          
        </div>
        
      )}
      <br></br>
    </div>
  );
};

export default ReportHistoryPanel;
