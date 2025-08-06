import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import ReportHistoryPanel from '../common/ReportHistory/ReportHistoryPanel';
import { apiService } from '../../services/api';
import { ReportMetadata } from '../../types/reportTypes';

export default function NavBar() {
  const [showHistory, setShowHistory] = useState(false);
  const [reports, setReports] = useState<ReportMetadata[]>([]);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // Fetch reports only when the dropdown is opened
    if (showHistory) {
      const fetchReports = async () => {
        try {
          setLoading(true);
          const response = await apiService.getStorageHistory();
          if (response && response.data && Array.isArray(response.data)) {
            // Filter out reports that have no data
            const validReports = response.data.filter((report: ReportMetadata) => {
              // Check if any of the report types exist
              const hasData = ['threat_model', 'dread_assessment', 'mitigation', 'attack_tree']
                .some(type => report[type] && report[type].result);
              
              console.log(`Report ${report.id} has data:`, hasData, report); // Add logging
              return hasData;
            });
            
            // Sort reports by timestamp in descending order (newest first)
            const sortedReports = validReports.sort((a: ReportMetadata, b: ReportMetadata) => 
              new Date(b.details?.timestamp || '').getTime() - new Date(a.details?.timestamp || '').getTime()
            );
            
            console.log('Filtered and sorted reports:', sortedReports); // Add logging
            setReports(sortedReports);
          } else {
            console.log('No reports found in response:', response);
            setReports([]);
          }
        } catch (err) {
          console.error('Error fetching reports:', err);
          setReports([]);
        } finally {
          setLoading(false);
        }
      };

      fetchReports();
    }
  }, [showHistory]);

  const handleReportSelect = (reportId: string) => {
    setShowHistory(false);
    navigate(`/report/${reportId}`);
  };

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as HTMLElement;
      if (showHistory && !target.closest('.report-history-container')) {
        setShowHistory(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showHistory]);

  return (
    <nav className="bg-white shadow-sm">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <img className="h-8 w-auto" src="/logo.svg" alt="Logo" />
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className="relative report-history-container">
              <button 
                onClick={() => setShowHistory(!showHistory)}
                className="flex items-center px-4 py-2 text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors duration-200"
                title="View report history"
              >
                <svg className="w-5 h-5 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
                Reports
                {reports.length > 0 && (
                  <span className="ml-1.5 inline-flex items-center justify-center w-5 h-5 text-xs font-bold text-white bg-indigo-600 rounded-full">
                    {reports.length > 9 ? '9+' : reports.length}
                  </span>
                )}
              </button>
              {showHistory && (
                <div className="absolute top-12 right-0 z-50 w-80 md:w-96">
                  <ReportHistoryPanel onSelect={handleReportSelect} />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
