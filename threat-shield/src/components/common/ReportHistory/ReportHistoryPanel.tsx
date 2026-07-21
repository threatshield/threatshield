import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { ReportMetadata } from '../../../types/reportTypes';
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
        const response = await apiService.getStorageHistory();
        if (!response?.data) {
          throw new Error('Invalid response format from server');
        }
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

  const filteredReports = useMemo(() => {
    if (!searchTerm) return reports;
    const searchLower = searchTerm.toLowerCase();

    return reports.filter(report => {
      if (report.id.toLowerCase().includes(searchLower)) return true;
      if (report.name.toLowerCase().includes(searchLower)) return true;
      if (report.details) {
        if (report.details.department.toLowerCase().includes(searchLower)) return true;
        if (report.details.projectName.toLowerCase().includes(searchLower)) return true;
      }
      return false;
    });
  }, [reports, searchTerm]);

  const handleReportSelect = (reportId: string) => {
    if (onSelect) {
      onSelect(reportId);
    } else {
      navigate(`/report/${reportId}`);
    }
  };

  return (
    <div className={className}>
      {/* Search bar */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          {!loading && !error && (
            <span className="text-sm text-slate-500 dark:text-slate-400">
              <span className="font-semibold text-slate-700 dark:text-slate-300">{filteredReports.length}</span>{' '}
              {filteredReports.length === 1 ? 'assessment' : 'assessments'}
              {searchTerm && ` matching "${searchTerm}"`}
            </span>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder="Search assessments..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-64 pl-9 pr-4 py-2 bg-white dark:bg-gray-800 border border-slate-200 dark:border-gray-700 rounded-lg text-sm text-slate-700 dark:text-slate-300 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#0052cc]/25 focus:border-[#0052cc] transition-all shadow-sm"
          />
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          {searchTerm && (
            <button onClick={() => setSearchTerm('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors">
              <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      {loading && (
        <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-gray-900 rounded-xl border border-slate-200 dark:border-gray-800 shadow-sm">
          <div className="relative w-10 h-10 mb-4">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700" />
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin" />
          </div>
          <p className="text-sm text-slate-400 dark:text-slate-500">Loading assessments...</p>
        </div>
      )}
      {!loading && error && (
        <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-gray-900 rounded-xl border border-dashed border-slate-200 dark:border-gray-700">
          <div className="w-12 h-12 rounded-xl bg-slate-50 dark:bg-gray-800 border border-slate-200 dark:border-gray-700 flex items-center justify-center mb-3">
            <svg className="h-6 w-6 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
            </svg>
          </div>
          <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1">No threat models found</p>
          <p className="text-sm text-slate-400 dark:text-slate-500">Generate a threat model to see your report history.</p>
        </div>
      )}
      {!loading && !error && filteredReports.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-gray-900 rounded-xl border border-dashed border-slate-200 dark:border-gray-700">
          <div className="w-12 h-12 rounded-xl bg-slate-50 dark:bg-gray-800 border border-slate-200 dark:border-gray-700 flex items-center justify-center mb-3">
            <svg className="h-6 w-6 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1">
            {searchTerm ? 'No matching results' : 'No reports found'}
          </p>
          {searchTerm && (
            <p className="text-sm text-slate-400 dark:text-slate-500">
              Try adjusting your search or{' '}
              <button onClick={() => setSearchTerm('')} className="text-[#0052cc] dark:text-blue-400 hover:underline font-medium">
                clear the filter
              </button>
            </p>
          )}
        </div>
      )}
      {!loading && !error && filteredReports.length > 0 && (
        <div className="space-y-2.5 max-h-[calc(100vh-16rem)] overflow-y-auto pr-1 pb-4">
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
    </div>
  );
};

export default ReportHistoryPanel;
