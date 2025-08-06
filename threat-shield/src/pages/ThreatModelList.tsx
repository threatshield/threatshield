import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAssessment } from '../context/AssessmentContext';
import ReportHistoryPanel from '../components/common/ReportHistory/ReportHistoryPanel';
import { apiService, API_BASE_URL } from '../services/api';

const ThreatModelList: React.FC = () => {
  const navigate = useNavigate();
  const { setAssessmentId } = useAssessment();
  const [refreshKey, setRefreshKey] = useState(0); // Add state to force refresh after deletion
  
  const handleDelete = async (reportId: string) => {
    try {
      await apiService.deleteThreatModel(reportId);
      // Force refresh of the list
      setRefreshKey(prevKey => prevKey + 1);
    } catch (error) {
      console.error('Error deleting threat model:', error);
      alert('Failed to delete threat model. Please try again.');
    }
  };
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="py-4">
        <div className="max-w-5xl mx-auto px-4">
          <div className="text-center">
            <h1 className="text-4xl font-bold mb-2">
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-[#0052cc]">
                Threat Models
              </span>
            </h1>
            <p className="text-xl text-[#0052cc]">View and analyze your threat models</p>
          </div>
        </div>
      </div>

      {/* Report History Panel */}
      <div className="max-w-5xl mx-auto px-4">
        <ReportHistoryPanel 
          key={refreshKey} // Add key to force re-render on deletion
          className="w-full" 
          buttonText="View Threat Model"
          onDelete={handleDelete} // Add this prop
          onSelect={async (reportId) => {
            try {
              console.log('Selected report ID:', reportId);
              
              // First check if the threat model exists in storage
              const data = await apiService.getStoredThreatModel(reportId);
              console.log('Successfully fetched threat model:', data);
              
              // Set the assessment ID and navigate
              setAssessmentId(reportId);
              navigate(`/view-threat-model/${reportId}`);
            } catch (error) {
              console.error('Error:', error);
              alert('Failed to load threat model. Please try again.');
            }
          }}
        />
      </div>
    </div>
  );
};

export default ThreatModelList;
