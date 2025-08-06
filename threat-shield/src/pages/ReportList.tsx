import React from 'react';
import ReportHistoryPanel from '../components/common/ReportHistory/ReportHistoryPanel';

const ReportList: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="py-4">
        <div className="max-w-5xl mx-auto px-4">
          <div className="text-center">
            <h1 className="text-4xl font-bold mb-2">
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-[#0052cc]">
                Report History
              </span>
            </h1>
            <p className="text-xl text-[#0052cc]">View and manage your threat assessments</p>
          </div>
        </div>
      </div>

      {/* Report History Panel */}
      <div className="max-w-5xl mx-auto px-4">
        <ReportHistoryPanel className="w-full" />
      </div>
    </div>
  );
};

export default ReportList;
