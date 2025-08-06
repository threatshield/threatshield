import React, { useState, useEffect } from 'react';
import { ReportMetadata, ReportDetails, ProjectDetails } from '../../../types/reportTypes';

interface FormattedDetails {
  projectName: string;
  timestamp: string;
  threatModelingMethodology?: string;
}

const isProjectDetails = (details: any): details is ProjectDetails => {
  return details && 
    typeof details.projectName === 'string' &&
    typeof details.timestamp === 'string';
};

const getFormattedDetails = (details: any): FormattedDetails | null => {
  if (!isProjectDetails(details)) return null;
  return {
    projectName: details.projectName,
    timestamp: details.timestamp,
    threatModelingMethodology: details.threatModelingMethodology
  };
};

interface ReportHistoryItemProps {
  report: ReportMetadata;
  onClick: () => void;
  onDelete?: () => void;
  buttonText?: string;
}

const ReportHistoryItem: React.FC<ReportHistoryItemProps> = ({ report, onClick, onDelete, buttonText = "View Report" }) => {
  const [isHovered, setIsHovered] = useState(false);
  const [isAdmin, setIsAdmin] = useState<boolean>(false);
  const details = getFormattedDetails(report.details);

  // Check for admin cookie on component mount
  useEffect(() => {
    const cookies = document.cookie.split(';');
    const adminCookie = cookies.find(cookie => cookie.trim().startsWith('admin='));
    setIsAdmin(adminCookie?.split('=')[1]?.toLowerCase() === 'true');
  }, []);

  // Function to format the date
  const formatDate = (dateString: string) => {
    try {
      const date = new Date(dateString);
      const now = new Date();
      const diffTime = Math.abs(now.getTime() - date.getTime());
      const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
      
      if (diffDays === 0) {
        return `Today at ${date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
      } else if (diffDays === 1) {
        return `Yesterday at ${date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
      } else if (diffDays < 7) {
        return `${diffDays} days ago`;
      } else {
        return date.toLocaleDateString('en-US', {
          month: 'short',
          day: 'numeric',
          year: 'numeric',
          hour: 'numeric',
          minute: '2-digit'
        });
      }
    } catch (e) {
      return 'Invalid date';
    }
  };

  // Function to determine which badge to show based on available reports
  const getBadges = () => {
    const badges: JSX.Element[] = [];
    
    // Regular report type badges (threat model, DREAD, mitigation, attack tree)
    const reportTypes = [
      {
        key: 'threat_model',
        available: report.threat_model?.result !== undefined,
        title: 'Threat Model Analysis',
        label: 'Threat Model',
        bgColor: 'bg-green-100',
        textColor: 'text-green-800',
        icon: (
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        )
      },
      {
        key: 'dread_assessment',
        available: report.dread_assessment?.result !== undefined,
        title: 'DREAD Risk Assessment',
        label: 'DREAD',
        bgColor: 'bg-yellow-100',
        textColor: 'text-yellow-800',
        icon: (
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        )
      },
      {
        key: 'mitigation',
        available: report.mitigation?.result !== undefined,
        title: 'Security Mitigations',
        label: 'Mitigation',
        bgColor: 'bg-red-100',
        textColor: 'text-red-800',
        icon: (
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        )
      },
      {
        key: 'attack_tree',
        available: report.attack_tree?.result !== undefined,
        title: 'Attack Tree Analysis',
        label: 'Attack Tree',
        bgColor: 'bg-blue-100',
        textColor: 'text-blue-800',
        icon: (
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
        )
      }
    ];

    // Add regular badges
    reportTypes.forEach(type => {
      if (type.available) {
        badges.push(
          <span 
            key={type.key} 
            className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${type.bgColor} ${type.textColor}`}
            title={type.title}
          >
            <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {type.icon}
            </svg>
            {type.label}
          </span>
        );
      }
    });
    
    return badges;
  };

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`p-4 rounded-lg cursor-pointer transition-all duration-200 border relative group ${
        isHovered 
          ? 'border-indigo-300 bg-indigo-50/50 shadow-md transform -translate-y-0.5' 
          : 'border-gray-200 bg-white'
      }`}
    >
      {/* Action Button */}
      {/* Delete button - only visible for admins */}
      {isAdmin && onDelete && (
        <button
          onClick={(e) => {
            e.stopPropagation(); // Prevent triggering the parent onClick
            // Confirm before deleting
            if (window.confirm('Are you sure you want to delete this threat model? This action cannot be undone.')) {
              onDelete();
            }
          }}
          className="absolute top-4 right-4 p-2 bg-red-600 text-white rounded-full hover:bg-red-700 transition-all duration-200 z-10"
          title="Delete Threat Model"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}



      <div className={`absolute bottom-4 right-4 transition-all duration-200`}>
        <div className={`px-4 py-2 bg-indigo-600 text-white rounded-full transform transition-all duration-200 shadow-sm hover:shadow-md ${
          isHovered ? 'scale-100 opacity-100' : 'scale-95 opacity-0'
        }`}>
          <span className="flex items-center whitespace-nowrap">
            <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            {buttonText}
          </span>
        </div>
      </div>

      <div className="flex items-start justify-between mb-2">
        <div className="flex-1">
          {details ? (
            <>
              <h4 className="text-sm font-medium text-gray-900 mb-1">
                {details.projectName} - {new Date(details.timestamp).toLocaleDateString()}
              </h4>
              <div className="flex flex-col">
                <div className="flex items-center text-xs text-gray-500 mb-1">
                  <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {formatDate(details.timestamp)}
                </div>
                <div className="text-xs text-gray-400 font-mono">
                  ID: {report.id}
                </div>
              </div>
            </>
          ) : (
            <>
              <h4 className="text-sm font-medium text-gray-900 mb-1 truncate">{report.name || 'Untitled Report'}</h4>
              <div className="flex items-center text-xs text-gray-500">
                <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                No date available
              </div>
            </>
          )}
        </div>
        <svg 
          className={`w-5 h-5 text-indigo-500 transition-opacity duration-200 ${isHovered ? 'opacity-100' : 'opacity-0'}`}
          fill="none" 
          stroke="currentColor" 
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {getBadges()}
      </div>
    </div>
  );
};

export default ReportHistoryItem;
