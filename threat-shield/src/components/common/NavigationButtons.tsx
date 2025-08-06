import React from 'react';
import { Link } from 'react-router-dom';

interface NavigationButtonsProps {
  assessment_id: string;
  currentPage: 'view-threat-model' | 'view-dread' | 'view-attack-tree' | 'view-mitigation';
  hasAttackTree?: boolean;
  hasDread?: boolean;
  hasMitigation?: boolean;
  viewMode?: boolean;
}

// Define the navigation stages in order
const stages = ['view-threat-model', 'view-attack-tree', 'view-dread', 'view-mitigation'];

const NavigationButtons: React.FC<NavigationButtonsProps> = ({
  assessment_id,
  currentPage,
  hasAttackTree = false,
  hasDread = false,
  hasMitigation = false,
  viewMode = false,
}) => {
  const basePrefix = viewMode ? '' : '';

  // Get stage status (current or not)
  const getStageStatus = (stage: string) => {
    return stage === currentPage ? 'current' : 'other';
  };

  // Get icon for each stage
  const getStageIcon = (stage: string) => {
    const status = getStageStatus(stage);
    const isActive = status === 'current';
    const colorClass = isActive ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-600';
    
    // Different icons for different stages
    switch (stage) {
      case 'view-threat-model':
        return (
          <svg className={`h-6 w-6 ${colorClass} transition-colors duration-200`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        );
      case 'view-attack-tree':
        return (
          <svg className={`h-6 w-6 ${colorClass} transition-colors duration-200`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
          </svg>
        );
      case 'view-dread':
        return (
          <svg className={`h-6 w-6 ${colorClass} transition-colors duration-200`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        );
      case 'view-mitigation':
        return (
          <svg className={`h-6 w-6 ${colorClass} transition-colors duration-200`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        );
      default:
        return null;
    }
  };

  // Check if a stage should be shown
  const shouldShowStage = (stage: string) => {
    if (stage === 'view-attack-tree' && !hasAttackTree) return false;
    if (stage === 'view-dread' && !hasDread) return false;
    if (stage === 'view-mitigation' && !hasMitigation) return false;
    return true;
  };

  // Get stage label
  const getStageLabel = (stage: string) => {
    switch (stage) {
      case 'view-threat-model':
        return 'Threat Model';
      case 'view-attack-tree':
        return 'Attack Tree';
      case 'view-dread':
        return 'DREAD';
      case 'view-mitigation':
        return 'Mitigation';
      default:
        return stage.replace('-', ' ');
    }
  };

  // Filter stages based on availability
  const visibleStages = stages.filter(shouldShowStage);

  return (
    <div className="flex flex-col items-center mt-6">
      <div className="flex items-center justify-center w-full max-w-3xl">
        {visibleStages.map((stage, index) => {
          const isActive = getStageStatus(stage) === 'current';
          const isLast = index === visibleStages.length - 1;
          
          return (
            <React.Fragment key={stage}>
              <Link
                to={`${basePrefix}/${stage}/${assessment_id}`}
                className={`group flex flex-col items-center ${isActive ? 'pointer-events-none' : ''}`}
              >
                <div className={`flex items-center justify-center w-12 h-12 rounded-full ${
                  isActive ? 'bg-blue-100' : 'bg-gray-100 group-hover:bg-gray-200'
                } transition-colors duration-200`}>
                  {getStageIcon(stage)}
                </div>
                <span className={`text-xs mt-2 capitalize ${
                  isActive ? 'text-blue-500 font-medium' : 'text-gray-500 group-hover:text-gray-700'
                } transition-colors duration-200`}>
                  {getStageLabel(stage)}
                </span>
              </Link>
              
              {/* Connecting line between icons */}
              {!isLast && (
                <div className="w-16 h-px bg-gray-300 mx-2"></div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};

export default NavigationButtons;
