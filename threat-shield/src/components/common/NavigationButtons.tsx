import React from 'react';
import { Link } from 'react-router-dom';

interface NavigationButtonsProps {
  assessment_id: string;
  currentPage: 'view-threat-model' | 'view-dread' | 'view-attack-tree' | 'view-mitigation' | 'interactive-threat-model' | 'view-security-test-cases';
  hasAttackTree?: boolean;
  hasDread?: boolean;
  hasMitigation?: boolean;
  viewMode?: boolean;
}

const stages = ['view-threat-model', 'view-attack-tree', 'view-dread', 'view-mitigation', 'view-security-test-cases'];

const STAGE_META: Record<string, { label: string; icon: React.ReactNode; activeIcon: React.ReactNode }> = {
  'view-threat-model': {
    label: 'Threat Model',
    icon: (
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
    activeIcon: (
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
  'view-attack-tree': {
    label: 'Attack Tree',
    icon: (
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
      </svg>
    ),
    activeIcon: (
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
      </svg>
    ),
  },
  'view-dread': {
    label: 'DREAD',
    icon: (
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    ),
    activeIcon: (
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    ),
  },
  'view-mitigation': {
    label: 'Mitigation',
    icon: (
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    ),
    activeIcon: (
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    ),
  },
  'view-security-test-cases': {
    label: 'Test Cases',
    icon: (
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
      </svg>
    ),
    activeIcon: (
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
      </svg>
    ),
  },
};

const NavigationButtons: React.FC<NavigationButtonsProps> = ({
  assessment_id,
  currentPage,
  hasAttackTree = false,
  hasDread = false,
  hasMitigation = false,
  viewMode = false,
}) => {
  const shouldShowStage = (stage: string) => {
    if (stage === 'view-attack-tree' && !hasAttackTree) return false;
    if (stage === 'view-dread' && !hasDread) return false;
    if (stage === 'view-mitigation' && !hasMitigation) return false;
    return true;
  };

  const visibleStages = stages.filter(stage => {
    if (currentPage === 'interactive-threat-model' && stage === 'view-threat-model') return false;
    return shouldShowStage(stage);
  });

  return (
    <div className="inline-flex items-center gap-0.5 bg-slate-100 dark:bg-gray-800/70 rounded-xl p-1 border border-slate-200 dark:border-gray-700/60 shadow-sm">
      {visibleStages.map((stage) => {
        const isActive = stage === currentPage;
        const meta = STAGE_META[stage];

        return (
          <Link
            key={stage}
            to={`/${stage}/${assessment_id}`}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-[13px] font-medium whitespace-nowrap transition-all duration-150 select-none ${
              isActive
                ? 'bg-white dark:bg-[#0d1e38] text-[#0052cc] dark:text-blue-400 shadow-sm border border-slate-200/80 dark:border-blue-900/40 pointer-events-none'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-white/60 dark:hover:bg-gray-700/50 border border-transparent'
            }`}
          >
            <span className={isActive ? 'text-[#0052cc] dark:text-blue-400' : 'text-slate-400 dark:text-slate-500'}>
              {isActive ? meta.activeIcon : meta.icon}
            </span>
            {meta.label}
          </Link>
        );
      })}
    </div>
  );
};

export default NavigationButtons;
