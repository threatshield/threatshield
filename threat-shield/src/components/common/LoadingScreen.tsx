import React, { useEffect, useRef, useState } from 'react';
import { LoaderState, LoaderStage, stageProgress, LogEntry } from '../../types/loader';

interface LoadingScreenProps {
  state: LoaderState;
}

const stages: LoaderStage[] = ['upload', 'threat-model','attack-tree', 'dread', 'mitigation', 'complete'];

// Function to render logs from state without typing effect
const TerminalLog: React.FC<{ log: LogEntry }> = ({ log }) => {
  let textColorClass = 'text-green-400';
  
  if (log.type === 'success') {
    textColorClass = 'text-yellow-300';
  } else if (log.type === 'warning') {
    textColorClass = 'text-yellow-500';
  } else if (log.type === 'error') {
    textColorClass = 'text-red-400';
  } else if (log.type === 'task') {
    textColorClass = 'text-blue-300 font-bold';
  }
  
  // Create tree-like structure for subtasks
  let prefix = '';
  if (log.indent) {
    if (log.indent === 1) {
      prefix = '├── ';
    } else if (log.indent === 2) {
      prefix = '│   ├── ';
    } else if (log.indent === 3) {
      prefix = '│   │   ├── ';
    }
  }
  
  return (
    <div className={`mb-1 text-left ${textColorClass}`}>
      {prefix}{log.text}
    </div>
  );
};

// Function to render all logs
const renderLogs = (logs: LogEntry[]) => {
  return logs.map(log => <TerminalLog key={log.id} log={log} />);
};

const LoadingScreen: React.FC<LoadingScreenProps> = ({ state }) => {
  const logsContainerRef = useRef<HTMLDivElement>(null);
  
  // Auto-scroll to the bottom of the logs container when logs change
  useEffect(() => {
    if (logsContainerRef.current) {
      logsContainerRef.current.scrollTop = logsContainerRef.current.scrollHeight;
    }
  }, [state.logs]);
  const getStageStatus = (stage: LoaderStage) => {
    const currentStageIndex = stages.indexOf(state.stage);
    const thisStageIndex = stages.indexOf(stage);
    
    if (thisStageIndex < currentStageIndex) return 'completed';
    if (thisStageIndex === currentStageIndex) return 'current';
    return 'pending';
  };

  const getStageIcon = (stage: LoaderStage) => {
    const status = getStageStatus(stage);
    
    if (status === 'completed') {
      return (
        <svg className="h-6 w-6 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
      );
    }
    
    if (status === 'current') {
      return (
        <svg className="h-6 w-6 text-blue-500 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      );
    }
    
    return (
      <svg className="h-6 w-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    );
  };

  return (
    <div className="fixed inset-0 bg-[#0a192f] flex flex-col items-center justify-center z-50">
      <div className="relative z-10 text-center max-w-2xl w-full px-4">
        <div className="mb-8">
          <div className="flex items-center justify-center mb-4">
            <svg className="h-16 w-16 text-[#0052cc] animate-pulse" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-4xl font-bold text-white mb-2">Threat Shield</h1>
          <p className="text-blue-300 text-xl">Advanced Threat Modeling Platform</p>
        </div>

        {/* Progress bar */}
        <div className="w-full max-w-4xl mx-auto h-2 bg-blue-900 rounded-full mb-6 overflow-hidden">
          <div 
            className="h-full bg-gradient-to-r from-blue-400 to-[#0052cc] rounded-full transition-all duration-500 ease-in-out transform"
            style={{ width: `${state.progress}%` }}
          ></div>
        </div>

        {/* Stages */}
        <div className="grid grid-cols-6 gap-3 mb-8 px-4">
          {stages.map((stage) => (
            <div 
              key={stage}
              className={`flex flex-col items-center ${
                getStageStatus(stage) === 'current' ? 'text-blue-400' :
                getStageStatus(stage) === 'completed' ? 'text-green-500' :
                'text-gray-500'
              }`}
            >
              {getStageIcon(stage)}
              <span className="text-xs mt-2 capitalize">{stage.replace('-', ' ')}</span>
            </div>
          ))}
        </div>

        {/* Current status message */}
        <p className="text-blue-200 text-lg font-medium">
          {state.message}
        </p>
        
        {/* Terminal box */}
        <div className="mt-6 w-full max-w-4xl mx-auto bg-gray-900 rounded-md overflow-hidden border border-gray-700 shadow-lg">
          <div className="bg-gray-800 px-4 py-2 flex items-center">
            <div className="flex space-x-2 mr-4">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
            </div>
            <span className="text-gray-200 font-medium">Progress</span>
          </div>
          <div 
            ref={logsContainerRef}
            className="p-4 h-64 overflow-y-auto font-mono text-sm text-green-400 text-left" 
            id="terminal-logs"
          >
            {state.logs.length > 0 ? renderLogs(state.logs) : (
              <div className="text-gray-500 italic">Initializing Agents, waiting for process to start...(1-2 min)</div>
            )}
          </div>
        </div>
        
        <br></br>
        <p className="text-blue-100 text-lg font-small">
          Please note that it would take around 3-5 minutes for the process to be completed.
        </p>
      </div>
    </div>
  );
};

export default LoadingScreen;
