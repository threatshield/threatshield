import React, { useEffect, useRef } from 'react';
import { LoaderState, LoaderStage, LogEntry } from '../../types/loader';

interface LoadingScreenProps {
  state: LoaderState;
  onCancel?: () => void;
  isCancelling?: boolean;
}

// Visual pipeline — 'parallel-analysis' is a virtual stage that activates all four
// analysis stages simultaneously; it is NOT listed here as its own node.
const STAGES: LoaderStage[] = [
  'upload',
  'threat-model',
  'attack-tree',
  'dread',
  'mitigation',
  'security-test-cases',
  'complete',
];

const STAGE_LABELS: Record<LoaderStage, string> = {
  'upload': 'Upload',
  'threat-model': 'Threat Model',
  'parallel-analysis': 'Analysis',
  'attack-tree': 'Attack Tree',
  'dread': 'DREAD',
  'mitigation': 'Mitigation',
  'security-test-cases': 'Test Cases',
  'complete': 'Complete',
};

// Stages that all activate together during the parallel phase
const PARALLEL_STAGES = new Set<LoaderStage>(['attack-tree', 'dread', 'mitigation', 'security-test-cases']);

const TerminalLog: React.FC<{ log: LogEntry }> = ({ log }) => {
  let color = '#4ade80'; // green-400
  if (log.type === 'success') color = '#fde047';   // yellow-300
  else if (log.type === 'warning') color = '#f59e0b'; // yellow-500
  else if (log.type === 'error') color = '#f87171';   // red-400
  else if (log.type === 'task') color = '#93c5fd';    // blue-300

  let prefix = '';
  if (log.indent === 1) prefix = '├── ';
  else if (log.indent === 2) prefix = '│   ├── ';
  else if (log.indent === 3) prefix = '│   │   ├── ';

  const fontWeight = log.type === 'task' ? 600 : 400;

  return (
    <div style={{ color, fontWeight, marginBottom: 3, textAlign: 'left' }}>
      {prefix}{log.text}
    </div>
  );
};

const LoadingScreen: React.FC<LoadingScreenProps> = ({ state, onCancel, isCancelling }) => {
  const logsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }
  }, [state.logs]);

  const isParallel = state.stage === 'parallel-analysis';
  // For the parallel phase, treat 'attack-tree' as the anchor so that
  // 'upload' and 'threat-model' render as completed.
  const currentIdx = isParallel
    ? STAGES.indexOf('attack-tree')
    : STAGES.indexOf(state.stage);

  return (
    <>
      <style>{`
        @keyframes ts-spin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
        .ts-spin { animation: ts-spin 1.2s linear infinite; }
      `}</style>

      <div
        className="fixed inset-0 z-[10000] flex items-center justify-center"
        style={{ background: 'linear-gradient(160deg, #04080f 0%, #080f1e 50%, #04080f 100%)' }}
      >
        {/* Dot-grid */}
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: 'radial-gradient(circle, rgba(59,130,246,0.18) 1px, transparent 1px)',
            backgroundSize: '36px 36px',
            opacity: 0.3,
          }}
        />

        {/* Ambient glow */}
        <div
          className="absolute pointer-events-none"
          style={{
            width: 800,
            height: 800,
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(59,130,246,0.06) 0%, transparent 65%)',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
          }}
        />

        {/* Card */}
        <div
          className="relative z-10 flex flex-col mx-4 w-full"
          style={{
            maxWidth: 760,
            padding: '40px 40px 36px',
            borderRadius: 20,
            background: 'rgba(255,255,255,0.025)',
            border: '1px solid rgba(255,255,255,0.07)',
            backdropFilter: 'blur(24px)',
            boxShadow:
              '0 0 0 1px rgba(59,130,246,0.1), 0 48px 96px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.04)',
          }}
        >
          {/* Header row: wordmark + progress */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <svg
                width="22"
                height="22"
                viewBox="0 0 24 24"
                fill="none"
                stroke="rgba(147,197,253,0.8)"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <span
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  letterSpacing: '0.12em',
                  color: 'rgba(255,255,255,0.75)',
                }}
              >
                THREATSHIELD
              </span>
            </div>
            <span style={{ fontSize: 12, color: 'rgba(100,116,139,0.7)', letterSpacing: '0.05em' }}>
              {state.progress}%
            </span>
          </div>

          {/* Progress bar */}
          <div
            className="w-full rounded-full overflow-hidden mb-6"
            style={{ height: 2, background: 'rgba(255,255,255,0.05)' }}
          >
            <div
              className="h-full rounded-full"
              style={{
                width: `${state.progress}%`,
                background: 'linear-gradient(to right, #1d4ed8, #60a5fa)',
                boxShadow: '0 0 8px rgba(96,165,250,0.5)',
                transition: 'width 0.5s cubic-bezier(0.4, 0, 0.2, 1)',
              }}
            />
          </div>

          {/* Stage pipeline */}
          <div className="flex items-start justify-between mb-6">
            {STAGES.map((s, i) => {
              const isComplete = isParallel ? i < STAGES.indexOf('attack-tree') : i < currentIdx;
              const isActive = isParallel ? PARALLEL_STAGES.has(s) : s === state.stage;

              let dotColor = 'rgba(255,255,255,0.1)';
              if (isComplete) dotColor = '#3b82f6';
              else if (isActive) dotColor = '#93c5fd';

              let dotShadow = 'none';
              if (isActive) dotShadow = '0 0 8px rgba(147,197,253,0.9)';
              else if (isComplete) dotShadow = '0 0 4px rgba(59,130,246,0.5)';

              let labelColor = 'rgba(100,116,139,0.4)';
              if (isActive) labelColor = 'rgba(147,197,253,0.95)';
              else if (isComplete) labelColor = 'rgba(147,197,253,0.5)';

              return (
                <div key={s} className="flex flex-col items-center" style={{ gap: 6, flex: 1 }}>
                  {isActive ? (
                    /* Spinning indicator for active stage */
                    <svg
                      className="ts-spin"
                      width="12"
                      height="12"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="#93c5fd"
                      strokeWidth="2.5"
                      strokeLinecap="round"
                    >
                      <path d="M21 12a9 9 0 11-6.219-8.56" />
                    </svg>
                  ) : isComplete ? (
                    /* Checkmark for completed */
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    <div
                      style={{
                        width: 6,
                        height: 6,
                        borderRadius: '50%',
                        background: dotColor,
                        boxShadow: dotShadow,
                        marginTop: 3,
                        transition: 'all 0.35s ease',
                      }}
                    />
                  )}
                  <span
                    style={{
                      fontSize: 8,
                      letterSpacing: '0.08em',
                      textTransform: 'uppercase',
                      textAlign: 'center',
                      color: labelColor,
                      transition: 'color 0.35s ease',
                      lineHeight: 1.3,
                    }}
                  >
                    {STAGE_LABELS[s]}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Divider */}
          <div
            className="w-full mb-5"
            style={{
              height: 1,
              background: 'linear-gradient(to right, transparent, rgba(255,255,255,0.07), transparent)',
            }}
          />

          {/* Status message */}
          <p
            className="mb-4"
            style={{ fontSize: 13, color: 'rgba(147,197,253,0.85)', fontWeight: 500, letterSpacing: '0.01em' }}
          >
            {state.message}
          </p>

          {/* Terminal */}
          <div
            style={{
              borderRadius: 10,
              overflow: 'hidden',
              border: '1px solid rgba(255,255,255,0.07)',
              background: 'rgba(0,0,0,0.35)',
            }}
          >
            {/* Title bar */}
            <div
              className="flex items-center px-4 py-2.5"
              style={{
                background: 'rgba(255,255,255,0.04)',
                borderBottom: '1px solid rgba(255,255,255,0.06)',
              }}
            >
              <div className="flex gap-1.5 mr-3">
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'rgba(255,95,86,0.7)' }} />
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'rgba(255,189,46,0.7)' }} />
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'rgba(39,201,63,0.7)' }} />
              </div>
              <span style={{ fontSize: 11, color: 'rgba(148,163,184,0.6)', letterSpacing: '0.06em' }}>
                Analysis Log
              </span>
            </div>

            {/* Log content */}
            <div
              ref={logsRef}
              style={{
                padding: '14px 16px',
                height: 220,
                overflowY: 'auto',
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, monospace',
                fontSize: 12,
                lineHeight: 1.6,
              }}
            >
              {state.logs.length > 0 ? (
                state.logs.map(log => <TerminalLog key={log.id} log={log} />)
              ) : (
                <span style={{ color: 'rgba(100,116,139,0.6)', fontStyle: 'italic' }}>
                  Initializing agents, waiting for process to start... (1–2 min)
                </span>
              )}
            </div>
          </div>

          {/* Footer note + cancel */}
          <div className="mt-4 flex flex-col items-center gap-2">
            <p style={{ fontSize: 11, color: 'rgba(100,116,139,0.55)', letterSpacing: '0.03em' }}>
              Analysis typically takes 3–5 minutes to complete.
            </p>
            {onCancel && (
              <button
                onClick={onCancel}
                disabled={isCancelling}
                style={{
                  fontSize: 11,
                  color: isCancelling ? 'rgba(100,116,139,0.4)' : 'rgba(147,197,253,0.6)',
                  background: 'none',
                  border: 'none',
                  cursor: isCancelling ? 'default' : 'pointer',
                  textDecoration: 'underline',
                  textDecorationColor: 'rgba(147,197,253,0.3)',
                  letterSpacing: '0.03em',
                  padding: 0,
                  transition: 'color 0.2s ease',
                }}
                onMouseEnter={e => { if (!isCancelling) (e.target as HTMLElement).style.color = 'rgba(147,197,253,0.9)'; }}
                onMouseLeave={e => { if (!isCancelling) (e.target as HTMLElement).style.color = 'rgba(147,197,253,0.6)'; }}
              >
                {isCancelling ? 'Cancelling…' : 'Cancel analysis'}
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  );
};

export default LoadingScreen;
