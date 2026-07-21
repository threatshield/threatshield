import React, { useEffect, useState } from 'react';

const INIT_MESSAGES = [
  'Initializing security engine...',
  'Loading threat intelligence modules...',
  'Preparing analysis workspace...',
  'Calibrating risk assessment models...',
  'Setting up secure environment...',
];

const LandingLoader: React.FC = () => {
  const [msgIndex, setMsgIndex] = useState(0);
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const cycle = setInterval(() => {
      setVisible(false);
      setTimeout(() => {
        setMsgIndex(i => (i + 1) % INIT_MESSAGES.length);
        setVisible(true);
      }, 300);
    }, 1800);
    return () => clearInterval(cycle);
  }, []);

  return (
    <>
      <style>{`
        @keyframes ts-shimmer {
          0%   { transform: translateX(-100%); }
          100% { transform: translateX(300%); }
        }
        @keyframes ts-pulse-ring {
          0%, 100% { opacity: 0.15; transform: scale(1); }
          50%       { opacity: 0.35; transform: scale(1.08); }
        }
        .ts-shimmer { animation: ts-shimmer 2.2s ease-in-out infinite; }
        .ts-pulse-ring { animation: ts-pulse-ring 3s ease-in-out infinite; }
      `}</style>

      <div
        className="fixed inset-0 z-50 flex items-center justify-center"
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
            width: 640,
            height: 640,
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(59,130,246,0.07) 0%, transparent 65%)',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
          }}
        />

        {/* Card */}
        <div
          className="relative z-10 flex flex-col items-center mx-4"
          style={{
            width: '100%',
            maxWidth: 400,
            padding: '52px 40px 44px',
            borderRadius: 20,
            background: 'rgba(255,255,255,0.025)',
            border: '1px solid rgba(255,255,255,0.07)',
            backdropFilter: 'blur(24px)',
            boxShadow:
              '0 0 0 1px rgba(59,130,246,0.1), 0 48px 96px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.04)',
          }}
        >
          {/* Pulsing outer ring + shield */}
          <div className="relative flex items-center justify-center mb-8" style={{ width: 96, height: 96 }}>
            <div
              className="ts-pulse-ring absolute inset-0 rounded-full"
              style={{ border: '1px solid rgba(59,130,246,0.6)' }}
            />
            <div
              className="ts-pulse-ring absolute rounded-full"
              style={{
                inset: -10,
                border: '1px solid rgba(59,130,246,0.25)',
                animationDelay: '0.6s',
              }}
            />
            <div
              className="flex items-center justify-center rounded-full"
              style={{
                width: 72,
                height: 72,
                background: 'rgba(59,130,246,0.08)',
                border: '1px solid rgba(59,130,246,0.2)',
              }}
            >
              <svg
                width="34"
                height="34"
                viewBox="0 0 24 24"
                fill="none"
                stroke="rgba(147,197,253,0.85)"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
          </div>

          {/* Wordmark */}
          <div className="text-center mb-8">
            <h1
              className="font-semibold mb-1"
              style={{ fontSize: 22, color: 'rgba(255,255,255,0.92)', letterSpacing: '0.12em' }}
            >
              THREATSHIELD
            </h1>
            <p
              style={{
                fontSize: 10,
                letterSpacing: '0.2em',
                textTransform: 'uppercase',
                color: 'rgba(148,163,184,0.5)',
              }}
            >
              Security Analysis Platform
            </p>
          </div>

          {/* Indeterminate shimmer bar */}
          <div
            className="w-full mb-6 rounded-full overflow-hidden"
            style={{ height: 2, background: 'rgba(255,255,255,0.05)' }}
          >
            <div
              className="ts-shimmer h-full rounded-full"
              style={{
                width: '40%',
                background: 'linear-gradient(to right, transparent, #60a5fa, transparent)',
                boxShadow: '0 0 8px rgba(96,165,250,0.6)',
              }}
            />
          </div>

          {/* Cycling init message */}
          <p
            style={{
              fontSize: 12,
              color: 'rgba(147,197,253,0.75)',
              letterSpacing: '0.03em',
              opacity: visible ? 1 : 0,
              transform: visible ? 'translateY(0)' : 'translateY(4px)',
              transition: 'opacity 0.3s ease, transform 0.3s ease',
              textAlign: 'center',
            }}
          >
            {INIT_MESSAGES[msgIndex]}
          </p>
        </div>
      </div>
    </>
  );
};

export default LandingLoader;
