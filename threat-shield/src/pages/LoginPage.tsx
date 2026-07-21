import React, { useState } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import { GoogleLogin, CredentialResponse } from '@react-oauth/google';
import { useAuth } from '../context/AuthContext';

/* ─── Mini feature rows shown below the sign-in button ─────────────────── */
const FEATURES = [
  {
    icon: (
      <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    label: 'AI-powered threat modeling',
  },
  {
    icon: (
      <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    ),
    label: 'DREAD risk scoring & ASVS test cases',
  },
  {
    icon: (
      <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
      </svg>
    ),
    label: 'Attack tree & mitigation reports',
  },
];

const LoginPage: React.FC = () => {
  const { login, user, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const from = (location.state as any)?.from?.pathname ?? '/home';

  // Already authenticated — skip the login page
  if (!loading && user) {
    return <Navigate to={from} replace />;
  }

  const handleSuccess = async (credentialResponse: CredentialResponse) => {
    if (!credentialResponse.credential) {
      setError('No credential received from Google');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await login(credentialResponse.credential);
      navigate(from, { replace: true });
    } catch (e: any) {
      setError(e.message || 'Login failed');
    } finally {
      setSubmitting(false);
    }
  };

  const handleError = () => {
    setError('Google sign-in failed. Please try again.');
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        background: 'linear-gradient(160deg, #04080f 0%, #080f1e 50%, #04080f 100%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px 16px',
        position: 'relative',
        overflow: 'hidden',
        fontFamily: 'inherit',
      }}
    >
      {/* ── Dot grid ─────────────────────────────────────────── */}
      <div
        style={{
          position: 'fixed',
          inset: 0,
          backgroundImage:
            'radial-gradient(circle, rgba(59,130,246,0.15) 1px, transparent 1px)',
          backgroundSize: '36px 36px',
          opacity: 0.3,
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />

      {/* ── Ambient glow — top-left ───────────────────────────── */}
      <div
        style={{
          position: 'fixed',
          top: '-15%',
          left: '-10%',
          width: 600,
          height: 600,
          borderRadius: '50%',
          background:
            'radial-gradient(circle, rgba(59,130,246,0.12) 0%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />

      {/* ── Ambient glow — bottom-right ──────────────────────── */}
      <div
        style={{
          position: 'fixed',
          bottom: '-20%',
          right: '-10%',
          width: 700,
          height: 700,
          borderRadius: '50%',
          background:
            'radial-gradient(circle, rgba(99,102,241,0.1) 0%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />

      {/* ── Card ─────────────────────────────────────────────── */}
      <div
        style={{
          position: 'relative',
          zIndex: 1,
          width: '100%',
          maxWidth: 420,
          borderRadius: 24,
          background: 'rgba(255,255,255,0.03)',
          border: '1px solid rgba(255,255,255,0.08)',
          backdropFilter: 'blur(32px)',
          boxShadow:
            '0 0 0 1px rgba(59,130,246,0.1), 0 40px 80px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.06)',
          padding: '44px 40px 36px',
        }}
      >
        {/* ── Brand ─────────────────────────────────────────── */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          {/* Shield icon with gradient glow */}
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 56,
              height: 56,
              borderRadius: 16,
              background:
                'linear-gradient(135deg, rgba(59,130,246,0.9) 0%, rgba(99,102,241,0.9) 100%)',
              boxShadow:
                '0 0 0 1px rgba(59,130,246,0.4), 0 8px 32px rgba(59,130,246,0.3), 0 2px 8px rgba(0,0,0,0.4)',
              marginBottom: 16,
            }}
          >
            <svg
              width="26"
              height="26"
              fill="none"
              viewBox="0 0 24 24"
              stroke="rgba(255,255,255,0.95)"
              strokeWidth={1.8}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
              />
            </svg>
          </div>

          {/* Wordmark */}
          <div>
            <span
              style={{
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: '0.2em',
                color: 'rgba(147,197,253,0.5)',
                display: 'block',
                marginBottom: 4,
                textTransform: 'uppercase',
              }}
            >
              ThreatShield
            </span>
            <h1
              style={{
                fontSize: 26,
                fontWeight: 700,
                letterSpacing: '-0.02em',
                color: 'rgba(255,255,255,0.95)',
                margin: 0,
                lineHeight: 1.2,
              }}
            >
              ThreatShield
            </h1>
          </div>
        </div>

        {/* ── Divider ───────────────────────────────────────── */}
        <div
          style={{
            height: 1,
            background:
              'linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.07) 50%, transparent 100%)',
            marginBottom: 28,
          }}
        />

        {/* ── Heading ───────────────────────────────────────── */}
        <div style={{ marginBottom: 20 }}>
          <h2
            style={{
              fontSize: 15,
              fontWeight: 600,
              color: 'rgba(255,255,255,0.85)',
              margin: '0 0 4px',
              letterSpacing: '-0.01em',
            }}
          >
            Sign in to continue
          </h2>
        </div>

        {/* ── Error ─────────────────────────────────────────── */}
        {error && (
          <div
            style={{
              marginBottom: 16,
              padding: '10px 14px',
              borderRadius: 10,
              background: 'rgba(239,68,68,0.08)',
              border: '1px solid rgba(239,68,68,0.2)',
              display: 'flex',
              alignItems: 'flex-start',
              gap: 8,
            }}
          >
            <svg
              width="14"
              height="14"
              fill="none"
              viewBox="0 0 24 24"
              stroke="rgba(248,113,113,0.9)"
              strokeWidth={2}
              style={{ marginTop: 1, flexShrink: 0 }}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
              />
            </svg>
            <span
              style={{
                fontSize: 12.5,
                color: 'rgba(248,113,113,0.9)',
                lineHeight: 1.5,
              }}
            >
              {error}
            </span>
          </div>
        )}

        {/* ── Google Sign-In ─────────────────────────────────── */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            opacity: submitting ? 0.5 : 1,
            pointerEvents: submitting ? 'none' : 'auto',
            transition: 'opacity 0.2s ease',
          }}
        >
          <GoogleLogin
            onSuccess={handleSuccess}
            onError={handleError}
            useOneTap={false}
            theme="filled_black"
            size="large"
            text="signin_with"
            shape="rectangular"
            width="340"
          />
        </div>

        {/* ── Loading indicator ──────────────────────────────── */}
        {submitting && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 8,
              marginTop: 14,
            }}
          >
            <div
              style={{
                width: 14,
                height: 14,
                borderRadius: '50%',
                border: '2px solid rgba(59,130,246,0.3)',
                borderTopColor: 'rgba(59,130,246,0.9)',
                animation: 'spin 0.8s linear infinite',
              }}
            />
            <span
              style={{ fontSize: 12, color: 'rgba(148,163,184,0.6)' }}
            >
              Signing you in…
            </span>
          </div>
        )}

        {/* ── Feature list ───────────────────────────────────── */}
        <div
          style={{
            marginTop: 28,
            paddingTop: 20,
            borderTop: '1px solid rgba(255,255,255,0.05)',
            display: 'flex',
            flexDirection: 'column',
            gap: 10,
          }}
        >
          {FEATURES.map((f, i) => (
            <div
              key={i}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
              }}
            >
              <div
                style={{
                  width: 26,
                  height: 26,
                  borderRadius: 7,
                  background: 'rgba(59,130,246,0.1)',
                  border: '1px solid rgba(59,130,246,0.15)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                  color: 'rgba(96,165,250,0.8)',
                }}
              >
                {f.icon}
              </div>
              <span
                style={{
                  fontSize: 12.5,
                  color: 'rgba(148,163,184,0.55)',
                  lineHeight: 1.4,
                }}
              >
                {f.label}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Keyframe for spinner ─────────────────────────────── */}
      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default LoginPage;
