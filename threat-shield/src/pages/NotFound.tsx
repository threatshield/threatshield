import React, { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useNavbar } from '../context/NavbarContext';
import { SKIP_LANDING_LOADER_KEY } from './LandingPage';

/**
 * Full-screen 404 page for unmatched routes.
 * Hides the navbar while mounted.
 */
const NotFound: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { setNavbarHidden } = useNavbar();

  // Hide the navbar while this page is shown, restore it on leave.
  useEffect(() => {
    setNavbarHidden(true);
    return () => setNavbarHidden(false);
  }, [setNavbarHidden]);

  // Navigate to the dashboard without flashing the landing intro loader
  // (if the user isn't authenticated, /home redirects to the landing page).
  const goToDashboard = () => {
    try { sessionStorage.setItem(SKIP_LANDING_LOADER_KEY, '1'); } catch (e) { /* noop */ }
    navigate('/home');
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 60,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
        background: 'linear-gradient(165deg, #04080f 0%, #080f1e 50%, #04080f 100%)',
        color: 'rgba(255,255,255,0.9)',
        fontFamily: "'IBM Plex Sans', system-ui, sans-serif",
        overflow: 'hidden',
      }}
    >
      {/* Dot grid */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: 'radial-gradient(circle, rgba(59,130,246,0.16) 1px, transparent 1px)',
          backgroundSize: '38px 38px',
          opacity: 0.28,
          pointerEvents: 'none',
        }}
      />
      {/* Glow */}
      <div
        style={{
          position: 'absolute',
          top: '-15%',
          left: '50%',
          width: 900,
          height: 600,
          transform: 'translateX(-50%)',
          background: 'radial-gradient(ellipse, rgba(59,130,246,0.12) 0%, transparent 65%)',
          pointerEvents: 'none',
        }}
      />

      <div style={{ position: 'relative', textAlign: 'center', maxWidth: 520 }}>
        {/* Shield mark */}
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 64,
            height: 64,
            borderRadius: 18,
            background: 'linear-gradient(135deg, rgba(59,130,246,0.9) 0%, rgba(99,102,241,0.9) 100%)',
            boxShadow: '0 0 0 1px rgba(96,165,250,0.35), 0 12px 34px rgba(59,130,246,0.35)',
            marginBottom: 28,
          }}
        >
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M12 8v4" />
            <path d="M12 16h.01" />
          </svg>
        </div>

        <div
          style={{
            fontFamily: "'Space Grotesk', sans-serif",
            fontSize: 96,
            fontWeight: 700,
            lineHeight: 1,
            letterSpacing: '-0.04em',
            background: 'linear-gradient(120deg, #93c5fd 10%, #3b82f6 90%)',
            WebkitBackgroundClip: 'text',
            backgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            marginBottom: 8,
          }}
        >
          404
        </div>

        <h1
          style={{
            fontFamily: "'Space Grotesk', sans-serif",
            fontSize: 24,
            fontWeight: 700,
            color: 'rgba(255,255,255,0.92)',
            margin: '0 0 12px',
          }}
        >
          this page slipped through the threat model
        </h1>
        <p style={{ fontSize: 14.5, color: 'rgba(148,163,184,0.75)', lineHeight: 1.7, margin: '0 0 8px' }}>
          we couldn't find anything at
        </p>
        <code
          style={{
            display: 'inline-block',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 12.5,
            color: 'rgba(147,197,253,0.9)',
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 8,
            padding: '5px 12px',
            marginBottom: 32,
            maxWidth: '100%',
            overflowWrap: 'anywhere',
          }}
        >
          {location.pathname}
        </code>

        <div style={{ display: 'flex', gap: 14, justifyContent: 'center', flexWrap: 'wrap' }}>
          <button
            onClick={goToDashboard}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 9,
              padding: '13px 28px',
              borderRadius: 11,
              background: 'linear-gradient(135deg, #1d4ed8, #2563eb)',
              border: '1px solid rgba(96,165,250,0.3)',
              color: '#fff',
              fontSize: 14,
              fontWeight: 500,
              cursor: 'pointer',
              boxShadow: '0 0 28px rgba(59,130,246,0.3)',
              transition: 'box-shadow 0.2s ease',
            }}
            onMouseEnter={e => ((e.currentTarget as HTMLElement).style.boxShadow = '0 0 40px rgba(59,130,246,0.5)')}
            onMouseLeave={e => ((e.currentTarget as HTMLElement).style.boxShadow = '0 0 28px rgba(59,130,246,0.3)')}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <path d="M3 9.5 12 3l9 6.5" />
              <path d="M5 10v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V10" />
            </svg>
            go to dashboard
          </button>
          <button
            onClick={() => navigate(-1)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 9,
              padding: '13px 24px',
              borderRadius: 11,
              border: '1px solid rgba(255,255,255,0.14)',
              background: 'rgba(255,255,255,0.04)',
              color: 'rgba(255,255,255,0.9)',
              fontSize: 14,
              fontWeight: 500,
              cursor: 'pointer',
              transition: 'background 0.2s ease, border-color 0.2s ease',
            }}
            onMouseEnter={e => {
              const el = e.currentTarget as HTMLElement;
              el.style.background = 'rgba(255,255,255,0.08)';
              el.style.borderColor = 'rgba(255,255,255,0.22)';
            }}
            onMouseLeave={e => {
              const el = e.currentTarget as HTMLElement;
              el.style.background = 'rgba(255,255,255,0.04)';
              el.style.borderColor = 'rgba(255,255,255,0.14)';
            }}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7" />
            </svg>
            go back
          </button>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
