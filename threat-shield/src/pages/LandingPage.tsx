import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { GoogleLogin, CredentialResponse } from '@react-oauth/google';
import LandingLoader from '../components/common/LandingLoader';
import { useAuth } from '../context/AuthContext';

const GITHUB_URL = 'https://github.com/threatshield/threatshield';
const CLONE_CMD = 'git clone github.com/threatshield/threatshield';

// Static Swagger UI page served from /public
const API_DOCS_URL = '/api-docs.html';

// sessionStorage flag: when set, the landing intro loader is skipped on next mount
// (used by in-app navigations that may redirect through the landing page).
export const SKIP_LANDING_LOADER_KEY = 'ts-skip-landing-loader';

const NAV_LINKS = [
  { href: '#features', label: 'features' },
  { href: '#model', label: 'threat model' },
  { href: '#how', label: 'how it works' },
  { href: '#benefits', label: 'benefits' },
  { href: API_DOCS_URL, label: 'docs', external: true },
];

const HERO_STATS = [
  { value: 99, suffix: '%', label: 'threat detection' },
  { value: 500, suffix: '+', label: 'security rules' },
  { value: 92, suffix: '%', label: 'faster reviews' },
];

const OLD_WAY = [
  { title: 'weeks per review', desc: 'workshops, diagrams, and write-ups stall every release.' },
  { title: 'inconsistent & subjective', desc: "quality depends on who's in the room that day." },
  { title: 'missed attack paths', desc: 'human reviewers overlook edge cases under deadline pressure.' },
];

const NEW_WAY = [
  { title: 'minutes per assessment', desc: 'upload an architecture or repo and get a full model back.' },
  { title: 'consistent DREAD scoring', desc: 'every threat ranked by the same repeatable methodology.' },
  { title: 'complete attack-tree coverage', desc: 'AI enumerates vectors a human reviewer would miss.' },
];

const FEATURES: { title: string; desc: string; icon: React.ReactNode; accent?: boolean }[] = [
  {
    title: 'automated threat identification',
    desc: 'AI parses your architecture and code to surface threats mapped to STRIDE and OWASP — no manual diagramming.',
    icon: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></>,
  },
  {
    title: 'intelligent risk scoring',
    desc: 'every threat ranked with consistent DREAD scoring so your team fixes what matters most, first.',
    icon: <path d="M9 19v-6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2zm0 0V9a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v10m-6 0a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2m0 0V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-2a2 2 0 0 1-2-2z" />,
  },
  {
    title: 'vulnerability prediction',
    desc: "models learn from known CVE patterns to flag weak spots before they're ever exploited.",
    icon: <><path d="M3 3v18h18" /><path d="m19 9-5 5-4-4-3 3" /></>,
  },
  {
    title: 'CI/CD pipeline integration',
    desc: 'run threat models on every pull request. block merges on critical findings, right inside GitHub Actions.',
    icon: <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z" />,
  },
  {
    title: 'metrics & analytics',
    desc: 'risk analytics by STRIDE category, DREAD-tier dashboards, ASVS coverage, and per-review cost & token metrics — exportable for leadership.',
    icon: <><rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" /></>,
  },
  {
    title: 'ASVS test-case generation',
    desc: 'turn every threat into concrete, ASVS-aligned security test cases your QA team can verify.',
    icon: <><path d="m9 11 3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" /></>,
  },
  {
    title: 'false-positive critic',
    desc: 'a 2nd-pass LLM critic filters false positives, dedupes near-identical scenarios, and sharpens vague threats — plus org-specific suppression rules.',
    icon: <path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z" />,
    accent: true,
  },
  {
    title: 'admin & org controls',
    desc: 'manage users, configure the LLM and methodology, tune false-positive rules, and wire up MCP servers and GitHub — changes apply instantly, no restart.',
    icon: <><line x1="4" y1="21" x2="4" y2="14" /><line x1="4" y1="10" x2="4" y2="3" /><line x1="12" y1="21" x2="12" y2="12" /><line x1="12" y1="8" x2="12" y2="3" /><line x1="20" y1="21" x2="20" y2="16" /><line x1="20" y1="12" x2="20" y2="3" /><line x1="1" y1="14" x2="7" y2="14" /><line x1="9" y1="8" x2="15" y2="8" /><line x1="17" y1="16" x2="23" y2="16" /></>,
  },
];

const HOW_STEPS = [
  { num: '01', title: 'document analysis', desc: 'upload architecture docs, diagrams, or a repo to analyze.' },
  { num: '02', title: 'threat assessment', desc: 'AI identifies and classifies threats via STRIDE or PASTA.' },
  { num: '03', title: 'false-positive critic', desc: 'a 2nd-pass LLM critic prunes false positives, dedupes scenarios, and sharpens vague descriptions.', accent: true },
  { num: '04', title: 'risk evaluation', desc: 'each surviving threat scored and prioritized via DREAD.' },
  { num: '05', title: 'mitigation planning', desc: 'generates concrete security controls for each finding.' },
  { num: '06', title: 'security testing', desc: 'produces ASVS-based test cases ready to run.' },
];

const BENEFITS = [
  { value: '92%', title: 'faster time-to-market', desc: 'ship secure applications without security becoming the bottleneck.' },
  { value: '✓', title: 'stronger security posture', desc: 'consistent, comprehensive coverage across every service you ship.' },
  { value: '10×', title: 'cheaper to fix early', desc: 'catch vulnerabilities at design time, not after a breach.' },
  { value: '1', title: 'one shared source of truth', desc: 'devs, security, and management work from the same living model.' },
];

const SEV: Record<string, { color: string; bg: string }> = {
  critical: { color: '#f3523c', bg: 'rgba(243,82,60,0.16)' },
  high: { color: '#f99438', bg: 'rgba(249,148,56,0.16)' },
  medium: { color: '#60a5fa', bg: 'rgba(59,130,246,0.16)' },
  low: { color: '#05c74f', bg: 'rgba(5,199,79,0.16)' },
};

type ThreatRow = [string, keyof typeof SEV, number];
const NODE_DATA: Record<string, { label: string; type: string; dread: number; threats: ThreatRow[]; pos: React.CSSProperties }> = {
  web: {
    label: 'web client', type: 'Client', dread: 6.4,
    pos: { left: 126, top: 14 },
    threats: [
      ['cross-site scripting (XSS)', 'high', 6.8],
      ['sensitive data in local storage', 'medium', 5.1],
      ['clickjacking', 'low', 3.4],
    ],
  },
  gw: {
    label: 'API gateway', type: 'API Gateway', dread: 9.1,
    pos: { left: 126, top: 100 },
    threats: [
      ['SQL injection · /api/auth/login', 'critical', 9.1],
      ['broken access control · /admin', 'high', 7.4],
      ['missing rate limiting', 'medium', 5.6],
    ],
  },
  auth: {
    label: 'auth service', type: 'Microservice', dread: 8.3,
    pos: { left: 14, top: 184 },
    threats: [
      ['JWT signature not verified', 'critical', 8.3],
      ['weak session token entropy', 'high', 7.2],
      ['privilege escalation via role claim', 'high', 6.9],
    ],
  },
  db: {
    label: 'database', type: 'Database', dread: 4.2,
    pos: { left: 238, top: 184 },
    threats: [
      ['unencrypted PII at rest', 'medium', 5.0],
      ['excessive db user privileges', 'low', 3.8],
      ['backup file exposure', 'low', 3.1],
    ],
  },
};

const AUTH_FEATURES = [
  {
    icon: <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
    label: 'AI-powered threat modeling',
  },
  {
    icon: <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />,
    label: 'DREAD scoring & ASVS test cases',
  },
  {
    icon: <path strokeLinecap="round" strokeLinejoin="round" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />,
    label: 'Attack tree & mitigation reports',
  },
];

// Navbar height: 16px padding top + 16px bottom + 34px tallest child (the GitHub
// button: 8+8 padding, 1+1 border, 16px line box) + 1px bottom border. Used to size
// the hero to exactly one viewport, so the section after it starts below the fold.
const NAV_HEIGHT = 67;

// Font stacks used by the landing design
const DISPLAY = "'Space Grotesk', sans-serif";
const BODY = "'IBM Plex Sans', sans-serif";
const MONO = "'JetBrains Mono', monospace";

// Shared inline style token
const card: React.CSSProperties = {
  borderRadius: 18,
  background: 'rgba(255,255,255,0.025)',
  border: '1px solid rgba(255,255,255,0.08)',
  backdropFilter: 'blur(24px)',
  boxShadow: '0 0 0 1px rgba(59,130,246,0.08), 0 40px 80px rgba(0,0,0,0.5)',
};

/* ─── Sign-in dialog ──────────────────────────────────────────────────────── */
interface SignInDialogProps {
  onClose: () => void;
  onSuccess: () => void;
}

const SignInDialog: React.FC<SignInDialogProps> = ({ onClose, onSuccess }) => {
  const { login } = useAuth();
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  const handleSuccess = async (cr: CredentialResponse) => {
    if (!cr.credential) { setError('No credential received from Google'); return; }
    setSubmitting(true);
    setError('');
    try {
      await login(cr.credential);
      onSuccess();
    } catch (e: any) {
      setError(e.message || 'Login failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    /* Backdrop */
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 100,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
        background: 'rgba(4,8,15,0.75)',
        backdropFilter: 'blur(8px)',
        animation: 'fadeIn 0.15s ease',
      }}
    >
      {/* Card — stop propagation so clicks inside don't close */}
      <div
        onClick={e => e.stopPropagation()}
        style={{
          position: 'relative',
          width: '100%',
          maxWidth: 400,
          borderRadius: 24,
          background: 'rgba(8,15,30,0.95)',
          border: '1px solid rgba(255,255,255,0.09)',
          backdropFilter: 'blur(40px)',
          boxShadow: '0 0 0 1px rgba(59,130,246,0.12), 0 40px 80px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.06)',
          padding: '40px 36px 32px',
          animation: 'slideUp 0.2s ease',
        }}
      >
        {/* Close button */}
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: 16,
            right: 16,
            width: 28,
            height: 28,
            borderRadius: 8,
            border: '1px solid rgba(255,255,255,0.08)',
            background: 'rgba(255,255,255,0.04)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
            color: 'rgba(148,163,184,0.5)',
            transition: 'background 0.15s ease, color 0.15s ease',
          }}
          onMouseEnter={e => {
            (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.08)';
            (e.currentTarget as HTMLElement).style.color = 'rgba(255,255,255,0.8)';
          }}
          onMouseLeave={e => {
            (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.04)';
            (e.currentTarget as HTMLElement).style.color = 'rgba(148,163,184,0.5)';
          }}
        >
          <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>

        {/* Brand */}
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 52,
              height: 52,
              borderRadius: 15,
              background: 'linear-gradient(135deg, rgba(59,130,246,0.9) 0%, rgba(99,102,241,0.9) 100%)',
              boxShadow: '0 0 0 1px rgba(59,130,246,0.35), 0 8px 28px rgba(59,130,246,0.28)',
              marginBottom: 14,
            }}
          >
            <svg width="24" height="24" fill="none" viewBox="0 0 24 24" stroke="rgba(255,255,255,0.95)" strokeWidth={1.8}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.18em', color: 'rgba(147,197,253,0.45)', display: 'block', marginBottom: 3, textTransform: 'uppercase' }}>
            One Threat at a time.
          </span>
          <h2 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', color: 'rgba(255,255,255,0.93)', margin: 0 }}>
            ThreatShield
          </h2>
        </div>

        {/* Divider */}
        <div style={{ height: 1, background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.07), transparent)', marginBottom: 24 }} />

        {/* Heading */}
        <div style={{ marginBottom: 18 }}>
          <p style={{ fontSize: 14, fontWeight: 600, color: 'rgba(255,255,255,0.8)', margin: '0 0 3px' }}>
            Sign in to continue
          </p>
          <p style={{ fontSize: 12.5, color: 'rgba(148,163,184,0.55)', margin: 0, lineHeight: 1.5 }}>
            Sign in with your Google account to continue
          </p>
        </div>

        {/* Error */}
        {error && (
          <div style={{
            marginBottom: 14,
            padding: '9px 13px',
            borderRadius: 10,
            background: 'rgba(239,68,68,0.07)',
            border: '1px solid rgba(239,68,68,0.18)',
            display: 'flex',
            alignItems: 'flex-start',
            gap: 8,
          }}>
            <svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="rgba(248,113,113,0.85)" strokeWidth={2} style={{ marginTop: 1, flexShrink: 0 }}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
            </svg>
            <span style={{ fontSize: 12, color: 'rgba(248,113,113,0.85)', lineHeight: 1.5 }}>{error}</span>
          </div>
        )}

        {/* Google Sign-In */}
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          opacity: submitting ? 0.5 : 1,
          pointerEvents: submitting ? 'none' : 'auto',
          transition: 'opacity 0.2s ease',
        }}>
          <GoogleLogin
            onSuccess={handleSuccess}
            onError={() => setError('Google sign-in failed. Please try again.')}
            useOneTap={false}
            theme="filled_black"
            size="large"
            text="signin_with"
            shape="rectangular"
            width="328"
          />
        </div>

        {/* Loading indicator */}
        {submitting && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 12 }}>
            <div style={{
              width: 13,
              height: 13,
              borderRadius: '50%',
              border: '2px solid rgba(59,130,246,0.25)',
              borderTopColor: 'rgba(59,130,246,0.85)',
              animation: 'spin 0.8s linear infinite',
            }} />
            <span style={{ fontSize: 12, color: 'rgba(148,163,184,0.55)' }}>Signing you in…</span>
          </div>
        )}

        {/* Feature list */}
        <div style={{ marginTop: 22, paddingTop: 18, borderTop: '1px solid rgba(255,255,255,0.05)', display: 'flex', flexDirection: 'column', gap: 9 }}>
          {AUTH_FEATURES.map((f, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 24, height: 24, borderRadius: 6,
                background: 'rgba(59,130,246,0.09)',
                border: '1px solid rgba(59,130,246,0.14)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0, color: 'rgba(96,165,250,0.75)',
              }}>
                <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  {f.icon}
                </svg>
              </div>
              <span style={{ fontSize: 12, color: 'rgba(148,163,184,0.5)', lineHeight: 1.4 }}>{f.label}</span>
            </div>
          ))}
        </div>

      </div>
    </div>
  );
};

/* ─── Section heading helper ──────────────────────────────────────────────── */
const SectionHeading: React.FC<{ eyebrow: string; title: string; sub?: string }> = ({ eyebrow, title, sub }) => (
  <div style={{ textAlign: 'center', marginBottom: 56 }}>
    <p style={{ fontFamily: MONO, fontSize: 10.5, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'rgba(96,165,250,0.7)', margin: '0 0 14px' }}>
      {eyebrow}
    </p>
    <h2 style={{ fontFamily: DISPLAY, fontSize: 34, fontWeight: 700, letterSpacing: '-0.02em', color: 'rgba(255,255,255,0.92)', margin: '0 0 12px' }}>
      {title}
    </h2>
    {sub && (
      <p style={{ fontSize: 14.5, color: 'rgba(148,163,184,0.65)', maxWidth: 520, margin: '0 auto', lineHeight: 1.7 }}>
        {sub}
      </p>
    )}
  </div>
);

const Divider: React.FC = () => (
  <div style={{ margin: '0 40px', height: 1, background: 'linear-gradient(to right, transparent, rgba(255,255,255,0.07), transparent)' }} />
);

const ShieldGlyph: React.FC = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

const GithubIcon: React.FC<{ size?: number }> = ({ size = 15 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 .5C5.7.5.5 5.7.5 12c0 5.1 3.3 9.4 7.9 10.9.6.1.8-.2.8-.5v-1.7c-3.2.7-3.9-1.5-3.9-1.5-.5-1.3-1.3-1.7-1.3-1.7-1.1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.7 1.3 3.4 1 .1-.8.4-1.3.7-1.6-2.6-.3-5.3-1.3-5.3-5.7 0-1.3.5-2.3 1.2-3.1-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0C17.3 4.7 18.3 5 18.3 5c.6 1.6.2 2.8.1 3.1.8.8 1.2 1.8 1.2 3.1 0 4.4-2.7 5.4-5.3 5.7.4.4.8 1.1.8 2.2v3.3c0 .3.2.6.8.5 4.6-1.5 7.9-5.8 7.9-10.9C23.5 5.7 18.3.5 12 .5z" />
  </svg>
);

const ArrowIcon: React.FC = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M5 12h14M12 5l7 7-7 7" />
  </svg>
);

/* ─── Landing page ────────────────────────────────────────────────────────── */
const LandingPage: React.FC = () => {
  const { user, loading } = useAuth();
  // Skip the intro loader when returning from the docs page (?skipLoader=1) or when an
  // in-app navigation set the sessionStorage flag (e.g. "go to dashboard" from the 404 page).
  // NOTE: keep this read pure (no removal) — removing here would break under StrictMode's
  // double render. The flag is cleared in an effect below instead.
  const [skipLoader] = useState(() => {
    if (typeof window === 'undefined') return false;
    if (new URLSearchParams(window.location.search).get('skipLoader') === '1') return true;
    try {
      return sessionStorage.getItem(SKIP_LANDING_LOADER_KEY) === '1';
    } catch (e) {
      return false;
    }
  });
  const [showLoader, setShowLoader] = useState(!skipLoader);
  const [showContent, setShowContent] = useState(skipLoader);

  // Consume the one-shot sessionStorage flag after mount.
  useEffect(() => {
    try { sessionStorage.removeItem(SKIP_LANDING_LOADER_KEY); } catch (e) { /* noop */ }
  }, []);
  const [showSignIn, setShowSignIn] = useState(false);
  const [selected, setSelected] = useState<keyof typeof NODE_DATA>('gw');
  const [showBoundaries, setShowBoundaries] = useState(true);
  const [cmdCopied, setCmdCopied] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    if (showLoader) {
      const timer = setTimeout(() => setShowLoader(false), 5000);
      return () => clearTimeout(timer);
    } else {
      setShowContent(true);
    }
  }, [showLoader]);

  // Load display fonts used by the landing design
  useEffect(() => {
    const links: HTMLLinkElement[] = [];
    const add = (href: string, crossorigin?: boolean) => {
      const l = document.createElement('link');
      l.rel = 'stylesheet';
      l.href = href;
      if (crossorigin) l.crossOrigin = 'anonymous';
      document.head.appendChild(l);
      links.push(l);
    };
    add('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
    return () => { links.forEach(l => l.remove()); };
  }, []);

  // Any CTA button opens the sign-in dialog
  const handleCTA = () => setShowSignIn(true);
  const handleClose = useCallback(() => setShowSignIn(false), []);
  const handleSignInSuccess = useCallback(() => {
    setShowSignIn(false);
    navigate('/home');
  }, [navigate]);

  const copyCmd = useCallback(() => {
    try { navigator.clipboard?.writeText(CLONE_CMD); } catch (e) { /* noop */ }
    setCmdCopied(true);
    setTimeout(() => setCmdCopied(false), 1600);
  }, []);

  // Already authenticated → skip straight to the app
  if (!loading && user) {
    return <Navigate to="/home" replace />;
  }

  const comp = NODE_DATA[selected];
  const ringCircumference = 2 * Math.PI * 44;
  const ringOffset = ringCircumference * (1 - comp.dread / 10);
  const ringColor = comp.dread >= 8 ? '#f3523c' : comp.dread >= 6 ? '#f99438' : comp.dread >= 4 ? '#60a5fa' : '#05c74f';

  const dread2bg = (d: number) =>
    d >= 8 ? 'rgba(243,82,60,0.18)' : d >= 6 ? 'rgba(249,148,56,0.18)' : d >= 4 ? 'rgba(59,130,246,0.18)' : 'rgba(5,199,79,0.18)';
  const dread2color = (d: number) =>
    d >= 8 ? '#f3523c' : d >= 6 ? '#f99438' : d >= 4 ? '#60a5fa' : '#05c74f';

  return (
    <div
      style={{
        minHeight: '100vh',
        background: 'linear-gradient(165deg, #04080f 0%, #080f1e 50%, #04080f 100%)',
        color: 'rgba(255,255,255,0.9)',
        overflowX: 'hidden',
        fontFamily: BODY,
        position: 'relative',
        zoom: 1.25, // counter the global `zoom: 0.8` (index.css) so the landing page renders at 100%
      }}
    >
      {showLoader && <LandingLoader />}

      {/* Dot-grid */}
      <div
        style={{
          position: 'fixed',
          inset: 0,
          backgroundImage: 'radial-gradient(circle, rgba(59,130,246,0.16) 1px, transparent 1px)',
          backgroundSize: '38px 38px',
          opacity: 0.28,
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />
      {/* Top glow */}
      <div
        style={{
          position: 'fixed',
          top: -200,
          left: '50%',
          width: 900,
          height: 600,
          transform: 'translateX(-50%)',
          background: 'radial-gradient(ellipse, rgba(59,130,246,0.10) 0%, transparent 65%)',
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />

      {/* Sign-in dialog */}
      {showSignIn && (
        <SignInDialog onClose={handleClose} onSuccess={handleSignInSuccess} />
      )}

      {/* Page content */}
      <div
        style={{
          position: 'relative',
          zIndex: 1,
          opacity: showContent ? 1 : 0,
          transition: 'opacity 0.9s ease',
        }}
      >
        {/* ── Navbar ─────────────────────────────────────── */}
        <nav
          style={{
            position: 'sticky',
            top: 0,
            zIndex: 50,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '16px 40px',
            borderBottom: '1px solid rgba(255,255,255,0.05)',
            backdropFilter: 'blur(16px)',
            background: 'rgba(4,8,15,0.7)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div
              style={{
                width: 30,
                height: 30,
                borderRadius: 9,
                background: 'linear-gradient(135deg, rgba(59,130,246,0.9) 0%, rgba(99,102,241,0.9) 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 0 0 1px rgba(96,165,250,0.3), 0 6px 18px rgba(37,99,235,0.4)',
              }}
            >
              <ShieldGlyph />
            </div>
            <span style={{ fontFamily: DISPLAY, fontSize: 17, fontWeight: 600, letterSpacing: '-0.01em', color: '#fff' }}>
              <span style={{ color: '#60a5fa' }}>Threat</span>Shield
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 32 }}>
            {NAV_LINKS.map((l) => (
              <a
                key={l.href}
                href={l.href}
                {...(l.external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
                style={{ fontSize: 13.5, color: 'rgba(148,163,184,0.8)', textDecoration: 'none' }}
                onMouseEnter={e => ((e.currentTarget as HTMLElement).style.color = '#fff')}
                onMouseLeave={e => ((e.currentTarget as HTMLElement).style.color = 'rgba(148,163,184,0.8)')}
              >
                {l.label}
              </a>
            ))}
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '8px 16px',
                borderRadius: 9,
                border: '1px solid rgba(255,255,255,0.1)',
                background: 'rgba(255,255,255,0.04)',
                color: 'rgba(255,255,255,0.92)',
                fontSize: 13,
                fontWeight: 500,
                textDecoration: 'none',
              }}
              onMouseEnter={e => {
                const el = e.currentTarget as HTMLElement;
                el.style.background = 'rgba(255,255,255,0.08)';
                el.style.borderColor = 'rgba(255,255,255,0.18)';
              }}
              onMouseLeave={e => {
                const el = e.currentTarget as HTMLElement;
                el.style.background = 'rgba(255,255,255,0.04)';
                el.style.borderColor = 'rgba(255,255,255,0.1)';
              }}
            >
              <GithubIcon />
              <span>GitHub</span>
            </a>
          </div>
        </nav>

        {/* ── Hero ───────────────────────────────────────── */}
        {/* Full-bleed so the gradient/glow/dot-grid span the whole viewport width,
            and tall enough that nav + hero + the divider below fill exactly one
            viewport — the next section ("the problem") starts under the fold.
            1vh == 1 screen vh here: this wrapper's zoom: 1.25 cancels html's
            zoom: 0.8. The extra height is background only; the content column
            below keeps its 1180px width and is centred in the leftover space. */}
        <section
          style={{
            position: 'relative',
            zIndex: 1,
            minHeight: `calc(100vh - ${NAV_HEIGHT + 1}px)`, // +1px for the Divider
            boxSizing: 'border-box',
            padding: '84px 40px 72px',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <div
            style={{
              width: '100%',
              maxWidth: 1180,
              margin: '0 auto',
              display: 'flex',
              alignItems: 'center',
              gap: 64,
              flexWrap: 'wrap',
            }}
          >
            <div style={{ flex: '1 1 440px' }}>
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '5px 14px',
                  borderRadius: 999,
                  border: '1px solid rgba(59,130,246,0.28)',
                  background: 'rgba(59,130,246,0.07)',
                  marginBottom: 26,
                }}
              >
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#3b82f6', boxShadow: '0 0 8px #3b82f6', animation: 'ts-pulse 2.4s ease-in-out infinite' }} />
                <span style={{ fontFamily: MONO, fontSize: 10.5, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'rgba(147,197,253,0.85)', whiteSpace: 'nowrap' }}>
                  open source · MIT licensed
                </span>
              </div>
              <h1 style={{ fontFamily: DISPLAY, fontSize: 58, fontWeight: 700, lineHeight: 1.05, letterSpacing: '-0.03em', margin: '0 0 22px' }}>
                <span style={{ color: 'rgba(255,255,255,0.95)' }}>threat modeling,</span>
                <br />
                <span style={{ background: 'linear-gradient(120deg, #93c5fd 10%, #3b82f6 90%)', WebkitBackgroundClip: 'text', backgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                  on autopilot.
                </span>
              </h1>
              <p style={{ fontSize: 16, lineHeight: 1.7, color: 'rgba(148,163,184,0.8)', margin: '0 0 34px', maxWidth: 480 }}>
                ThreatShield uses AI to map your architecture, surface real threats, and score risk in minutes — not the weeks a manual review takes. proactive security, built into your pipeline.
              </p>
              <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginBottom: 40 }}>
                <button
                  onClick={handleCTA}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 9,
                    padding: '14px 28px',
                    borderRadius: 11,
                    background: 'linear-gradient(135deg, #1d4ed8, #2563eb)',
                    border: '1px solid rgba(96,165,250,0.3)',
                    color: '#fff',
                    fontSize: 14.5,
                    fontWeight: 500,
                    cursor: 'pointer',
                    boxShadow: '0 0 28px rgba(59,130,246,0.3)',
                    transition: 'box-shadow 0.2s ease',
                  }}
                  onMouseEnter={e => ((e.currentTarget as HTMLElement).style.boxShadow = '0 0 40px rgba(59,130,246,0.5)')}
                  onMouseLeave={e => ((e.currentTarget as HTMLElement).style.boxShadow = '0 0 28px rgba(59,130,246,0.3)')}
                >
                  start a free assessment
                  <ArrowIcon />
                </button>
                <button
                  onClick={copyCmd}
                  title={CLONE_CMD}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 7,
                    padding: '8px 13px',
                    borderRadius: 9,
                    border: '1px solid rgba(255,255,255,0.12)',
                    background: 'rgba(255,255,255,0.03)',
                    color: 'rgba(255,255,255,0.8)',
                    fontSize: 11.5,
                    fontFamily: MONO,
                    cursor: 'pointer',
                    alignSelf: 'center',
                  }}
                  onMouseEnter={e => {
                    const el = e.currentTarget as HTMLElement;
                    el.style.borderColor = 'rgba(96,165,250,0.4)';
                    el.style.background = 'rgba(255,255,255,0.06)';
                  }}
                  onMouseLeave={e => {
                    const el = e.currentTarget as HTMLElement;
                    el.style.borderColor = 'rgba(255,255,255,0.12)';
                    el.style.background = 'rgba(255,255,255,0.03)';
                  }}
                >
                  <span style={{ color: 'rgba(96,165,250,0.7)' }}>$</span>
                  <span style={{ whiteSpace: 'nowrap' }}>{cmdCopied ? 'copied!' : 'git clone'}</span>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="9" y="9" width="13" height="13" rx="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                </button>
              </div>
              <div style={{ display: 'flex', gap: 44 }}>
                {HERO_STATS.map((s) => (
                  <div key={s.label}>
                    <div style={{ fontFamily: DISPLAY, fontSize: 30, fontWeight: 700, color: '#60a5fa', lineHeight: 1 }}>
                      {s.value}{s.suffix}
                    </div>
                    <div style={{ fontFamily: MONO, fontSize: 10, color: 'rgba(100,116,139,0.7)', letterSpacing: '0.1em', textTransform: 'uppercase', marginTop: 7 }}>
                      {s.label}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Hero preview card */}
            <div style={{ flex: '1 1 380px' }}>
              <div style={{ position: 'relative', overflow: 'hidden', ...card }}>
                <div style={{ position: 'absolute', top: -120, right: -90, width: 300, height: 300, borderRadius: '50%', background: 'radial-gradient(circle, rgba(99,102,241,0.18) 0%, transparent 65%)', pointerEvents: 'none' }} />
                <div style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', position: 'relative' }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#3b82f6', boxShadow: '0 0 8px #3b82f6', animation: 'ts-pulse 2.2s ease-in-out infinite' }} />
                  <span style={{ fontFamily: MONO, fontSize: 11, color: 'rgba(148,163,184,0.7)' }}>threatshield · assessment overview</span>
                  <span style={{ marginLeft: 'auto', fontFamily: MONO, fontSize: 10, color: 'rgba(96,165,250,0.8)' }}>payments-api</span>
                </div>
                <div style={{ padding: '24px 22px', position: 'relative', zIndex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 22, marginBottom: 22 }}>
                    <div style={{ position: 'relative', width: 122, height: 122, flexShrink: 0 }}>
                      <svg width="122" height="122" viewBox="0 0 132 132" style={{ transform: 'rotate(-90deg)' }}>
                        <defs>
                          <linearGradient id="tsRing" x1="0" y1="0" x2="1" y2="1">
                            <stop offset="0%" stopColor="#60a5fa" />
                            <stop offset="100%" stopColor="#818cf8" />
                          </linearGradient>
                        </defs>
                        <circle cx="66" cy="66" r="56" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="11" />
                        <circle cx="66" cy="66" r="56" fill="none" stroke="url(#tsRing)" strokeWidth="11" strokeLinecap="round" strokeDasharray="352" strokeDashoffset="92" style={{ animation: 'ts-ring 1.5s ease-out' }} />
                      </svg>
                      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                        <span style={{ fontFamily: DISPLAY, fontSize: 30, fontWeight: 700, color: '#fff', lineHeight: 1 }}>7.4</span>
                        <span style={{ fontFamily: MONO, fontSize: 8.5, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'rgba(148,163,184,0.7)', marginTop: 4 }}>avg DREAD</span>
                      </div>
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontFamily: MONO, fontSize: 9.5, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'rgba(100,116,139,0.7)', marginBottom: 13 }}>threat distribution</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
                        {([['critical', '88%', '#f3523c', 8], ['high', '70%', '#f99438', 7], ['medium', '48%', '#eab308', 5], ['low', '28%', '#05c74f', 3]] as [string, string, string, number][]).map(([lbl, w, c, n]) => (
                          <div key={lbl} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <span style={{ width: 54, fontSize: 10.5, color: 'rgba(148,163,184,0.8)' }}>{lbl}</span>
                            <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                              <div style={{ height: '100%', width: w, borderRadius: 3, background: c }} />
                            </div>
                            <span style={{ fontFamily: MONO, fontSize: 10.5, color: 'rgba(255,255,255,0.7)', width: 14, textAlign: 'right' }}>{n}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', marginBottom: 16 }} />
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 10, marginBottom: 16 }}>
                    {([['94%', 'ASVS coverage'], ['41', 'test cases'], ['18', 'mitigations']] as [string, string][]).map(([v, l]) => (
                      <div key={l} style={{ padding: '11px 12px', borderRadius: 11, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
                        <div style={{ fontFamily: DISPLAY, fontSize: 18, fontWeight: 700, color: '#60a5fa', lineHeight: 1 }}>{v}</div>
                        <div style={{ fontFamily: MONO, fontSize: 8, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'rgba(100,116,139,0.75)', marginTop: 6 }}>{l}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '11px 14px', borderRadius: 11, background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.22)' }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#a5b4fc" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M20 6 9 17l-5-5" />
                    </svg>
                    <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.85)' }}>2nd-pass critic cleared <span style={{ color: '#a5b4fc', fontWeight: 600 }}>3 false positives</span></span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <Divider />

        {/* ── Problem ────────────────────────────────────── */}
        <section style={{ position: 'relative', zIndex: 1, maxWidth: 1180, margin: '0 auto', padding: '84px 40px' }}>
          <SectionHeading
            eyebrow="the problem"
            title="manual threat modeling can't keep up"
            sub="whiteboard sessions and spreadsheets don't scale to the speed teams ship today. coverage slips, and threats reach production."
          />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, alignItems: 'stretch' }}>
            <div style={{ borderRadius: 16, padding: '32px 30px', background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(243,82,60,0.14)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
                <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(243,82,60,0.1)', border: '1px solid rgba(243,82,60,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f3523c" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" /></svg>
                </div>
                <span style={{ fontFamily: DISPLAY, fontSize: 15, fontWeight: 600, color: 'rgba(255,255,255,0.82)' }}>the old way</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {OLD_WAY.map((r) => (
                  <div key={r.title} style={{ display: 'flex', gap: 12 }}>
                    <span style={{ color: 'rgba(243,82,60,0.6)', flexShrink: 0 }}>✕</span>
                    <div>
                      <div style={{ fontSize: 13.5, color: 'rgba(255,255,255,0.8)', marginBottom: 3 }}>{r.title}</div>
                      <div style={{ fontSize: 12.5, color: 'rgba(100,116,139,0.7)', lineHeight: 1.6 }}>{r.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ borderRadius: 16, padding: '32px 30px', background: 'rgba(59,130,246,0.04)', border: '1px solid rgba(59,130,246,0.22)', boxShadow: '0 0 0 1px rgba(59,130,246,0.06), 0 30px 60px rgba(0,0,0,0.35)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
                <div style={{ width: 34, height: 34, borderRadius: 9, background: 'linear-gradient(135deg, rgba(59,130,246,0.9) 0%, rgba(99,102,241,0.9) 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 14px rgba(59,130,246,0.4)' }}>
                  <ShieldGlyph />
                </div>
                <span style={{ fontFamily: DISPLAY, fontSize: 15, fontWeight: 600, color: '#fff' }}>with ThreatShield</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {NEW_WAY.map((r) => (
                  <div key={r.title} style={{ display: 'flex', gap: 12 }}>
                    <span style={{ color: '#60a5fa', flexShrink: 0 }}>✓</span>
                    <div>
                      <div style={{ fontSize: 13.5, color: 'rgba(255,255,255,0.9)', marginBottom: 3 }}>{r.title}</div>
                      <div style={{ fontSize: 12.5, color: 'rgba(148,163,184,0.7)', lineHeight: 1.6 }}>{r.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <Divider />

        {/* ── Features ───────────────────────────────────── */}
        <section id="features" style={{ position: 'relative', zIndex: 1, maxWidth: 1180, margin: '0 auto', padding: '84px 40px' }}>
          <SectionHeading
            eyebrow="capabilities"
            title="everything a security review needs"
            sub="end-to-end assessment, from threat identification to test cases — automated and built to fit your existing workflow."
          />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))', gap: 18 }}>
            {FEATURES.map((f) => (
              <div
                key={f.title}
                style={{
                  borderRadius: 14,
                  padding: '28px 26px',
                  background: 'rgba(255,255,255,0.025)',
                  border: '1px solid rgba(255,255,255,0.07)',
                  backdropFilter: 'blur(16px)',
                  transition: 'border-color 0.25s ease, transform 0.25s ease',
                }}
                onMouseEnter={e => {
                  const el = e.currentTarget as HTMLElement;
                  el.style.borderColor = 'rgba(59,130,246,0.32)';
                  el.style.transform = 'translateY(-4px)';
                }}
                onMouseLeave={e => {
                  const el = e.currentTarget as HTMLElement;
                  el.style.borderColor = 'rgba(255,255,255,0.07)';
                  el.style.transform = 'translateY(0)';
                }}
              >
                <div
                  style={{
                    width: 40,
                    height: 40,
                    borderRadius: 10,
                    border: `1px solid ${f.accent ? 'rgba(99,102,241,0.25)' : 'rgba(59,130,246,0.2)'}`,
                    background: f.accent ? 'rgba(99,102,241,0.08)' : 'rgba(59,130,246,0.07)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginBottom: 16,
                  }}
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={f.accent ? '#a5b4fc' : '#93c5fd'} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
                    {f.icon}
                  </svg>
                </div>
                <h3 style={{ fontFamily: DISPLAY, fontSize: 16, fontWeight: 600, color: 'rgba(255,255,255,0.9)', margin: '0 0 9px' }}>{f.title}</h3>
                <p style={{ fontSize: 13, color: 'rgba(148,163,184,0.7)', lineHeight: 1.65, margin: 0 }}>{f.desc}</p>
              </div>
            ))}
          </div>
        </section>

        <Divider />

        {/* ── How it works ───────────────────────────────── */}
        <section id="how" style={{ position: 'relative', zIndex: 1, maxWidth: 1180, margin: '0 auto', padding: '84px 40px' }}>
          <SectionHeading
            eyebrow="how it works"
            title="six steps to a vetted threat model"
            sub="point ThreatShield at your system and let the pipeline do the heavy lifting — including a 2nd-pass critic that keeps every finding clean."
          />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
            {HOW_STEPS.map((s) => (
              <div
                key={s.num}
                style={{
                  position: 'relative',
                  borderRadius: 14,
                  padding: '26px 22px',
                  background: s.accent ? 'rgba(99,102,241,0.05)' : 'rgba(255,255,255,0.02)',
                  border: `1px solid ${s.accent ? 'rgba(99,102,241,0.25)' : 'rgba(255,255,255,0.07)'}`,
                }}
              >
                <div
                  style={{
                    width: 30,
                    height: 30,
                    borderRadius: '50%',
                    border: `1px solid ${s.accent ? 'rgba(99,102,241,0.4)' : 'rgba(59,130,246,0.35)'}`,
                    background: s.accent ? 'rgba(99,102,241,0.1)' : 'rgba(59,130,246,0.07)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontFamily: MONO,
                    fontSize: 11,
                    fontWeight: 600,
                    color: s.accent ? '#a5b4fc' : '#93c5fd',
                    marginBottom: 16,
                  }}
                >
                  {s.num}
                </div>
                <h3 style={{ fontFamily: DISPLAY, fontSize: 14.5, fontWeight: 600, color: 'rgba(255,255,255,0.88)', margin: '0 0 7px' }}>{s.title}</h3>
                <p style={{ fontSize: 12, color: s.accent ? 'rgba(148,163,184,0.7)' : 'rgba(100,116,139,0.75)', lineHeight: 1.6, margin: 0 }}>{s.desc}</p>
              </div>
            ))}
          </div>
        </section>

        <Divider />

        {/* ── Benefits ───────────────────────────────────── */}
        <section id="benefits" style={{ position: 'relative', zIndex: 1, maxWidth: 1180, margin: '0 auto', padding: '84px 40px' }}>
          <SectionHeading eyebrow="outcomes" title="what your team actually gains" />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 18 }}>
            {BENEFITS.map((b) => (
              <div key={b.title} style={{ borderRadius: 14, padding: '30px 26px', background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.07)' }}>
                <div style={{ fontFamily: DISPLAY, fontSize: 32, fontWeight: 700, color: '#60a5fa', lineHeight: 1, marginBottom: 14 }}>{b.value}</div>
                <h3 style={{ fontFamily: DISPLAY, fontSize: 15, fontWeight: 600, color: 'rgba(255,255,255,0.88)', margin: '0 0 7px' }}>{b.title}</h3>
                <p style={{ fontSize: 12.5, color: 'rgba(148,163,184,0.7)', lineHeight: 1.65, margin: 0 }}>{b.desc}</p>
              </div>
            ))}
          </div>
        </section>

        <Divider />

        {/* ── Interactive threat model ───────────────────── */}
        <section id="model" style={{ position: 'relative', zIndex: 1, maxWidth: 1180, margin: '0 auto', padding: '84px 40px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 64, flexWrap: 'wrap' }}>
            <div style={{ flex: '1 1 400px' }}>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '5px 14px', borderRadius: 999, border: '1px solid rgba(59,130,246,0.28)', background: 'rgba(59,130,246,0.07)', marginBottom: 22 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#3b82f6', boxShadow: '0 0 8px #3b82f6' }} />
                <span style={{ fontFamily: MONO, fontSize: 10.5, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'rgba(147,197,253,0.85)' }}>interactive threat model</span>
              </div>
              <h2 style={{ fontFamily: DISPLAY, fontSize: 34, fontWeight: 700, letterSpacing: '-0.02em', color: 'rgba(255,255,255,0.92)', margin: '0 0 14px' }}>
                explore your architecture as a living map
              </h2>
              <p style={{ fontSize: 14.5, color: 'rgba(148,163,184,0.72)', lineHeight: 1.7, margin: '0 0 26px', maxWidth: 480 }}>
                every assessment renders as an interactive canvas. drag components to lay out your system, click any node to see the threats mapped to it — ranked by DREAD — and overlay trust boundaries to see exactly where data crosses a line of trust.
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {([
                  { accent: false, title: 'draggable component nodes', desc: 'rearrange the data-flow diagram to match how you reason about the system.', icon: <path d="M5 9l-3 3 3 3M9 5l3-3 3 3M15 19l-3 3-3-3M19 9l3 3-3 3M2 12h20M12 2v20" /> },
                  { accent: true, title: 'toggleable trust boundaries', desc: 'overlay the zones where trust changes hands and watch which flows cross them.', icon: <><rect x="3" y="3" width="18" height="18" rx="3" strokeDasharray="4 3" /><path d="M12 3v18" /></> },
                  { accent: false, title: 'per-component DREAD scoring', desc: 'each node carries a colour-coded risk badge, STRIDE or PASTA, switchable on the fly.', icon: <><path d="M12 2a10 10 0 1 0 10 10" /><path d="M12 12V6" /><path d="M12 12l4 2" /></> },
                ]).map((it) => (
                  <div key={it.title} style={{ display: 'flex', gap: 13 }}>
                    <div style={{ width: 30, height: 30, flexShrink: 0, borderRadius: 8, border: `1px solid ${it.accent ? 'rgba(99,102,241,0.3)' : 'rgba(59,130,246,0.22)'}`, background: it.accent ? 'rgba(99,102,241,0.08)' : 'rgba(59,130,246,0.07)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={it.accent ? '#a5b4fc' : '#93c5fd'} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        {it.icon}
                      </svg>
                    </div>
                    <div>
                      <div style={{ fontSize: 13.5, fontWeight: 600, color: 'rgba(255,255,255,0.9)', marginBottom: 3 }}>{it.title}</div>
                      <div style={{ fontSize: 12.5, color: 'rgba(148,163,184,0.7)', lineHeight: 1.6 }}>{it.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ flex: '1 1 400px' }}>
              <div style={{ position: 'relative', maxWidth: 460, margin: '0 auto', overflow: 'hidden', ...card }}>
                <div style={{ position: 'absolute', top: -120, right: -90, width: 300, height: 300, borderRadius: '50%', background: 'radial-gradient(circle, rgba(99,102,241,0.18) 0%, transparent 65%)', pointerEvents: 'none' }} />
                <div style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '13px 18px', borderBottom: '1px solid rgba(255,255,255,0.06)', position: 'relative' }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#3b82f6', boxShadow: '0 0 8px #3b82f6', animation: 'ts-pulse 2.2s ease-in-out infinite' }} />
                  <span style={{ fontFamily: MONO, fontSize: 11, color: 'rgba(148,163,184,0.7)' }}>threatshield · interactive model</span>
                  <button
                    onClick={() => setShowBoundaries(v => !v)}
                    style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 7, padding: '5px 10px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.09)', cursor: 'pointer', fontFamily: MONO, fontSize: 9.5, letterSpacing: '0.04em', color: '#a5b4fc' }}
                    onMouseEnter={e => ((e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.16)')}
                    onMouseLeave={e => ((e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.09)')}
                  >
                    <span style={{ width: 5, height: 5, borderRadius: '50%', background: showBoundaries ? '#6366f1' : 'rgba(148,163,184,0.5)' }} />
                    trust boundaries · {showBoundaries ? 'on' : 'off'}
                  </button>
                </div>

                <div style={{ position: 'relative', zIndex: 1, padding: '18px 30px 6px' }}>
                  <div style={{ position: 'relative', width: 380, height: 262, margin: '0 auto', backgroundImage: 'radial-gradient(circle, rgba(148,163,184,0.16) 1px, transparent 1px)', backgroundSize: '22px 22px' }}>
                    {showBoundaries && (
                      <>
                        <div style={{ position: 'absolute', left: 108, top: 2, width: 164, height: 86, border: '1.5px dashed #3b82f6', borderRadius: 11, background: 'rgba(59,130,246,0.04)', zIndex: 0 }}>
                          <span style={{ position: 'absolute', top: -10, left: 12, padding: '2px 8px', borderRadius: 4, background: '#3b82f6', color: '#fff', fontFamily: MONO, fontSize: 8.5, fontWeight: 600, whiteSpace: 'nowrap' }}>public edge</span>
                        </div>
                        <div style={{ position: 'absolute', left: 0, top: 98, width: 380, height: 164, border: '1.5px dashed #10b981', borderRadius: 11, background: 'rgba(16,185,129,0.04)', zIndex: 0 }}>
                          <span style={{ position: 'absolute', top: -10, left: 12, padding: '2px 8px', borderRadius: 4, background: '#10b981', color: '#04130d', fontFamily: MONO, fontSize: 8.5, fontWeight: 600, whiteSpace: 'nowrap' }}>internal network</span>
                        </div>
                      </>
                    )}

                    <svg width="380" height="262" style={{ position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 1 }}>
                      <line x1="190" y1="70" x2="190" y2="108" stroke="rgba(148,163,184,0.4)" strokeWidth="1.5" strokeDasharray="4 4" />
                      <line x1="190" y1="164" x2="78" y2="190" stroke="rgba(148,163,184,0.4)" strokeWidth="1.5" strokeDasharray="4 4" />
                      <line x1="190" y1="164" x2="302" y2="190" stroke="rgba(148,163,184,0.4)" strokeWidth="1.5" strokeDasharray="4 4" />
                    </svg>

                    {(Object.keys(NODE_DATA) as (keyof typeof NODE_DATA)[]).map((id) => {
                      const n = NODE_DATA[id];
                      const isSel = selected === id;
                      return (
                        <div
                          key={id}
                          onClick={() => setSelected(id)}
                          style={{ position: 'absolute', ...n.pos, width: 128, padding: '9px 11px', borderRadius: 10, background: 'rgba(20,30,48,0.97)', border: '1.5px solid rgba(255,255,255,0.12)', boxShadow: '0 6px 16px rgba(0,0,0,0.4)', cursor: 'pointer', zIndex: 2 }}
                          onMouseEnter={e => { if (!isSel) (e.currentTarget as HTMLElement).style.borderColor = 'rgba(96,165,250,0.6)'; }}
                          onMouseLeave={e => { if (!isSel) (e.currentTarget as HTMLElement).style.borderColor = 'rgba(255,255,255,0.12)'; }}
                        >
                          {isSel && <div style={{ position: 'absolute', inset: -3, borderRadius: 13, border: '2px solid #60a5fa', boxShadow: '0 0 18px rgba(96,165,250,0.6)', pointerEvents: 'none' }} />}
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6 }}>
                            <span style={{ fontSize: 11, fontWeight: 600, color: 'rgba(255,255,255,0.92)', whiteSpace: 'nowrap' }}>{n.label}</span>
                            <span style={{ fontFamily: MONO, fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 999, background: dread2bg(n.dread), color: dread2color(n.dread), flexShrink: 0 }}>{n.dread.toFixed(1)}</span>
                          </div>
                          <span style={{ marginTop: 6, display: 'inline-block', fontFamily: MONO, fontSize: 8, padding: '1px 6px', borderRadius: 999, background: 'rgba(59,130,246,0.14)', color: '#93c5fd', whiteSpace: 'nowrap' }}>{n.type}</span>
                        </div>
                      );
                    })}
                  </div>
                  <p style={{ textAlign: 'center', fontFamily: MONO, fontSize: 9, letterSpacing: '0.08em', color: 'rgba(100,116,139,0.6)', margin: '10px 0 0' }}>click a node to inspect its threats</p>
                </div>

                <div style={{ position: 'relative', zIndex: 1, padding: '14px 22px 22px' }}>
                  <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', marginBottom: 18 }} />
                  <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
                    <div style={{ position: 'relative', width: 98, height: 98, flexShrink: 0 }}>
                      <svg width="98" height="98" viewBox="0 0 110 110" style={{ transform: 'rotate(-90deg)' }}>
                        <circle cx="55" cy="55" r="44" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="9" />
                        <circle cx="55" cy="55" r="44" fill="none" stroke={ringColor} strokeWidth="9" strokeLinecap="round" strokeDasharray={ringCircumference.toFixed(1)} strokeDashoffset={ringOffset.toFixed(1)} style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.4s ease' }} />
                      </svg>
                      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                        <span style={{ fontFamily: DISPLAY, fontSize: 25, fontWeight: 700, color: '#fff', lineHeight: 1 }}>{comp.dread.toFixed(1)}</span>
                        <span style={{ fontFamily: MONO, fontSize: 7.5, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'rgba(148,163,184,0.7)', marginTop: 3 }}>DREAD</span>
                      </div>
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 11 }}>
                        <span style={{ fontFamily: DISPLAY, fontSize: 15, fontWeight: 600, color: 'rgba(255,255,255,0.92)' }}>{comp.label}</span>
                        <span style={{ fontFamily: MONO, fontSize: 8.5, color: 'rgba(100,116,139,0.8)' }}>{comp.threats.length} threats</span>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                        {comp.threats.map(([type, sev, d]) => (
                          <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 9, animation: 'ts-fade 0.3s ease' }}>
                            <span style={{ fontFamily: MONO, fontSize: 8, fontWeight: 600, padding: '2px 6px', borderRadius: 5, letterSpacing: '0.04em', textTransform: 'uppercase', flexShrink: 0, background: SEV[sev].bg, color: SEV[sev].color }}>{sev}</span>
                            <span style={{ flex: 1, fontSize: 11.5, color: 'rgba(255,255,255,0.82)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{type}</span>
                            <span style={{ fontFamily: MONO, fontSize: 10.5, color: 'rgba(148,163,184,0.85)', flexShrink: 0 }}>{d.toFixed(1)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── Docs / CTA ─────────────────────────────────── */}
        <section id="docs" style={{ position: 'relative', zIndex: 1, maxWidth: 1180, margin: '0 auto', padding: '40px 40px 96px' }}>
          <div style={{ position: 'relative', borderRadius: 20, padding: '64px 48px', textAlign: 'center', background: 'rgba(59,130,246,0.04)', border: '1px solid rgba(59,130,246,0.18)', overflow: 'hidden' }}>
            <div style={{ position: 'absolute', width: 560, height: 280, borderRadius: '50%', background: 'radial-gradient(ellipse, rgba(59,130,246,0.1) 0%, transparent 70%)', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', pointerEvents: 'none' }} />
            <div style={{ position: 'relative', zIndex: 1 }}>
              <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 56, height: 56, borderRadius: 16, background: 'linear-gradient(135deg, rgba(59,130,246,0.9) 0%, rgba(99,102,241,0.9) 100%)', boxShadow: '0 0 0 1px rgba(96,165,250,0.35), 0 10px 30px rgba(59,130,246,0.35)', marginBottom: 24 }}>
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              </div>
              <h2 style={{ fontFamily: DISPLAY, fontSize: 36, fontWeight: 700, letterSpacing: '-0.02em', color: 'rgba(255,255,255,0.94)', margin: '0 0 14px' }}>secure your application today</h2>
              <p style={{ fontSize: 15, color: 'rgba(148,163,184,0.7)', maxWidth: 480, margin: '0 auto 32px', lineHeight: 1.7 }}>
                free, open source, and self-hostable. get a complete threat model for your first service in under ten minutes.
              </p>
              <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', justifyContent: 'center', marginBottom: 24 }}>
                <button
                  onClick={handleCTA}
                  style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '14px 30px', borderRadius: 11, background: 'linear-gradient(135deg, #1d4ed8, #2563eb)', border: '1px solid rgba(96,165,250,0.3)', color: '#fff', fontSize: 14.5, fontWeight: 500, cursor: 'pointer', boxShadow: '0 0 28px rgba(59,130,246,0.3)' }}
                  onMouseEnter={e => ((e.currentTarget as HTMLElement).style.boxShadow = '0 0 40px rgba(59,130,246,0.5)')}
                  onMouseLeave={e => ((e.currentTarget as HTMLElement).style.boxShadow = '0 0 28px rgba(59,130,246,0.3)')}
                >
                  begin assessment <ArrowIcon />
                </button>
                <a
                  href={GITHUB_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '14px 26px', borderRadius: 11, border: '1px solid rgba(255,255,255,0.14)', background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.9)', fontSize: 14, fontWeight: 500, textDecoration: 'none' }}
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
                  <GithubIcon size={16} />star on GitHub
                </a>
              </div>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 10, padding: '10px 16px', borderRadius: 10, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(4,8,15,0.5)', fontFamily: MONO, fontSize: 13, color: 'rgba(255,255,255,0.8)' }}>
                <span style={{ color: 'rgba(96,165,250,0.7)' }}>$</span> {CLONE_CMD}
              </div>
            </div>
          </div>
        </section>

        {/* ── Footer ─────────────────────────────────────── */}
        <footer style={{ position: 'relative', zIndex: 1, borderTop: '1px solid rgba(255,255,255,0.05)', padding: '40px 40px 48px' }}>
          <div style={{ maxWidth: 1180, margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 26, height: 26, borderRadius: 8, background: 'linear-gradient(135deg, rgba(59,130,246,0.9) 0%, rgba(99,102,241,0.9) 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              </div>
              <span style={{ fontFamily: DISPLAY, fontSize: 14, fontWeight: 600, color: 'rgba(255,255,255,0.75)' }}><span style={{ color: '#60a5fa' }}>Threat</span>Shield</span>
            </div>
            <div style={{ display: 'flex', gap: 28, flexWrap: 'wrap' }}>
              {([['features', '#features'], ['docs', API_DOCS_URL], ['GitHub', GITHUB_URL]] as [string, string][]).map(([label, href]) => {
                const external = href.startsWith('http') || href.endsWith('.html');
                return (
                  <a
                    key={label}
                    href={href}
                    {...(external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
                    style={{ fontSize: 12.5, color: 'rgba(148,163,184,0.6)', textDecoration: 'none' }}
                    onMouseEnter={e => ((e.currentTarget as HTMLElement).style.color = '#fff')}
                    onMouseLeave={e => ((e.currentTarget as HTMLElement).style.color = 'rgba(148,163,184,0.6)')}
                  >
                    {label}
                  </a>
                );
              })}
            </div>
            <p style={{ fontFamily: MONO, fontSize: 10.5, color: 'rgba(100,116,139,0.45)', letterSpacing: '0.06em', margin: 0 }}>MIT licensed · threatshield 2026</p>
          </div>
        </footer>
      </div>

      <style>{`
        @keyframes fadeIn   { from { opacity: 0 } to { opacity: 1 } }
        @keyframes slideUp  { from { opacity: 0; transform: translateY(16px) } to { opacity: 1; transform: translateY(0) } }
        @keyframes spin     { to   { transform: rotate(360deg) } }
        @keyframes ts-pulse { 0%,100% { opacity: 0.4; transform: scale(1) } 50% { opacity: 1; transform: scale(1.12) } }
        @keyframes ts-ring  { from { stroke-dashoffset: 352 } }
        @keyframes ts-fade  { from { opacity: 0; transform: translateY(6px) } to { opacity: 1; transform: translateY(0) } }
      `}</style>
    </div>
  );
};

export default LandingPage;
