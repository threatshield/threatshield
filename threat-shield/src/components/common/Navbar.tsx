import React, { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext';
import { useNavbar } from '../../context/NavbarContext';
import { useAuth } from '../../context/AuthContext';
import { API_BASE_URL } from '../../services/api';

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  matchPaths?: string[];
  badge?: number;
}

const ShieldIcon = () => (
  <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const NAV_ITEMS: NavItem[] = [
  {
    to: '/home',
    label: 'Home',
    matchPaths: ['/home'],
    icon: (
      <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
      </svg>
    ),
  },
  {
    to: '/department-threat-models',
    label: 'Threat Models',
    matchPaths: ['/department-threat-models'],
    icon: (
      <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
      </svg>
    ),
  },
  {
    to: '/threat-models',
    label: 'Sub Threat Models',
    matchPaths: ['/threat-models', '/view-threat-model/'],
    icon: <ShieldIcon />,
  },
  {
    to: '/queue',
    label: 'Queue',
    matchPaths: ['/queue'],
    icon: (
      <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
      </svg>
    ),
  },
  {
    to: '/analytics',
    label: 'Analytics',
    matchPaths: ['/analytics'],
    icon: (
      <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    ),
  },
  {
    to: '/metrics',
    label: 'Metrics',
    matchPaths: ['/metrics'],
    icon: (
      <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M16 8v8m-4-5v5m-4-2v2M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
      </svg>
    ),
  },
];

const BOTTOM_NAV_ITEMS: NavItem[] = [
  {
    to: '/integrations',
    label: 'Integrations',
    matchPaths: ['/integrations'],
    icon: (
      <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
  },
  {
    to: '/feedback',
    label: 'Feedback',
    matchPaths: ['/feedback'],
    icon: (
      <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
      </svg>
    ),
  },
];

const ASSESSMENT_SUB_ITEMS = [
  {
    key: 'view-threat-model',
    label: 'Threat Model',
    activeClass: 'bg-emerald-900/30 text-emerald-300',
    inactiveClass: 'text-emerald-400/70 hover:bg-emerald-900/20 hover:text-emerald-300',
    icon: <ShieldIcon />,
  },
  {
    key: 'dread',
    label: 'DREAD',
    activeClass: 'bg-amber-900/30 text-amber-300',
    inactiveClass: 'text-amber-400/70 hover:bg-amber-900/20 hover:text-amber-300',
    icon: (
      <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    ),
  },
  {
    key: 'mitigation',
    label: 'Mitigation',
    activeClass: 'bg-rose-900/30 text-rose-300',
    inactiveClass: 'text-rose-400/70 hover:bg-rose-900/20 hover:text-rose-300',
    icon: (
      <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
  {
    key: 'attack-tree',
    label: 'Attack Tree',
    activeClass: 'bg-violet-900/30 text-violet-300',
    inactiveClass: 'text-violet-400/70 hover:bg-violet-900/20 hover:text-violet-300',
    icon: (
      <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
      </svg>
    ),
  },
];

const Navbar: React.FC = () => {
  const location = useLocation();
  const params = useParams<{ assessment_id?: string }>();
  const navigate = useNavigate();
  const { isDark, toggleDark } = useTheme();
  const { isCollapsed, toggleCollapse } = useNavbar();
  const { user, logout, isMcpAdmin } = useAuth();
  const [pendingFeedbackCount, setPendingFeedbackCount] = useState(0);

  useEffect(() => {
    if (!user) return;
    fetch(`${API_BASE_URL}/feedback`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.feedbacks) {
          setPendingFeedbackCount(data.feedbacks.filter((f: any) => !f.submitted).length);
        }
      })
      .catch(() => {});
  }, [user, location.pathname]);

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  const isActive = (item: NavItem) => {
    if (!item.matchPaths) return false;
    return item.matchPaths.some(p =>
      p.endsWith('/') ? location.pathname.startsWith(p) : location.pathname === p
    );
  };

  const isAssessmentRoute = /\/(threat-model|view-threat-model|dread|mitigation|attack-tree)\//.test(location.pathname);
  const assessmentId = params.assessment_id;

  // NavLink — renders icon only when collapsed, icon+label when expanded
  const NavLink: React.FC<{ item: NavItem }> = ({ item }) => {
    const active = isActive(item);
    return (
      <Link
        to={item.to}
        title={isCollapsed ? item.label : undefined}
        className={`relative flex items-center gap-3 rounded-lg text-sm font-medium transition-all duration-150 group ${
          isCollapsed ? 'px-0 py-2.5 justify-center' : 'px-3 py-2.5'
        } ${active ? 'bg-white/10 text-white' : 'text-blue-200/60 hover:bg-white/6 hover:text-white'}`}
      >
        {!isCollapsed && (
          <span className={`absolute left-0 w-0.5 h-5 rounded-r-full bg-blue-300 transition-opacity duration-150 ${active ? 'opacity-100' : 'opacity-0'}`} />
        )}
        <span className={`relative flex-shrink-0 transition-colors duration-150 ${active ? 'text-white' : 'text-blue-300/50 group-hover:text-blue-200'}`}>
          {item.icon}
          {/* Collapsed badge — dot with count */}
          {isCollapsed && item.badge != null && item.badge > 0 && (
            <span className="absolute -top-1 -right-1 min-w-[14px] h-[14px] px-0.5 rounded-full bg-red-500 text-white text-[9px] font-bold flex items-center justify-center leading-none">
              {item.badge > 9 ? '9+' : item.badge}
            </span>
          )}
        </span>
        {!isCollapsed && item.label}

        {/* Expanded badge */}
        {!isCollapsed && item.badge != null && item.badge > 0 && (
          <span className="ml-auto min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center leading-none">
            {item.badge > 99 ? '99+' : item.badge}
          </span>
        )}

        {/* Tooltip on collapsed */}
        {isCollapsed && (
          <span className="absolute left-full ml-3 px-2 py-1 bg-gray-900 text-white text-xs rounded-md whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity duration-150 z-50 shadow-lg border border-white/10">
            {item.label}{item.badge != null && item.badge > 0 ? ` (${item.badge} pending)` : ''}
          </span>
        )}
      </Link>
    );
  };

  return (
    <nav
      className={`fixed left-0 top-0 bottom-0 z-[9999] flex flex-col overflow-y-auto overflow-x-hidden transition-all duration-300 ${isCollapsed ? 'w-16' : 'w-64'}`}
      style={{ background: 'linear-gradient(180deg, #0a1628 0%, #0d1f3c 100%)', borderRight: '1px solid rgba(255,255,255,0.06)' }}
    >
      {/* Logo + Collapse toggle */}
      <div
        className={`flex items-center border-b flex-shrink-0 transition-all duration-300 ${isCollapsed ? 'justify-center px-0 py-[18px]' : 'justify-between px-4 py-[18px]'}`}
        style={{ borderColor: 'rgba(255,255,255,0.06)' }}
      >
        {!isCollapsed && (
          <Link to="/home" className="flex items-center gap-2.5 min-w-0">
            <div className="w-7 h-7 rounded-lg bg-[#0052cc] flex items-center justify-center shadow-lg shadow-blue-900/50 flex-shrink-0">
              <svg style={{ width: 14, height: 14 }} fill="none" viewBox="0 0 24 24" stroke="white" strokeWidth={2.2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <span className="text-[15px] font-bold text-white tracking-tight whitespace-nowrap">
              <span className="text-blue-300">Threat</span>Shield
            </span>
          </Link>
        )}
        {isCollapsed && (
          <Link to="/home" title="ThreatShield">
            <div className="w-7 h-7 rounded-lg bg-[#0052cc] flex items-center justify-center shadow-lg shadow-blue-900/50">
              <svg style={{ width: 14, height: 14 }} fill="none" viewBox="0 0 24 24" stroke="white" strokeWidth={2.2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
          </Link>
        )}
        {!isCollapsed && (
          <button
            onClick={toggleCollapse}
            title="Collapse sidebar"
            className="w-6 h-6 rounded-md flex items-center justify-center text-blue-300/50 hover:text-white hover:bg-white/10 transition-all duration-150 flex-shrink-0"
          >
            <svg style={{ width: 14, height: 14 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
            </svg>
          </button>
        )}
      </div>

      {/* Expand button when collapsed */}
      {isCollapsed && (
        <div className="flex justify-center pt-3 flex-shrink-0">
          <button
            onClick={toggleCollapse}
            title="Expand sidebar"
            className="w-7 h-7 rounded-md flex items-center justify-center text-blue-300/40 hover:text-white hover:bg-white/10 transition-all duration-150"
          >
            <svg style={{ width: 14, height: 14 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 5l7 7-7 7M5 5l7 7-7 7" />
            </svg>
          </button>
        </div>
      )}

      {/* Main nav */}
      <div className={`flex-1 py-4 space-y-0.5 ${isCollapsed ? 'px-2' : 'px-3'}`}>
        {!isCollapsed && (
          <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-widest" style={{ color: 'rgba(147,197,253,0.35)' }}>Navigation</p>
        )}
        {NAV_ITEMS.map(item => (
          <NavLink key={item.to} item={item} />
        ))}

        {/* Assessment sub-nav — only show when expanded */}
        {!isCollapsed && isAssessmentRoute && assessmentId && (
          <div className="pt-4 mt-2" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-widest" style={{ color: 'rgba(147,197,253,0.35)' }}>Current Assessment</p>
            {ASSESSMENT_SUB_ITEMS.map(sub => {
              const to = `/${sub.key}/${assessmentId}`;
              const active = location.pathname === to;
              return (
                <Link
                  key={sub.key}
                  to={to}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                    active ? sub.activeClass : sub.inactiveClass
                  }`}
                >
                  <span className="flex-shrink-0 opacity-80">{sub.icon}</span>
                  {sub.label}
                </Link>
              );
            })}
          </div>
        )}
      </div>

      {/* Bottom section */}
      <div
        className={`flex-shrink-0 pb-4 pt-3 space-y-0.5 ${isCollapsed ? 'px-2' : 'px-3'}`}
        style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
      >
        {BOTTOM_NAV_ITEMS.map(item => (
          <NavLink
            key={item.to}
            item={item.to === '/feedback' ? { ...item, badge: pendingFeedbackCount } : item}
          />
        ))}

        {/* Admin — only visible to MCP admins */}
        {isMcpAdmin && (
          <NavLink
            item={{
              to: '/admin',
              label: 'Admin',
              matchPaths: ['/admin'],
              icon: (
                <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0zm6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              ),
            }}
          />
        )}

        {/* Dark mode toggle */}
        {isCollapsed ? (
          <button
            onClick={toggleDark}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            className="w-full flex justify-center py-2.5 text-blue-300/50 hover:text-white hover:bg-white/10 rounded-lg transition-all duration-150"
          >
            {isDark ? (
              <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
              </svg>
            ) : (
              <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
            )}
          </button>
        ) : (
          <div className="mt-1 flex items-center justify-between px-3 py-2.5 rounded-lg">
            <span className="flex items-center gap-3 text-sm font-medium" style={{ color: 'rgba(191,219,254,0.6)' }}>
              {isDark ? (
                <svg style={{ width: 17, height: 17, color: 'rgba(147,197,253,0.5)' }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
              ) : (
                <svg style={{ width: 17, height: 17, color: 'rgba(147,197,253,0.5)' }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              )}
              Dark Mode
            </span>
            <button
              onClick={toggleDark}
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-offset-1 ${
                isDark ? 'bg-[#0052cc]' : 'bg-white/20'
              }`}
              aria-label="Toggle dark mode"
            >
              <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-sm transition-transform duration-200 ${isDark ? 'translate-x-[18px]' : 'translate-x-[3px]'}`} />
            </button>
          </div>
        )}
      </div>

      {/* User profile + logout */}
      {user && (
        <div
          className={`flex-shrink-0 pb-3 pt-2 ${isCollapsed ? 'px-2' : 'px-3'}`}
          style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
        >
          {isCollapsed ? (
            <button
              onClick={handleLogout}
              title="Sign out"
              className="w-full flex justify-center py-2.5 text-blue-300/50 hover:text-red-400 hover:bg-white/10 rounded-lg transition-all duration-150"
            >
              <svg style={{ width: 17, height: 17 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          ) : (
            <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg">
              {user.picture ? (
                <img src={user.picture} alt={user.name} className="w-7 h-7 rounded-full flex-shrink-0" referrerPolicy="no-referrer" />
              ) : (
                <div className="w-7 h-7 rounded-full flex-shrink-0 bg-blue-600 flex items-center justify-center text-white text-xs font-semibold">
                  {user.name.charAt(0).toUpperCase()}
                </div>
              )}
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-blue-100 truncate">{user.name}</p>
                <p className="text-xs text-blue-300/40 truncate">{user.email}</p>
              </div>
              <button
                onClick={handleLogout}
                title="Sign out"
                className="flex-shrink-0 p-1 rounded text-blue-300/40 hover:text-red-400 hover:bg-white/10 transition-all duration-150"
              >
                <svg style={{ width: 15, height: 15 }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
              </button>
            </div>
          )}
        </div>
      )}
    </nav>
  );
};

export default Navbar;
