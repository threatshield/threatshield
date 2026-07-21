import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation, Navigate, Link } from 'react-router-dom';
import { AssessmentProvider } from './context/AssessmentContext';
import { ThemeProvider } from './context/ThemeContext';
import { NavbarProvider, useNavbar } from './context/NavbarContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { API_BASE_URL } from './services/api';
import ProtectedRoute from './components/common/ProtectedRoute';
import Navbar from './components/common/Navbar';
import LoginPage from './pages/LoginPage';
import Home from './pages/Home';
import LandingPage from './pages/LandingPage';
import NotFound from './pages/NotFound';
import ThreatModel from './pages/ThreatModel';
import ViewThreatModel from './pages/ViewThreatModel';
import InteractiveThreatModel from './pages/InteractiveThreatModel';
import Dread from './pages/Dread';
import Mitigation from './pages/Mitigation';
import AttackTree from './pages/AttackTree';
import Chat from './pages/Chat';
import Report from './pages/Report';
import ReportList from './pages/ReportList';
import ThreatModelList from './pages/ThreatModelList';
import TeamThreatModels from './pages/TeamThreatModels';
import DepartmentThreatModelDetail from './pages/DepartmentThreatModelDetail';
import DepartmentThreats from './pages/DepartmentThreats';
import CustomDepartmentDetail from './pages/CustomDepartmentDetail';
import Analytics from './pages/Analytics';
import Metrics from './pages/Metrics';
import Integrations from './pages/Integrations';
import ViewSecurityTestCases from './pages/ViewSecurityTestCases';
import TmBom from './pages/TmBom';
import Queue from './pages/Queue';
import FeedbackPage from './pages/FeedbackPage';
import FeedbackList from './pages/FeedbackList';
import AdminDashboard from './pages/AdminDashboard';

// ── Model status banner ───────────────────────────────────────────────────────
const ModelStatusBanner: React.FC = () => {
  const { user, isMcpAdmin } = useAuth();
  const location = useLocation();
  const [configured, setConfigured] = useState<boolean | null>(null);

  useEffect(() => {
    if (!user) return;
    fetch(`${API_BASE_URL}/model-status`)
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) setConfigured(data.configured); })
      .catch(() => {});
  }, [user, location.pathname]);  // re-check on every route change

  if (!user || configured !== false) return null;

  return (
    <div className="w-full bg-amber-500/90 dark:bg-amber-600/80 text-white text-xs font-medium flex items-center justify-center gap-2 py-1.5 px-4 z-50">
      <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
      <span>LLM model is not configured — threat analysis will not work.</span>
      {isMcpAdmin && (
        <Link
          to="/admin?tab=settings"
          className="underline underline-offset-2 font-semibold hover:text-amber-100 transition-colors ml-1"
        >
          Configure in Settings →
        </Link>
      )}
      {!isMcpAdmin && (
        <span className="ml-1 opacity-80">Contact an admin to configure the model.</span>
      )}
    </div>
  );
};

// Wrapper component to conditionally show navbar
const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation();
  const [showNavbar, setShowNavbar] = useState(false);
  const { isCollapsed, navbarHidden } = useNavbar();

  useEffect(() => {
    const noNavbarRoutes = ['/', '/landing'];
    const isNoNavbar =
      noNavbarRoutes.includes(location.pathname) ||
      location.pathname.startsWith('/provide-feedback/');
    setShowNavbar(!isNoNavbar);
  }, [location]);

  // A page (e.g. the 404 page) can force the navbar off regardless of the route.
  const navbarVisible = showNavbar && !navbarHidden;

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#0a1628] dark-grid-bg">
      {navbarVisible && <Navbar />}
      <main
        className={navbarVisible ? `transition-all duration-300 ${isCollapsed ? 'ml-16' : 'ml-64'}` : ''}
      >
        {navbarVisible && <ModelStatusBanner />}
        {children}
      </main>
    </div>
  );
};

const App: React.FC = () => {
  return (
    <Router>
      <ThemeProvider>
        <NavbarProvider>
          <AuthProvider>
            <AssessmentProvider>
              <AppLayout>
                <Routes>
                  {/* Public routes */}
                  <Route path="/" element={<LandingPage />} />
                  <Route path="/login" element={<Navigate to="/" replace />} />

                  {/* Protected routes */}
                  <Route path="/home" element={<ProtectedRoute><Home /></ProtectedRoute>} />
                  <Route path="/threat-model/:assessment_id" element={<ProtectedRoute><ThreatModel /></ProtectedRoute>} />
                  <Route path="/dread/:assessment_id" element={<ProtectedRoute><Dread /></ProtectedRoute>} />
                  <Route path="/mitigation/:assessment_id" element={<ProtectedRoute><Mitigation /></ProtectedRoute>} />
                  <Route path="/attack-tree/:assessment_id" element={<ProtectedRoute><AttackTree /></ProtectedRoute>} />
                  <Route path="/view-threat-model/:assessment_id" element={<ProtectedRoute><ViewThreatModel /></ProtectedRoute>} />
                  <Route path="/interactive-threat-model/:assessment_id" element={<ProtectedRoute><InteractiveThreatModel /></ProtectedRoute>} />
                  <Route path="/view-dread/:assessment_id" element={<ProtectedRoute><Dread /></ProtectedRoute>} />
                  <Route path="/view-mitigation/:assessment_id" element={<ProtectedRoute><Mitigation /></ProtectedRoute>} />
                  <Route path="/view-attack-tree/:assessment_id" element={<ProtectedRoute><AttackTree /></ProtectedRoute>} />
                  <Route path="/view-security-test-cases/:assessment_id" element={<ProtectedRoute><ViewSecurityTestCases /></ProtectedRoute>} />
                  <Route path="/tmbom/:assessment_id" element={<ProtectedRoute><TmBom /></ProtectedRoute>} />
                  <Route path="/chat/:assessment_id" element={<ProtectedRoute><Chat /></ProtectedRoute>} />
                  <Route path="/report/:assessment_id" element={<ProtectedRoute><Report /></ProtectedRoute>} />
                  <Route path="/chat" element={<ProtectedRoute><Chat /></ProtectedRoute>} />
                  <Route path="/report" element={<ProtectedRoute><Report /></ProtectedRoute>} />
                  <Route path="/reports" element={<ProtectedRoute><ReportList /></ProtectedRoute>} />
                  <Route path="/threat-models" element={<ProtectedRoute><ThreatModelList /></ProtectedRoute>} />
                  <Route path="/department-threat-models" element={<ProtectedRoute><TeamThreatModels /></ProtectedRoute>} />
                  <Route path="/department-threat-models/custom/:id" element={<ProtectedRoute><CustomDepartmentDetail /></ProtectedRoute>} />
                  <Route path="/department-threat-models/custom/:customId/threats" element={<ProtectedRoute><DepartmentThreats /></ProtectedRoute>} />
                  <Route path="/department-threat-models/:department" element={<ProtectedRoute><DepartmentThreatModelDetail /></ProtectedRoute>} />
                  <Route path="/department-threat-models/:department/threats" element={<ProtectedRoute><DepartmentThreats /></ProtectedRoute>} />
                  <Route path="/analytics" element={<ProtectedRoute><Analytics /></ProtectedRoute>} />
                  <Route path="/metrics" element={<Metrics />} />
                  <Route path="/queue" element={<ProtectedRoute><Queue /></ProtectedRoute>} />
                  <Route path="/integrations" element={<ProtectedRoute><Integrations /></ProtectedRoute>} />
                  <Route path="/feedback" element={<ProtectedRoute><FeedbackList /></ProtectedRoute>} />
                  <Route path="/admin" element={<ProtectedRoute><AdminDashboard /></ProtectedRoute>} />
                  {/* Public feedback form — no auth required */}
                  <Route path="/provide-feedback/:uuid" element={<FeedbackPage />} />

                  {/* Catch-all 404 */}
                  <Route path="*" element={<NotFound />} />
                </Routes>
              </AppLayout>
            </AssessmentProvider>
          </AuthProvider>
        </NavbarProvider>
      </ThemeProvider>
    </Router>
  );
};

export default App;
