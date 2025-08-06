import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import { AssessmentProvider } from './context/AssessmentContext';
import Navbar from './components/common/Navbar';
import Home from './pages/Home';
import ThreatModel from './pages/ThreatModel';
import ViewThreatModel from './pages/ViewThreatModel';
import Dread from './pages/Dread';
import Mitigation from './pages/Mitigation';
import AttackTree from './pages/AttackTree';
import Chat from './pages/Chat';
import Report from './pages/Report';
import ReportList from './pages/ReportList';
import ThreatModelList from './pages/ThreatModelList';
import Analytics from './pages/Analytics';
import Settings from './pages/Settings';
import About from './pages/About';

// Wrapper component to conditionally show navbar
const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation();
  const [showNavbar, setShowNavbar] = useState(false);
  
  useEffect(() => {
    // Always show navbar as landing page is removed
    // Also ensure navbar shows for all assessment-related routes
    const isAssessmentRoute = location.pathname.match(/\/(threat-model|dread|mitigation|attack-tree|reports)\//) !== null;
    setShowNavbar(true);
  }, [location]);
  
  return (
    <div className="min-h-screen bg-background">
      {showNavbar && <Navbar />}
      <main className={showNavbar ? "ml-64 transition-all duration-300" : ""}>
        {children}
      </main>
    </div>
  );
};

const App: React.FC = () => {
  return (
    <Router>
      <AssessmentProvider>
        <AppLayout>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/home" element={<Home />} />
            {/* Generation routes */}
            <Route path="/threat-model/:assessment_id" element={<ThreatModel />} />
            <Route path="/dread/:assessment_id" element={<Dread />} />
            <Route path="/mitigation/:assessment_id" element={<Mitigation />} />
            <Route path="/attack-tree/:assessment_id" element={<AttackTree />} />
            
            {/* View-only routes */}
            <Route path="/view-threat-model/:assessment_id" element={<ViewThreatModel />} />
            <Route path="/view-dread/:assessment_id" element={<Dread />} />
            <Route path="/view-mitigation/:assessment_id" element={<Mitigation />} />
            <Route path="/view-attack-tree/:assessment_id" element={<AttackTree />} />
            <Route path="/chat/:assessment_id" element={<Chat />} />
            <Route path="/report/:assessment_id" element={<Report />} />
            <Route path="/chat" element={<Chat />} />
            <Route path="/report" element={<Report />} />
            <Route path="/reports" element={<ReportList />} />
            <Route path="/threat-models" element={<ThreatModelList />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/about" element={<About />} />
          </Routes>
        </AppLayout>
      </AssessmentProvider>
    </Router>
  );
};

export default App;
