import React, { useState } from 'react';
import { Link, useLocation, useParams } from 'react-router-dom';

const Navbar: React.FC = () => {
  const location = useLocation();
  const params = useParams<{ assessment_id?: string }>();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  // Check if we're on an assessment-related page
  const isAssessmentRoute = location.pathname.match(/\/(threat-model|view-threat-model|dread|mitigation|attack-tree)\//) !== null;
  const assessmentId = params.assessment_id;

  return (
    <nav className="bg-gradient-to-r from-[#0a192f] to-[#172b4d] shadow-lg fixed left-0 h-screen w-64 z-30 overflow-y-auto">
      {/* Logo Section */}
      <Link
              to="/">
      <div className="p-4 flex justify-center border-b border-blue-800/30">
        <span className="text-2xl font-bold text-white tracking-tight">
          <span className="text-blue-300">Threat</span>Shield
        </span>
      </div>
      </Link>

      {/* Desktop Navigation */}
      <div className="hidden md:block">
        {/* Main Navigation */}
        <div className="py-4">
          <div className="px-4 pb-2 text-xs font-semibold text-blue-300 uppercase tracking-wider">
            Main Navigation
          </div>
          <div className="space-y-1 px-2">
            <Link
              to="/home"
              className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                location.pathname === '/home' 
                  ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                  : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
              </svg>
              Home
            </Link>
            <Link
              to="/threat-models"
              className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                location.pathname === '/view-threat-models' || 
                location.pathname.startsWith('/view-threat-model/') ||
                location.pathname.startsWith('/view-threat-model/')
                  ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                  : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Threat Models
            </Link>
            <Link
              to="/reports"
              className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                location.pathname === '/reports' || location.pathname.startsWith('/report/')
                  ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                  : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Reports
            </Link>
            <Link
              to="/chat"
              className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                location.pathname === '/chat' || location.pathname.startsWith('/chat/') 
                  ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                  : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
              Threat Bot
            </Link>
            <Link
              to="/analytics"
              className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                location.pathname === '/analytics' 
                  ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                  : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              Analytics
            </Link>
          </div>
        </div>



        {/* Assessment Navigation */}
        {isAssessmentRoute && assessmentId && (
          <div className="py-4 border-t border-blue-800/30">
            <div className="px-4 pb-2 text-xs font-semibold text-blue-300 uppercase tracking-wider">
              Assessment Navigation
            </div>
            <div className="space-y-1 px-2">
              <Link
                to={`/view-threat-model/${assessmentId}`}
                className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                  location.pathname === `/view-threat-model/${assessmentId}` ||
                location.pathname === `/view-threat-model/${assessmentId}`
                    ? 'bg-green-600 text-white font-semibold shadow-md'
                    : 'text-green-300 hover:bg-green-800/30 hover:text-white'
                }`}
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Threat Model
              </Link>
              <Link
                to={`/dread/${assessmentId}`}
                className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                  location.pathname === `/dread/${assessmentId}`
                    ? 'bg-yellow-600 text-white font-semibold shadow-md'
                    : 'text-yellow-300 hover:bg-yellow-800/30 hover:text-white'
                }`}
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                DREAD
              </Link>
              <Link
                to={`/mitigation/${assessmentId}`}
                className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                  location.pathname === `/mitigation/${assessmentId}`
                    ? 'bg-red-600 text-white font-semibold shadow-md'
                    : 'text-red-300 hover:bg-red-800/30 hover:text-white'
                }`}
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Mitigation
              </Link>
              <Link
                to={`/attack-tree/${assessmentId}`}
                className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                  location.pathname === `/attack-tree/${assessmentId}`
                    ? 'bg-purple-600 text-white font-semibold shadow-md'
                    : 'text-purple-300 hover:bg-purple-800/30 hover:text-white'
                }`}
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
                </svg>
                Attack Tree
              </Link>
            </div>
          </div>
        )}
        
        {/* No duplicate settings link here */}
      </div>

      {/* Mobile menu button - always visible on mobile */}
      <div className="md:hidden absolute top-4 right-4">
        <button
          onClick={toggleMobileMenu}
          className="inline-flex items-center justify-center p-2 rounded-md text-blue-100 hover:text-white hover:bg-blue-800/30 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white"
          aria-expanded="false"
        >
          <span className="sr-only">Toggle menu</span>
          {!isMobileMenuOpen ? (
            <svg className="block h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          ) : (
            <svg className="block h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          )}
        </button>
      </div>

      {/* Mobile menu */}
      <div className={`md:hidden ${isMobileMenuOpen ? 'block' : 'hidden'}`}>
        {/* Main Navigation */}
        <div className="px-2 pt-2 pb-3 space-y-1">
          <Link
            to="/"
            className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
              location.pathname === '/' 
                ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
            }`}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
            </svg>
            Home
          </Link>
          <Link
            to="/threat-models"
            className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
              location.pathname === '/view-threat-models' || 
              location.pathname.startsWith('/view-threat-model/') ||
              location.pathname.startsWith('/view-threat-model/')
                ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
            }`}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Threat Models
          </Link>
          <Link
            to="/reports"
            className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
              location.pathname === '/reports' || location.pathname.startsWith('/report/')
                ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
            }`}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Reports
          </Link>
          <Link
            to="/chat"
            className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
              location.pathname === '/chat' || location.pathname.startsWith('/chat/') 
                ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
            }`}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
            </svg>
            Threat Bot
          </Link>
          <Link
            to="/analytics"
            className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
              location.pathname === '/analytics' 
                ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
            }`}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            Analytics
          </Link>
        </div>

        {/* Config in Mobile Menu */}
        <div className="px-2 pt-2 pb-3 space-y-1 border-t border-blue-800/30 mt-2">
          <Link
            to="/settings"
            className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
              location.pathname === '/settings' 
                ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
            }`}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            Settings
          </Link>
          <Link
            to="/about"
            className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
              location.pathname === '/about' 
                ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
                : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
            }`}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            About
          </Link>
        </div>

        {/* Assessment Navigation */}
        {isAssessmentRoute && assessmentId && (
          <div className="px-2 pt-2 pb-3 space-y-1 border-t border-blue-800/30 mt-2">
            <div className="px-4 py-2 text-xs font-semibold text-blue-300 uppercase tracking-wider">
              Assessment
            </div>
            <Link
              to={`/view-threat-model/${assessmentId}`}
              className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                location.pathname === `/view-threat-model/${assessmentId}` ||
                location.pathname === `/view-threat-model/${assessmentId}`
                  ? 'bg-green-600 text-white font-semibold shadow-md'
                  : 'text-green-300 hover:bg-green-800/30 hover:text-white'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Threat Model
            </Link>
            <Link
              to={`/dread/${assessmentId}`}
              className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                location.pathname === `/dread/${assessmentId}`
                  ? 'bg-yellow-600 text-white font-semibold shadow-md'
                  : 'text-yellow-300 hover:bg-yellow-800/30 hover:text-white'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              DREAD
            </Link>
            <Link
              to={`/mitigation/${assessmentId}`}
              className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                location.pathname === `/mitigation/${assessmentId}`
                  ? 'bg-red-600 text-white font-semibold shadow-md'
                  : 'text-red-300 hover:bg-red-800/30 hover:text-white'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Mitigation
            </Link>
            <Link
              to={`/attack-tree/${assessmentId}`}
              className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
                location.pathname === `/attack-tree/${assessmentId}`
                  ? 'bg-purple-600 text-white font-semibold shadow-md'
                  : 'text-purple-300 hover:bg-purple-800/30 hover:text-white'
              }`}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
              </svg>
              Attack Tree
            </Link>
          </div>
        )}
      </div>

      {/* Config Section - Added at the bottom of the navbar (desktop only) */}
      <div className="hidden md:block mt-auto border-t border-blue-800/30 py-4 px-2 absolute bottom-0 left-0 right-0 space-y-1">
        <Link
          to="/settings"
          className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
            location.pathname === '/settings' 
              ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
              : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
          }`}
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          Settings
        </Link>
        <Link
          to="/about"
          className={`flex items-center px-4 py-3 rounded-md text-sm font-medium transition-all duration-200 ${
            location.pathname === '/about' 
              ? 'bg-[#0052cc] text-white font-semibold shadow-md' 
              : 'text-blue-100 hover:bg-blue-800/30 hover:text-white'
          }`}
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          About
        </Link>
      </div>
    </nav>
  );
};

export default Navbar;
