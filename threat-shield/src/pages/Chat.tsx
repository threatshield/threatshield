import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import ReportHistoryPanel from '../components/common/ReportHistory/ReportHistoryPanel';
import { ReportMetadata, ProjectDetails } from '../types/reportTypes';

interface AIResponse {
  Result: any;  // Can be string, number, object etc.
}

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

const Chat: React.FC = () => {
  const { assessment_id } = useParams<{ assessment_id?: string }>();
  const navigate = useNavigate();
  const [selectedReportId, setSelectedReportId] = useState<string | null>(assessment_id || null);
  const [selectedReport, setSelectedReport] = useState<ReportMetadata | null>(null);
  const [showReportSelector, setShowReportSelector] = useState<boolean>(!assessment_id);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isInstructionsVisible, setIsInstructionsVisible] = useState<boolean>(false);
  const [reports, setReports] = useState<ReportMetadata[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Initial welcome message and report selector
  useEffect(() => {
    const welcomeMessage: Message = {
      id: 'welcome',
      role: 'assistant',
      content: selectedReportId
        ? 'Hello! I\'m your Threat Bot assistant. I can help you understand the threats identified in your application and suggest appropriate mitigations. What would you like to know about your threat model?'
        : 'Hello! Please select a report to get started. I can help you understand the threats and security concerns identified in your assessment.',
      timestamp: new Date()
    };
    setMessages([welcomeMessage]);
  }, [selectedReportId]);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Focus input on load
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Fetch reports on mount
  useEffect(() => {
    const fetchReports = async () => {
      try {
        const response = await apiService.getStorageHistory();
        if (response && response.data) {
          setReports(response.data);
          // If we have an assessment_id, find and set the corresponding report
          if (assessment_id) {
            const report = response.data.find(r => r.id === assessment_id);
            if (report) {
              setSelectedReport(report);
              setSelectedReportId(assessment_id);
              setShowReportSelector(false);
            }
          }
        }
      } catch (error) {
        console.error('Error fetching reports:', error);
      }
    };
    fetchReports();
  }, [assessment_id]);

  // Handle report selection
  const handleReportSelect = (reportId: string) => {
    const report = reports.find(r => r.id === reportId);
    if (report) {
      setSelectedReportId(reportId);
      setSelectedReport(report);
      setShowReportSelector(false);
      setMessages([]); // Clear messages when switching reports

      // Navigate to the specific chat URL
      navigate(`/chat/${reportId}`);
    }
  };

  // Handle change report
  const handleChangeReport = () => {
    navigate('/chat'); // Navigate back to the main chat page
  };

  // Effect to handle state reset when navigating to main chat page
  useEffect(() => {
    if (!assessment_id) {
      setSelectedReportId(null);
      setSelectedReport(null);
      setShowReportSelector(true);
      setMessages([]);
      setInput('');
    }
  }, [assessment_id]);

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);

    // Auto-resize textarea
    e.target.style.height = 'auto';
    e.target.style.height = `${e.target.scrollHeight}px`;
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault(); // Prevent default to avoid adding a new line
      handleSubmit(e as unknown as React.FormEvent);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!input.trim()) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    // Reset textarea height
    if (inputRef.current) {
      inputRef.current.style.height = 'auto';
    }

    try {
      if (!selectedReportId) {
        throw new Error('Please select a report to get personalized assistance.');
      }

      const response = await apiService.queryAI(selectedReportId, userMessage.content);
      console.log('Bot response:', response); // Debug logging

      if (!response || !response.Result) {
        throw new Error('Invalid response format from server');
      }

      const botResponse = typeof response.Result === 'object'
        ? JSON.stringify(response.Result, null, 2)  // Pretty print objects
        : String(response.Result);  // Convert numbers, booleans etc to string

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: botResponse,
        timestamp: new Date()
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (error) {
      console.error('Error sending message:', error);

      // Add error message
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: 'Sorry, I encountered an error processing your request. Please try again.',
        timestamp: new Date()
      };

      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const formatTimestamp = (date: Date) => {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // If no report selected, show only report selection UI
  if (!selectedReportId) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent">
        <div className="px-6 py-8">
          {/* Page Header */}
          <div className="mb-8">
            <div className="flex items-center gap-2 mb-1">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
                <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
                </svg>
              </div>
              <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Threat Bot</h1>
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-400">AI-powered security assistant for your threat models</p>
          </div>

          {/* How to Use — Collapsible */}
          <div className="bg-white dark:bg-[#0d1e38]/80 rounded-xl border border-slate-200 dark:border-blue-900/30 shadow-sm overflow-hidden mb-6">
            <button
              onClick={() => setIsInstructionsVisible(prev => !prev)}
              className="w-full flex items-center justify-between px-6 py-4 focus:outline-none"
              aria-expanded={isInstructionsVisible}
              aria-controls="instructions-content"
            >
              <div className="flex items-center gap-3">
                <div className="w-7 h-7 rounded-lg bg-blue-50 border border-blue-200 dark:bg-blue-900/20 dark:border-blue-800/40 flex items-center justify-center">
                  <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <span className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">How to Use</span>
              </div>
              <svg
                className={`h-4 w-4 text-slate-400 dark:text-slate-500 transform transition-transform duration-200 ${isInstructionsVisible ? 'rotate-180' : ''}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            <div
              id="instructions-content"
              className={`overflow-hidden transition-all duration-300 ${isInstructionsVisible ? 'max-h-64 opacity-100' : 'max-h-0 opacity-0'}`}
            >
              <div className="px-6 pb-5 border-t border-slate-100 dark:border-blue-900/20 pt-4">
                <ol className="space-y-2">
                  {[
                    'Select a completed threat model report from the list below.',
                    'The chat interface will appear automatically once a report is selected.',
                    'Ask questions about identified threats, vulnerabilities, and recommended mitigations.',
                  ].map((step, i) => (
                    <li key={i} className="flex items-start gap-3 text-sm text-slate-600 dark:text-slate-400">
                      <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-[#0052cc] dark:bg-blue-900/30 dark:text-blue-400 text-xs font-bold flex items-center justify-center mt-0.5">
                        {i + 1}
                      </span>
                      {step}
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          </div>

          {/* Report History Panel */}
          <ReportHistoryPanel onSelect={handleReportSelect} buttonText="Ask AI" />
        </div>
      </div>
    );
  }

  // If report selected, show chat interface
  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      <div className="px-6 py-8">
        {/* Page Header */}
        <div className="mb-6">
          <div className="flex items-center gap-2 mb-1">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
              <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
            </div>
            <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Threat Bot</h1>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400">AI-powered security assistant for your threat models</p>
        </div>

        {/* Report Info Bar */}
        <div className="flex items-center justify-between mb-4 bg-white dark:bg-[#0d1e38]/80 border border-slate-200 dark:border-blue-900/30 rounded-xl px-4 py-3 shadow-sm">
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-6 h-6 rounded-md bg-blue-50 border border-blue-200 dark:bg-blue-900/20 dark:border-blue-800/40 flex items-center justify-center flex-shrink-0">
              <svg className="h-3.5 w-3.5 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-0.5">Active Report</p>
              <p className="text-sm font-medium text-slate-700 dark:text-slate-300 truncate">
                {selectedReport?.details
                  ? `[${selectedReport.details.department}] ${selectedReport.details.projectName} — ${new Date(selectedReport.details.timestamp).toLocaleDateString()}`
                  : 'Loading...'}
              </p>
            </div>
          </div>
          <button
            onClick={handleChangeReport}
            className="flex-shrink-0 ml-4 px-4 py-2 bg-white border border-slate-200 text-slate-600 text-sm font-medium rounded-lg hover:border-[#0052cc]/40 hover:text-[#0052cc] hover:bg-blue-50/50 dark:bg-gray-800/60 dark:border-gray-700 dark:text-slate-300 transition-all duration-200 shadow-sm"
          >
            Change Report
          </button>
        </div>

        {/* Chat Window */}
        <div
          className="flex flex-col bg-white dark:bg-[#0d1e38]/80 rounded-xl border border-slate-200 dark:border-blue-900/30 shadow-sm overflow-hidden"
          style={{ height: 'calc(100vh - 280px)' }}
        >
          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-5 bg-slate-50/50 dark:bg-[#060e1d]/70">
            <div className="space-y-5">
              {messages.map(message => (
                <div
                  key={message.id}
                  className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  <div
                    className={`max-w-[78%] ${
                      message.role === 'user'
                        ? 'bg-[#0052cc] text-white rounded-2xl rounded-br-sm shadow-sm'
                        : 'bg-white dark:bg-[#0d1e38] border border-slate-200 dark:border-blue-900/40 rounded-2xl rounded-bl-sm shadow-sm'
                    }`}
                  >
                    <div className={`px-4 pt-3 pb-1 flex items-center gap-2 ${message.role === 'user' ? '' : ''}`}>
                      <span className={`text-xs font-semibold ${message.role === 'user' ? 'text-blue-200' : 'text-slate-500 dark:text-slate-400'}`}>
                        {message.role === 'user' ? 'You' : 'Threat Bot'}
                      </span>
                      <span className={`text-xs ${message.role === 'user' ? 'text-blue-300' : 'text-slate-400 dark:text-slate-500'}`}>
                        {formatTimestamp(message.timestamp)}
                      </span>
                    </div>
                    <div className={`px-4 pb-3 text-sm leading-relaxed whitespace-pre-wrap ${message.role === 'user' ? 'text-white' : 'text-slate-700 dark:text-slate-200'}`}>
                      {message.content}
                    </div>
                  </div>
                </div>
              ))}

              {/* Loading dots */}
              {isLoading && (
                <div className="flex justify-start">
                  <div className="bg-white dark:bg-[#0d1e38] border border-slate-200 dark:border-blue-900/40 rounded-2xl rounded-bl-sm shadow-sm px-4 py-3">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">Threat Bot</span>
                      <span className="text-xs text-slate-400 dark:text-slate-500">{formatTimestamp(new Date())}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-full bg-[#0052cc] animate-bounce opacity-75" style={{ animationDelay: '0ms' }} />
                      <div className="w-2 h-2 rounded-full bg-[#0052cc] animate-bounce opacity-75" style={{ animationDelay: '150ms' }} />
                      <div className="w-2 h-2 rounded-full bg-[#0052cc] animate-bounce opacity-75" style={{ animationDelay: '300ms' }} />
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>
          </div>

          {/* Input Area */}
          <form
            onSubmit={handleSubmit}
            className="flex items-end gap-3 bg-white dark:bg-[#0c1a2e]/90 px-4 py-3 border-t border-slate-100 dark:border-blue-900/20"
          >
            <div className="flex-1">
              <textarea
                ref={inputRef}
                value={input}
                onChange={handleInputChange}
                onKeyDown={handleKeyDown}
                placeholder={selectedReportId ? 'Ask about security threats and mitigations...' : 'Select a report to start chatting...'}
                className="w-full px-4 py-2.5 border border-slate-200 dark:border-blue-900/40 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#0052cc]/30 focus:border-[#0052cc] resize-none overflow-hidden bg-slate-50 dark:bg-[#0d1e38] text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 text-sm transition-all"
                rows={1}
                disabled={isLoading || !selectedReportId}
              />
            </div>
            <button
              type="submit"
              className="flex-shrink-0 w-10 h-10 flex items-center justify-center rounded-xl bg-[#0052cc] hover:bg-[#0047b3] transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed shadow-sm"
              disabled={isLoading || !selectedReportId || !input.trim()}
            >
              <svg
                className="h-4 w-4 text-white transform rotate-90"
                viewBox="0 0 20 20"
                fill="currentColor"
              >
                <path d="M10.894 2.553a1 1 0 00-1.788 0l-7 14a1 1 0 001.169 1.409l5-1.429A1 1 0 009 15.571V11a1 1 0 112 0v4.571a1 1 0 00.725.962l5 1.428a1 1 0 001.17-1.408l-7-14z" />
              </svg>
            </button>
          </form>
        </div>

        {/* Footer hint */}
        <div className="mt-4 flex justify-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-white dark:bg-[#0d1e38]/80 border border-slate-200 dark:border-blue-900/30 rounded-full text-xs text-slate-500 dark:text-slate-400 shadow-sm">
            <svg className="h-3.5 w-3.5 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Ask about threats, vulnerabilities, and recommended mitigations
          </div>
        </div>
      </div>
    </div>
  );
};

export default Chat;
