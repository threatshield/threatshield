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
      <div className="py-4">
      <div className="max-w-5xl mx-auto px-4">
        <div className="text-center mb-6">
          <div className="flex items-center justify-center mb-2">
            <div className="bg-blue-100 p-2 rounded-full mr-3">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
            </div>
            <h1 className="text-3xl font-bold text-[#0052cc]">Threat Bot</h1>
          </div>
          <p className="text-gray-600">Your AI-powered security assistant</p>
        </div>

        {/* Instructions Card - Collapsible */}
        <div className="bg-blue-50 border border-blue-100 rounded-lg p-6 mb-6">
          <button 
            onClick={() => setIsInstructionsVisible(prev => !prev)}
            className="w-full flex items-start justify-between focus:outline-none"
            aria-expanded={isInstructionsVisible}
            aria-controls="instructions-content"
          >
            <div className="flex items-start">
              <div className="bg-blue-100 p-2 rounded-full mr-4">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h2 className="text-lg font-semibold text-blue-800">How to Use Threat Bot</h2>
            </div>
            <svg 
              xmlns="http://www.w3.org/2000/svg" 
              className={`h-5 w-5 text-blue-600 transform transition-transform duration-200 ${isInstructionsVisible ? 'rotate-180' : ''}`} 
              fill="none" 
              viewBox="0 0 24 24" 
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          
          <div 
            id="instructions-content" 
            className={`mt-4 pl-12 overflow-hidden transition-all duration-300 ${
              isInstructionsVisible ? 'max-h-[200px] opacity-100' : 'max-h-0 opacity-0'
            }`}
          >
            <ol className="list-decimal list-inside text-blue-700 space-y-2">
              <li>Select a report from the list below</li>
              <li>Chat interface will appear automatically</li>
              <li>Ask questions about threats and security concerns</li>
            </ol>
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
    <div className="max-w-5xl mx-auto px-4">
      <div className="text-center mb-6">
        <div className="flex items-center justify-center mb-2">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
            </svg>
          </div>
          <h1 className="text-3xl font-bold text-[#0052cc]">Threat Bot</h1>
        </div>
        <p className="text-gray-600">Your AI-powered security assistant</p>
      </div>
      
      {/* Report Selection Header - Always show when report is selected */}
      <div className="flex items-center justify-between mb-4 bg-blue-50 p-3 rounded-lg">
        <div className="flex items-center">
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-blue-600 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <span className="text-blue-600 font-medium">
            Selected Report: {selectedReport?.details ? 
              `${selectedReport.details.projectName} - ${new Date(selectedReport.details.timestamp).toLocaleDateString()}` 
              : 'Loading...'}
          </span>
        </div>
        <button
          onClick={handleChangeReport}
          className="text-blue-600 hover:text-blue-800 text-sm font-medium"
        >
          Change Report
        </button>
      </div>
      
      <div className="flex flex-col h-[70vh] card">
        {/* Chat messages */}
        <div className="flex-1 overflow-y-auto mb-4 p-4 border border-blue-100 rounded-lg bg-blue-50/30">
          <div className="space-y-4">
            {messages.map(message => (
              <div
                key={message.id}
                className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[80%] rounded-lg p-4 shadow-sm ${
                    message.role === 'user'
                      ? 'bg-[#0052cc] text-white'
                      : 'bg-white border border-blue-100'
                  }`}
                >
                  <div className="text-sm mb-1">
                    {message.role === 'user' ? 'You' : 'Threat Bot'}{' '}
                    <span className="text-xs opacity-70">
                      {formatTimestamp(message.timestamp)}
                    </span>
                  </div>
                  <div className="whitespace-pre-wrap">{message.content}</div>
                </div>
              </div>
            ))}
            {isLoading && (
              <div className="flex justify-start">
                <div className="max-w-[80%] rounded-lg p-4 bg-white border border-blue-100 shadow-sm">
                  <div className="flex items-center mb-1">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-[#0052cc] mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                    <span className="text-sm font-medium text-[#172b4d]">Threat Bot</span>
                    <span className="text-xs text-gray-500 ml-2">
                      {formatTimestamp(new Date())}
                    </span>
                  </div>
                  <div className="flex space-x-2 pl-5">
                    <div className="w-2 h-2 rounded-full bg-[#0052cc] animate-bounce opacity-75" style={{ animationDelay: '0ms' }}></div>
                    <div className="w-2 h-2 rounded-full bg-[#0052cc] animate-bounce opacity-75" style={{ animationDelay: '150ms' }}></div>
                    <div className="w-2 h-2 rounded-full bg-[#0052cc] animate-bounce opacity-75" style={{ animationDelay: '300ms' }}></div>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>
        </div>
        
        {/* Input form */}
        <form onSubmit={handleSubmit} className="flex items-end bg-white p-4 border-t border-blue-100">
          <div className="flex-1 mr-3">
            <div className="relative">
              <textarea
                ref={inputRef}
                value={input}
                onChange={handleInputChange}
                onKeyDown={handleKeyDown}
                placeholder={selectedReportId ? "Ask about security threats and mitigations..." : "Select a report to start chatting..."}
                className="w-full p-3 pr-12 border-2 border-blue-100 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#0052cc] focus:border-[#0052cc] resize-none overflow-hidden bg-white shadow-sm"
                rows={1}
                disabled={isLoading || !selectedReportId}
              />
              <div className="absolute right-3 bottom-3 text-gray-400">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                </svg>
              </div>
            </div>
          </div>
          <button
            type="submit"
            className="bg-[#0052cc] h-12 w-12 flex items-center justify-center rounded-full shadow-sm hover:bg-[#0047B3] transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            disabled={isLoading || !selectedReportId || !input.trim()}
          >
            <svg 
              xmlns="http://www.w3.org/2000/svg" 
              className="h-5 w-5 text-white transform rotate-90" 
              viewBox="0 0 20 20" 
              fill="currentColor"
            >
              <path d="M10.894 2.553a1 1 0 00-1.788 0l-7 14a1 1 0 001.169 1.409l5-1.429A1 1 0 009 15.571V11a1 1 0 112 0v4.571a1 1 0 00.725.962l5 1.428a1 1 0 001.17-1.408l-7-14z" />
            </svg>
          </button>
        </form>
      </div>
      
      <div className="mt-6 text-sm text-center">
        <div className="inline-flex items-center px-4 py-2 bg-blue-50 border border-blue-100 rounded-full text-[#0052cc]">
          <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p>
            Ask me about security threats, vulnerabilities, and recommended mitigations
          </p>
        </div>
      </div>
    </div>
  );
};

export default Chat;
