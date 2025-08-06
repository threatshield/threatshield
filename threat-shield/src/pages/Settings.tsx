import React, { useState, useEffect } from 'react';
import { apiService } from '../services/api';

interface ThreatModelSettings {
  preContext: string;
}

const Settings: React.FC = () => {
  const [settings, setSettings] = useState<ThreatModelSettings>({
    preContext: ''
  });
  const [saveStatus, setSaveStatus] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Load settings from settings.json on component mount
  useEffect(() => {
    const loadSettings = async () => {
      try {
        setIsLoading(true);
        const response = await apiService.getSettings();
        if (response && response.data) {
          setSettings(response.data);
        }
      } catch (error) {
        console.error('Error loading settings:', error);
      } finally {
        setIsLoading(false);
      }
    };

    loadSettings();
  }, []);

  const handleSaveSettings = async () => {
    try {
      setIsLoading(true);
      // Save settings to settings.json in the home directory
      await apiService.saveSettings(settings);
      
      // Show success message
      setSaveStatus('Settings saved successfully!');
      
      // Clear message after 3 seconds
      setTimeout(() => {
        setSaveStatus(null);
      }, 3000);
    } catch (error) {
      console.error('Error saving settings:', error);
      setSaveStatus('Error saving settings. Please try again.');
      setTimeout(() => {
        setSaveStatus(null);
      }, 3000);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      {/* Status Message at the top */}
      {saveStatus && (
        <div className={`mb-4 p-4 rounded-md ${saveStatus.includes('Error') ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
          {saveStatus}
        </div>
      )}
      
      <div className="bg-white rounded-lg shadow-md p-6">
        <h1 className="text-2xl font-bold text-gray-800 mb-6">Threat Modeling Settings</h1>
        
        <div className="space-y-6">
          {/* Pre-Context of the Organisation */}
          <div>
            <h2 className="text-xl font-semibold text-gray-700 mb-4">Pre-Context of the Organisation</h2>
            <div className="bg-gray-50 p-6 rounded-md border border-gray-200">
              <div className="space-y-4">
                <p className="text-gray-600">
                  This section allows you to document any security mechanisms or controls that are already implemented in your organization. 
                  Including this information helps prevent false positives during threat modeling by acknowledging existing security measures.
                </p>
                
                
                <div>
                  <label htmlFor="preContext" className="block text-sm font-medium text-gray-700 mb-2">
                    Security Controls and Mechanisms
                  </label>
                  <textarea
                    id="preContext"
                    name="preContext"
                    rows={4}
                    value={settings.preContext}
                    onChange={(e) => setSettings(prev => ({ 
                      ...prev, 
                      preContext: e.target.value
                    }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Describe existing security controls, authentication mechanisms, encryption standards, etc."
                  ></textarea>
                </div>
              </div>
            </div>
          </div>
          
          {/* Save Button */}
          <div className="flex justify-end">
            <button 
              onClick={handleSaveSettings}
              disabled={isLoading}
              className="px-6 py-3 bg-[#0052cc] text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-all duration-200 disabled:opacity-50"
            >
              {isLoading ? 'Saving...' : 'Save Settings'}
            </button>
          </div>
          
          {/* Status Message removed from here as it's now at the top of the page */}
        </div>
      </div>
    </div>
  );
};

export default Settings;
