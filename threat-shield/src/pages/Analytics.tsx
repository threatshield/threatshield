import React, { useState, useEffect } from 'react';
import { 
  Chart as ChartJS, 
  ArcElement, 
  Tooltip, 
  Legend, 
  CategoryScale,
  LinearScale,
  BarElement,
  Title
} from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';
import { apiService } from '../services/api';
import { 
  ReportMetadata, 
  DreadAssessmentItem, 
  Threat, 
  AttackTreeNode,
  MitigationItem,
  AttackTree
} from '../types/reportTypes';

// Helper function to safely get mitigation data
const getMitigationData = (result: any): MitigationItem[] => {
  try {
    // Case 1: Direct raw_response
    if (result?.raw_response?.mitigations) {
      return result.raw_response.mitigations;
    }
    
    // Case 2: Nested in result.raw_response
    if (result?.result?.raw_response?.mitigations) {
      return result.result.raw_response.mitigations;
    }

    console.warn('No valid mitigation data found in result:', result);
    return [];
  } catch (error) {
    console.error('Error extracting mitigation data:', error);
    return [];
  }
};

// Helper function to safely get attack tree data
const getAttackTreeData = (result: any): AttackTree | undefined => {
  try {
    // Case 1: Direct attack_tree
    if (result?.attack_tree) {
      return result.attack_tree;
    }
    
    // Case 2: Nested in result
    if (result?.result?.attack_tree) {
      return result.result.attack_tree;
    }

    console.warn('No valid attack tree data found in result:', result);
    return undefined;
  } catch (error) {
    console.error('Error extracting attack tree data:', error);
    return undefined;
  }
};

// Helper function to safely get threat model data
const getThreatModelData = (result: any): Threat[] => {
  try {
    // Case 1: Direct raw_response
    if (result?.raw_response?.threat_model) {
      return result.raw_response.threat_model;
    }
    
    // Case 2: Nested in result.raw_response
    if (result?.result?.raw_response?.threat_model) {
      return result.result.raw_response.threat_model;
    }
    
    // Case 3: Double nested in result.result.raw_response
    if (result?.result?.result?.raw_response?.threat_model) {
      return result.result.result.raw_response.threat_model;
    }

    console.warn('No valid threat model data found in result:', result);
    return [];
  } catch (error) {
    console.error('Error extracting threat model data:', error);
    return [];
  }
};

// Helper function to safely get DREAD items
const getDreadItems = (result: any): DreadAssessmentItem[] => {
  try {
    // Case 1: Direct raw_response
    if (result?.raw_response?.['Risk Assessment']) {
      return result.raw_response['Risk Assessment'];
    }
    
    // Case 2: Nested in result
    if (result?.result?.raw_response?.['Risk Assessment']) {
      return result.result.raw_response['Risk Assessment'];
    }

    console.warn('No valid DREAD data found in result:', result);
    return [];
  } catch (error) {
    console.error('Error extracting DREAD items:', error);
    return [];
  }
};

// Register ChartJS components
ChartJS.register(
  ArcElement, 
  Tooltip, 
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  Title
);

const Analytics: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [reportData, setReportData] = useState<ReportMetadata[]>([]);
  const [highRiskIssues, setHighRiskIssues] = useState<DreadAssessmentItem[]>([]);
  const [duration, setDuration] = useState<string>('all');
  const [isHighIssuesExpanded, setIsHighIssuesExpanded] = useState<boolean>(false);
  const [isThreatTypesExpanded, setIsThreatTypesExpanded] = useState<boolean>(true);
  const [categoryHighIssues, setCategoryHighIssues] = useState<Record<string, number>>({});
  const [modelCount, setModelCount] = useState<number>(0);
  const [totalModels, setTotalModels] = useState<number>(0);
  
  // Analytics data
  const [threatTypeData, setThreatTypeData] = useState<{
    labels: string[];
    datasets: {
      label: string;
      data: number[];
      backgroundColor: string[];
      borderColor: string[];
      borderWidth: number;
    }[];
  }>({
    labels: [],
    datasets: [
      {
        label: 'Issues by Threat Type',
        data: [],
        backgroundColor: [],
        borderColor: [],
        borderWidth: 1,
      },
    ],
  });

  
  
  const [mitigationData, setMitigationData] = useState<{
    labels: string[];
    datasets: {
      label: string;
      data: number[];
      backgroundColor: string[];
      borderColor: string[];
      borderWidth: number;
    }[];
  }>({
    labels: ['Mitigated', 'Unmitigated'],
    datasets: [
      {
        label: 'Mitigation Status',
        data: [0, 0],
        backgroundColor: [
          'rgba(75, 192, 192, 0.6)',
          'rgba(255, 99, 132, 0.6)',
        ],
        borderColor: [
          'rgba(75, 192, 192, 1)',
          'rgba(255, 99, 132, 1)',
        ],
        borderWidth: 1,
      },
    ],
  });
  
  const [attackPathData, setAttackPathData] = useState<{
    labels: string[];
    datasets: {
      label: string;
      data: number[];
      backgroundColor: string[];
    }[];
  }>({
    labels: ['Attack Paths'],
    datasets: [
      {
        label: 'Total Attack Paths',
        data: [0],
        backgroundColor: ['rgba(153, 102, 255, 0.6)'],
      },
    ],
  });
  
  const [strideData, setStrideData] = useState<{
    labels: string[];
    datasets: {
      label: string;
      data: number[];
      backgroundColor: string[];
    }[];
  }>({
    labels: ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'],
    datasets: [
      {
        label: 'Issues by STRIDE Category',
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: [
          'rgba(255, 99, 132, 0.6)',
          'rgba(54, 162, 235, 0.6)',
          'rgba(255, 206, 86, 0.6)',
          'rgba(75, 192, 192, 0.6)',
          'rgba(153, 102, 255, 0.6)',
          'rgba(255, 159, 64, 0.6)',
        ],
      },
    ],
  });

  // Calculate DREAD score
  const calculateDreadScore = (item: DreadAssessmentItem): number => {
    return (
      item['Damage Potential'] +
      item['Reproducibility'] +
      item['Exploitability'] +
      item['Affected Users'] +
      item['Discoverability']
    ) / 5;
  };

  // Fetch report data based on duration
  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        console.log('Fetching storage history...');
        const { data } = await apiService.getStorageHistory();
        console.log('Storage history response:', data);
        
        if (!data || data.length === 0) {
          setError('No threat models found. Generate a threat model to view analytics.');
          setLoading(false);
          return;
        }

        // Filter reports based on timestamp and duration
        const now = new Date();
        let startDate = new Date();
        
        switch (duration) {
          case 'week':
            startDate.setDate(now.getDate() - 7);
            break;
          case 'month':
            startDate.setMonth(now.getMonth() - 1);
            break;
          case 'quarter':
            startDate.setMonth(now.getMonth() - 3);
            break;
          case 'year':
            startDate.setFullYear(now.getFullYear() - 1);
            break;
          default:
            startDate = new Date(0); // Beginning of time for 'all'
        }
        // Filter reports based on timestamp
        const filteredReports = data.filter((report: ReportMetadata) => {
          if (!report) {
            console.warn('Found null or undefined report in data array');
            return false;
          }
          
          // For 'all' duration, include all reports
          if (duration === 'all') return true;
          
          const timestamp = report.threat_model?.timestamp;
          if (!timestamp) {
            console.warn('Report missing threat_model or timestamp:', report.id);
            return false;
          }
          
          const reportDate = new Date(timestamp);
          const isInRange = reportDate >= startDate && reportDate <= now;
          if (!isInRange) {
            console.log('Report outside date range:', {
              reportId: report.id,
              reportDate,
              startDate,
              now
            });
          }
          return isInRange;
        });
        
        console.log('Filtered reports:', filteredReports);
        setReportData(filteredReports);
        
        // Process data for analytics
        console.log('Processing report data...');
        processReportData(filteredReports);
        
        setLoading(false);
        console.log('Analytics data loaded successfully');
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
        setError(`Failed to load analytics data: ${errorMessage}`);
        setLoading(false);
        console.error('Error loading analytics data:', {
          error: err,
          message: errorMessage,
          stack: err instanceof Error ? err.stack : undefined
        });
      }
    };
    
    fetchData();
  }, [duration]);
  
  // Process report data for analytics
  const processReportData = (reports: ReportMetadata[]) => {
    // Track high risk issues (DREAD score >= 8)
    const highRiskItems: DreadAssessmentItem[] = [];
    
    // Track threat types
    const threatTypeCounts: Record<string, number> = {};
    
    
    // Track STRIDE categories
    const strideCounts = {
      'Spoofing': 0,
      'Tampering': 0,
      'Repudiation': 0,
      'Information Disclosure': 0,
      'Denial of Service': 0,
      'Elevation of Privilege': 0
    };
    
    
    // Track mitigation status
    let mitigatedCount = 0;
    let totalThreats = 0;
    
    // Track attack paths
    let totalAttackPaths = 0;
    
    // Process each report
  reports.forEach(report => {
      // Process DREAD assessments only for high risk items
      if (report.dread_assessment?.result) {
        console.log('Processing DREAD assessment for report:', report.id);
        
        const dreadItems = getDreadItems(report.dread_assessment.result);
        console.log('DREAD items:', dreadItems);
        
        if (dreadItems && Array.isArray(dreadItems)) {
          dreadItems.forEach((item: DreadAssessmentItem) => {
            // Calculate DREAD score
            const score = calculateDreadScore(item);
            
            
            
            // Add high risk items
            if (score >= 8) {
              highRiskItems.push(item);
              
            }
          });
        }
      }
      
     
      // Process threat models for analytics
      if (report.threat_model?.result) {
        // Get threats using the helper function
        const threats = getThreatModelData(report.threat_model.result);
        
        setModelCount(prev => prev + 1);
        
        threats.forEach((threat: Threat) => {
          // Count threat types
          const threatType = threat['Threat Type'];
          if (threatType) {
            threatTypeCounts[threatType] = (threatTypeCounts[threatType] || 0) + 1;
            
          
            
            // Count STRIDE categories
            if (Object.prototype.hasOwnProperty.call(strideCounts, threatType)) {
              strideCounts[threatType as keyof typeof strideCounts]++;
            }
          }
    
    totalThreats++;
  });
      }
      
      // Process mitigations using helper function
      if (report.mitigation?.result) {
        const mitigations = getMitigationData(report.mitigation.result);
        mitigatedCount += mitigations.length;
      }
      
      // Process attack trees
      if (report.attack_tree?.result) {
        const attackTree = getAttackTreeData(report.attack_tree.result);
        if (attackTree?.total_paths !== undefined) {
          totalAttackPaths += attackTree.total_paths;
        }
      }
    });
    
    // Sort high risk issues by DREAD score
    highRiskItems.sort((a, b) => calculateDreadScore(b) - calculateDreadScore(a));
    setHighRiskIssues(highRiskItems);
    
    // Set threat type data
    const threatTypeLabels = Object.keys(threatTypeCounts);
    const threatTypeValues = Object.values(threatTypeCounts);
    const threatTypeColors = threatTypeLabels.map((_, i) => 
      `rgba(${Math.floor(Math.random() * 255)}, ${Math.floor(Math.random() * 255)}, ${Math.floor(Math.random() * 255)}, 0.6)`
    );
    
   
    
    setThreatTypeData({
      labels: threatTypeLabels,
      datasets: [
        {
          label: 'Issues by Threat Type',
          data: threatTypeValues,
          backgroundColor: threatTypeColors,
          borderColor: threatTypeColors.map(color => color.replace('0.6', '1')),
          borderWidth: 1,
        },
      ],
    });
    

    
    // Use a more appealing color palette for categories
    const categoryColors = [
      'rgba(54, 162, 235, 0.7)',   // Blue
      'rgba(255, 99, 132, 0.7)',    // Red
      'rgba(75, 192, 192, 0.7)',    // Green
      'rgba(255, 159, 64, 0.7)',    // Orange
      'rgba(153, 102, 255, 0.7)',   // Purple
      'rgba(255, 205, 86, 0.7)',    // Yellow
      'rgba(201, 203, 207, 0.7)',   // Grey
      'rgba(255, 99, 71, 0.7)',     // Tomato
      'rgba(50, 205, 50, 0.7)',     // Lime Green
      'rgba(138, 43, 226, 0.7)',    // Blue Violet
    ];
    
   
    
    
    // Set mitigation data
    setMitigationData({
      labels: ['Mitigated', 'Unmitigated'],
      datasets: [
        {
          label: 'Mitigation Status',
          data: [mitigatedCount, Math.max(0, totalThreats - mitigatedCount)],
          backgroundColor: [
            'rgba(75, 192, 192, 0.6)',
            'rgba(255, 99, 132, 0.6)',
          ],
          borderColor: [
            'rgba(75, 192, 192, 1)',
            'rgba(255, 99, 132, 1)',
          ],
          borderWidth: 1,
        },
      ],
    });
    
    // Set attack path data
    setAttackPathData({
      labels: ['Attack Paths'],
      datasets: [
        {
          label: 'Total Attack Paths',
          data: [totalAttackPaths],
          backgroundColor: ['rgba(153, 102, 255, 0.6)'],
        },
      ],
    });
    
    // Set STRIDE data
    setStrideData({
      labels: Object.keys(strideCounts),
      datasets: [
        {
          label: 'Issues by STRIDE Category',
          data: Object.values(strideCounts),
          backgroundColor: [
            'rgba(255, 99, 132, 0.6)',
            'rgba(54, 162, 235, 0.6)',
            'rgba(255, 206, 86, 0.6)',
            'rgba(75, 192, 192, 0.6)',
            'rgba(153, 102, 255, 0.6)',
            'rgba(255, 159, 64, 0.6)',
          ],
        },
      ],
    });
    
    
    // Set state for other analytics data
    setCategoryHighIssues(categoryHighIssues);
    setTotalModels(modelCount);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500 mx-auto"></div>
          <p className="mt-4 text-gray-700">Loading analytics data...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
      <div className="text-center">
        <svg xmlns="http://www.w3.org/2000/svg" className="h-12 w-12 mx-auto text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
        </svg>
        <p className="mt-4 text-gray-600">{error}</p>
      </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold text-gray-800">ThreatShield Analytics Dashboard</h1>
        
        {/* Duration Filter */}
        <select
          value={duration}
          onChange={(e) => setDuration(e.target.value)}
          className="w-48 px-3 py-2 bg-white border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
        >
          <option value="all">All Time</option>
          <option value="week">Last Week</option>
          <option value="month">Last Month</option>
          <option value="quarter">Last Quarter</option>
          <option value="year">Last Year</option>
        </select>
      </div>
      
      {/* Executive Summary Section */}
      <div className="bg-white rounded-lg shadow-md p-6 mb-8">
        <h2 className="text-2xl font-semibold text-gray-700 mb-4">Executive Summary</h2>
        
        {/* Summary Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="bg-blue-50 rounded-lg p-4 border border-blue-100">
            <h4 className="text-sm font-medium text-blue-800">Total Threat Models</h4>
            <p className="text-2xl font-bold text-blue-600">{reportData.length}</p>
          </div>
          <div className="bg-red-50 rounded-lg p-4 border border-red-100">
            <h4 className="text-sm font-medium text-red-800">High Risk Issues</h4>
            <p className="text-2xl font-bold text-red-600">{highRiskIssues.length}</p>
          </div>
          <div className="bg-yellow-50 rounded-lg p-4 border border-yellow-100">
            <h4 className="text-sm font-medium text-yellow-800">Total Issues</h4>
            <p className="text-2xl font-bold text-yellow-600">
              {threatTypeData.datasets[0].data.reduce((a, b) => a + b, 0)}
            </p>
          </div>
        </div>

        {/* High Risk Issues */}
        <div className="mb-4">
          <button
            onClick={() => setIsHighIssuesExpanded(!isHighIssuesExpanded)}
            className="flex items-center text-lg font-medium text-red-600 mb-2 hover:text-red-700"
          >
            <svg
              className={`w-5 h-5 mr-2 transform transition-transform ${isHighIssuesExpanded ? 'rotate-90' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
            High Risk Issues
          </button>
          {isHighIssuesExpanded ? (
            highRiskIssues.length > 0 ? (
              <div className="overflow-x-auto">
              <table className="min-w-full bg-white border border-gray-200">
                <thead>
                  <tr>
                    <th className="py-2 px-4 border-b border-gray-200 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threat Type</th>
                    <th className="py-2 px-4 border-b border-gray-200 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scenario</th>
                    <th className="py-2 px-4 border-b border-gray-200 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Assessment</th>
                    <th className="py-2 px-4 border-b border-gray-200 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">DREAD Score</th>
                  </tr>
                </thead>
                <tbody>
                  {highRiskIssues.map((issue, index) => (
                    <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                      <td className="py-2 px-4 border-b border-gray-200 text-sm">{issue['Threat Type']}</td>
                      <td className="py-2 px-4 border-b border-gray-200 text-sm">{issue['Scenario']}</td>
                      <td className="py-2 px-4 border-b border-gray-200 text-sm">
                        {(() => {
                          const report = reportData.find(r => {
                            if (!r.dread_assessment?.result) return false;
                            const dreadItems = getDreadItems(r.dread_assessment.result);
                            return dreadItems?.some(item => 
                              item['Threat Type'] === issue['Threat Type'] &&
                              item['Scenario'] === issue['Scenario']
                            );
                          });
                          return `${report?.details?.projectName || 'Unknown'} - ${new Date(report?.details?.timestamp || Date.now()).toLocaleDateString()}`;
                        })()}
                      </td>
                      <td className="py-2 px-4 border-b border-gray-200 text-sm">
                        <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">
                          {calculateDreadScore(issue).toFixed(1)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            ) : (
              <p className="text-gray-500">No high risk issues identified.</p>
            )
          ) : null}
        </div>
        
      </div>
      
      {/* Detailed Analytics Section */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-2xl font-semibold text-gray-700 mb-6">Detailed Analytics</h2>
        
        {/* STRIDE Analytics */}
        <div className="mb-8">
          <h3 className="text-xl font-medium text-gray-700 mb-4">STRIDE Analytics</h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Issues by STRIDE Category */}
            <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
              <h4 className="text-lg font-medium text-gray-700 mb-4">Issues by STRIDE Category</h4>
              <div className="h-64">
                <Bar 
                  data={strideData} 
                  options={{ 
                    maintainAspectRatio: false,
                    scales: {
                      y: {
                        beginAtZero: true
                      }
                    }
                  }} 
                />
              </div>
            </div>
            
            {/* STRIDE Statistics */}
            <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
              <h4 className="text-lg font-medium text-gray-700 mb-4">STRIDE Statistics</h4>
              <div className="grid grid-cols-2 gap-4">
                {Object.entries(strideData.labels).map((entry, index) => {
                  const [_, category] = entry;
                  return (
                    <div key={index} className="bg-white rounded-lg p-4 border border-gray-200">
                      <h5 className="text-sm font-medium text-gray-600">{category}</h5>
                      <p className="text-2xl font-bold text-gray-800">{strideData.datasets[0].data[index]}</p>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
        
        
        {/* Attack Path Analysis */}
        <div className="mb-8">
          <h3 className="text-xl font-medium text-gray-700 mb-4">Attack Path Analysis</h3>
          <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
            <div className="flex flex-col items-center justify-center h-64">
              <div className="text-5xl font-bold text-purple-600">
                {attackPathData.datasets[0].data[0]}
              </div>
              <div className="text-gray-500 mt-2">Total Attack Path Combinations</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;
