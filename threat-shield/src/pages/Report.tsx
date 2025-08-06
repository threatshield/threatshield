import React, { useState, useEffect, useRef, useMemo } from 'react';
import html2pdf from 'html2pdf.js';
import { useParams, useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import { 
  Threat, 
  DreadAssessmentItem, 
  AttackTreeNode,
  MitigationItem,
} from '../types/reportTypes';
import ReactFlow, { 
  Background, 
  Controls, 
  MiniMap, 
  Node, 
  Edge,
  NodeTypes,
  EdgeTypes,
  Position,
  Handle,
  MarkerType
} from 'reactflow';
import { NodeProps } from 'reactflow';
import 'reactflow/dist/style.css';

// Interface for parsed mitigation table rows
interface MitigationRow {
  threatType: string;
  scenario: string;
  mitigation: string;
}

// Function to parse markdown table into structured data
const parseMitigationTable = (markdown: string): MitigationRow[] => {
  try {
    // Handle empty or undefined markdown
    if (!markdown) {
      console.error('Markdown is empty or undefined');
      return [];
    }

    // Split the markdown table into rows
    const rows = markdown.split('\n').filter(row => row.trim() !== '' && !row.includes('---'));
    
    // Find the header row (it should contain column names)
    let headerRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if ((rows[i].includes('Threat Type') || rows[i].includes('Business Risk Type')) && rows[i].includes('Scenario')) {
        headerRowIndex = i;
        break;
      }
    }
    
    if (headerRowIndex === -1) {
      console.error('Could not find header row in markdown table');
      return [];
    }
    
    const headerRow = rows[headerRowIndex];
    const dataRows = rows.slice(headerRowIndex + 1).filter(row => row.includes('|'));
    
    // Determine the column indices for each field
    const headerCells = headerRow.split('|').map(cell => cell.trim());
    
    let threatTypeIndex = -1;
    let scenarioIndex = -1;
    let mitigationIndex = -1;
    
    headerCells.forEach((cell, index) => {
      if (cell.toLowerCase().includes('threat type')) threatTypeIndex = index;
      if (cell.toLowerCase().includes('scenario')) scenarioIndex = index;
      if (cell.toLowerCase().includes('mitigation')) mitigationIndex = index;
    });
    
    // We need Threat Type and Scenario
    
    return dataRows.map(row => {
      // Remove leading/trailing whitespace and split by |
      const cells = row.split('|').map(cell => cell.trim());
      
      // Extract values using the determined indices
      const threatType = cells[threatTypeIndex] || 'Unknown';
      const scenario = cells[scenarioIndex] || 'Unknown';
      const mitigation = cells[mitigationIndex] || '';
      
      return {
        threatType: threatType,
        scenario: scenario,
        mitigation: mitigation,
      };
    });
  } catch (error) {
    console.error('Error parsing mitigation table:', error);
    return [];
  }
};

// Custom node components with handles
const GoalNode = ({ data }: NodeProps) => (
  <div className="px-4 py-2 shadow-md rounded-md bg-red-100 border border-red-200 min-w-[150px]">
    <div className="font-bold text-red-800">{data.label}</div>
    <div className="nodrag" style={{ position: 'absolute', bottom: '-8px', left: '50%', transform: 'translateX(-50%)' }}>
      <Handle type="source" position={Position.Bottom} style={{ background: '#555' }} />
    </div>
    <div className="nodrag" style={{ position: 'absolute', top: '-8px', left: '50%', transform: 'translateX(-50%)' }}>
      <Handle type="target" position={Position.Top} style={{ background: '#555' }} />
    </div>
  </div>
);

const AttackNode = ({ data }: NodeProps) => (
  <div className="px-4 py-2 shadow-md rounded-md bg-yellow-100 border border-yellow-200 min-w-[150px]">
    <div className="font-bold text-yellow-800">{data.label}</div>
    <div className="nodrag" style={{ position: 'absolute', bottom: '-8px', left: '50%', transform: 'translateX(-50%)' }}>
      <Handle type="source" position={Position.Bottom} style={{ background: '#555' }} />
    </div>
    <div className="nodrag" style={{ position: 'absolute', top: '-8px', left: '50%', transform: 'translateX(-50%)' }}>
      <Handle type="target" position={Position.Top} style={{ background: '#555' }} />
    </div>
  </div>
);

const VulnerabilityNode = ({ data }: NodeProps) => (
  <div className="px-4 py-2 shadow-md rounded-md bg-blue-100 border border-blue-200 min-w-[150px]">
    <div className="font-bold text-blue-800">{data.label}</div>
    <div className="nodrag" style={{ position: 'absolute', bottom: '-8px', left: '50%', transform: 'translateX(-50%)' }}>
      <Handle type="source" position={Position.Bottom} style={{ background: '#555' }} />
    </div>
    <div className="nodrag" style={{ position: 'absolute', top: '-8px', left: '50%', transform: 'translateX(-50%)' }}>
      <Handle type="target" position={Position.Top} style={{ background: '#555' }} />
    </div>
  </div>
);

// Attack Tree Visualization Component
const AttackTreeVisualization: React.FC<{ attackTreeData: any }> = ({ attackTreeData }) => {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  
  // Define node types for ReactFlow
  const nodeTypes: NodeTypes = {
    goal: GoalNode,
    attack: AttackNode,
    vulnerability: VulnerabilityNode,
  };
  
  useEffect(() => {
    if (attackTreeData?.attack_tree?.nodes) {
      processAttackTreeData(attackTreeData.attack_tree.nodes);
    }
  }, [attackTreeData]);
  
  
  const processAttackTreeData = (treeNodes: AttackTreeNode[]) => {
    try {
      const flowNodes: Node<any>[] = [];
      const flowEdges: Edge<any>[] = [];
      
      // Create a map to store node positions
      const nodePositions: Record<string, { x: number, y: number }> = {};
      
      // Define spacing configurations for different methodologies
      const spacingConfig = {
        baseWidth: 250,
        level0: { xGap: 0 },
        level1: { xGapMultiplier: 1.8, siblingFactor: 0.5 },
        level2: { xGapMultiplier: 1.0, siblingFactor: 0.6 },
        verticalBase: 160,
        verticalIncrement: 25,
        horizontalOffset: 15
      };
      
      // Create nodes function with optimized positioning for attack trees
      const createNodes = (node: AttackTreeNode, level: number, position: number, totalSiblings: number, parentX: number = 0): void => {
        // Get the configuration
        const cfg = spacingConfig;
        
        // Dynamic spacing based on tree structure with increased gaps
        const baseWidth = cfg.baseWidth;
        
        // Calculate horizontal gap based on level and siblings with wider spacing
        let xGap: number = 0;
        if (level === 0) {
          // Root node
          xGap = 0;
        } else if (level === 1) {
          // First level nodes
          xGap = baseWidth * cfg.level1.xGapMultiplier * Math.max(1, totalSiblings * cfg.level1.siblingFactor);
        } else if (level === 2) {
          // Second level nodes
          xGap = baseWidth * cfg.level2.xGapMultiplier * Math.max(1, totalSiblings * cfg.level2.siblingFactor);
        } else {
          // Other levels - use default values if level-specific config doesn't exist
          let xGapMultiplier = 1.2;
          let siblingFactor = 0.4;
          
          // Try to get level-specific config if it exists
          if (level === 2 && cfg.level2) {
            xGapMultiplier = cfg.level2.xGapMultiplier;
            siblingFactor = cfg.level2.siblingFactor;
          } else if (level === 1 && cfg.level1) {
            xGapMultiplier = cfg.level1.xGapMultiplier;
            siblingFactor = cfg.level1.siblingFactor;
          }
          
          xGap = baseWidth * xGapMultiplier * Math.max(1, totalSiblings * siblingFactor);
        }
        
        // Vertical spacing increases with depth
        const yGap: number = cfg.verticalBase + (level * cfg.verticalIncrement);
        
        // Calculate position with improved centering and wider distribution
        let x: number = 0;
        let y: number = level * yGap; // Initialize y here as a mutable variable
        
        if (level === 0) {
          // Root node is centered
          x = 0;
        } else if (level === 1) {
          // First level nodes are distributed evenly with wider spacing
          const totalWidth: number = xGap * (totalSiblings - 1);
          const startX: number = -totalWidth / 2;
          x = startX + (position * xGap);
        } else {
          // Child nodes are centered under their parent with wider spacing
          const childOffset: number = ((totalSiblings - 1) * xGap) / 2;
          x = parentX - childOffset + (position * xGap);
          
          // Add horizontal offset to prevent perfect vertical alignment
          // This helps with visibility when nodes have multiple children
          const offsetMultiplier: number = position - (totalSiblings - 1) / 2;
          
          // Add a slight offset for all levels
          x += offsetMultiplier * 15;
        }
        
        // Store the position for edge creation
        nodePositions[node.id] = { x, y };
        
        // Create the node with improved styling
        flowNodes.push({
          id: node.id,
          type: node.type || 'goal',
          position: { x, y },
          data: { label: node.label },
          style: { 
            width: 'auto',
            maxWidth: '400px', // Increased maximum width for all nodes
            padding: '10px', // Added more padding for better text spacing
            fontSize: '14px' // Slightly larger font for better readability
          }
        });
        
        // Process children if any
        if (node.children && node.children.length > 0) {
          node.children.forEach((childNode, idx) => {
            createNodes(childNode, level + 1, idx, node.children!.length, x);
          });
        }
      };
      
      // Get the root node
      const rootNode = treeNodes.find(node => node.type === 'goal') || treeNodes[0];
      
      if (rootNode) {
        // Start creating nodes from the root
        createNodes(rootNode, 0, 0, 1, 0);
        
        // Second pass: create edges
        const createEdges = (node: AttackTreeNode) => {
          if (node.children && node.children.length > 0) {
            node.children.forEach(childNode => {
              flowEdges.push({
                id: `${node.id}-${childNode.id}`,
                source: node.id,
                target: childNode.id,
                type: 'smoothstep',
                animated: true,
                style: { 
                  stroke: '#000', 
                  strokeWidth: 2,
                  opacity: 0.8
                },
                markerEnd: {
                  type: MarkerType.ArrowClosed,
                  width: 20,
                  height: 20,
                  color: '#000'
                }
              });
              
              // Process child's edges recursively
              createEdges(childNode);
            });
          }
        };
        
        // Create edges starting from the root
        createEdges(rootNode);
        
        setNodes(flowNodes);
        setEdges(flowEdges);
      }
    } catch (error) {
      console.error("Error processing attack tree data:", error);
    }
  };
  
  return (
      <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.5 }}
      minZoom={0.1}
      maxZoom={1.5}
      defaultEdgeOptions={{
        type: 'smoothstep',
        animated: true
      }}
    >
      <Background />
      <Controls />
      <MiniMap />
    </ReactFlow>
  );
};

// API response interfaces
interface ThreatModelData {
  timestamp: string;
  result: {
    result: {
      raw_response: {
        threat_model: Threat[];
        improvement_suggestions: string[];
      };
      markdown: string;
      threat_model?: Threat[];
    };
  };
}

interface DreadAssessmentData {
  timestamp: string;
  result: {
    result: {
      raw_response: {
        'Risk Assessment': DreadAssessmentItem[];
      };
      markdown: string;
    };
  };
}

interface MitigationData {
  timestamp: string;
  result: {
    result: {
      markdown: string;
      raw_response?: {
        mitigations: MitigationItem[];
      };
    };
  };
}

interface AttackTreeData {
  timestamp: string;
  result: {
    result: {
      markdown: string;
      attack_tree?: {
        nodes: AttackTreeNode[];
      };
    };
  };
}

// Nested API response structure
interface ApiResponse {
  timestamp: string;
  result: {
    threat_model?: ThreatModelData;
    dread_assessment?: DreadAssessmentData;
    mitigation?: MitigationData;
    attack_tree?: AttackTreeData;
  };
}

// Component state interface
interface ReportData {
  threat_model: {
    data: ThreatModelData | null;
    loading: boolean;
    error: string | null;
  };
  dread_assessment: {
    data: DreadAssessmentData | null;
    loading: boolean;
    error: string | null;
  };
  mitigation: {
    data: MitigationData | null;
    loading: boolean;
    error: string | null;
  };
  attack_tree: {
    data: AttackTreeData | null;
    loading: boolean;
    error: string | null;
  };
}

const Report: React.FC = () => {
  const { assessment_id } = useParams<{ assessment_id: string }>();
  const navigate = useNavigate();
  const [reportData, setReportData] = useState<ReportData>({
    threat_model: { data: null, loading: true, error: null },
    dread_assessment: { data: null, loading: true, error: null },
    mitigation: { data: null, loading: true, error: null },
    attack_tree: { data: null, loading: true, error: null }
  });
  const [introduction, setIntroduction] = useState<string | null>(null);
  const [introductionLoading, setIntroductionLoading] = useState<boolean>(true);
  const [introductionError, setIntroductionError] = useState<string | null>(null);
  const [additionalInfo, setAdditionalInfo] = useState<{
    functional_flows: string | null;
    third_party_integrations: string | null;
  }>({ functional_flows: null, third_party_integrations: null });
  const [additionalInfoLoading, setAdditionalInfoLoading] = useState<boolean>(true);
  const [additionalInfoError, setAdditionalInfoError] = useState<string | null>(null);
  const [assessmentDetails, setAssessmentDetails] = useState<{
    projectName: string;
    timestamp: string;
    threatModelingMethodology: string;
  } | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [downloadingMarkdown, setDownloadingMarkdown] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [showDownloadOptions, setShowDownloadOptions] = useState(false);
  const downloadMenuRef = useRef<HTMLDivElement>(null);
  
  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (downloadMenuRef.current && !downloadMenuRef.current.contains(event.target as HTMLElement)) {
        setShowDownloadOptions(false);
      }
    }
    
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [downloadMenuRef]);

  // Fetch assessment details from storage history
  useEffect(() => {
    const fetchAssessmentDetails = async () => {
      if (assessment_id) {
        try {
          const response = await apiService.getStorageHistory();
          if (response && response.data) {
            const report = response.data.find(r => r.id === assessment_id);
            if (report && report.details) {
              setAssessmentDetails({
                projectName: report.details.projectName,
                timestamp: report.details.timestamp,
                threatModelingMethodology: report.details.threatModelingMethodology || ''
              });
            } else {
              console.error('Report or details not found for assessment ID:', assessment_id);
            }
          } else {
            console.error('Failed to fetch storage history');
          }
        } catch (error) {
          console.error('Error fetching assessment details:', error);
        }
      }
    };
    
    fetchAssessmentDetails();
  }, [assessment_id]);

  // Fetch introduction from RAG result
  // Fetch additional info
  useEffect(() => {
    const fetchAdditionalInfo = async () => {
      if (!assessment_id) {
        setAdditionalInfoLoading(false);
        return;
      }

      try {
        setAdditionalInfoLoading(true);
        console.log('Fetching additional info for assessment ID:', assessment_id);
        
        const data = await apiService.getAdditionalInfo(assessment_id);
        console.log('Additional info data received:', data);
        
        if (data && data.result) {
          setAdditionalInfo({
            functional_flows: data.result.functional_flows || null,
            third_party_integrations: data.result.third_party_integrations || null
          });
        } else {
          console.error('Invalid additional info data structure:', data);
          setAdditionalInfoError('Could not load additional information');
        }
        setAdditionalInfoLoading(false);
      } catch (error) {
        console.error('Error fetching additional info:', error);
        setAdditionalInfoError(`Failed to load additional information: ${error instanceof Error ? error.message : 'Unknown error'}`);
        setAdditionalInfoLoading(false);
      }
    };

    fetchAdditionalInfo();
  }, [assessment_id]);

  useEffect(() => {
    const fetchIntroduction = async () => {
      if (!assessment_id) {
        setIntroductionLoading(false);
        return;
      }

      try {
        setIntroductionLoading(true);
        console.log('Fetching RAG result for assessment ID:', assessment_id);
        
        const data = await apiService.getRAGResult(assessment_id);
        console.log('RAG result data received:', data);
        
        // Check if data exists
        if (!data) {
          console.error('No data returned from getRAGResult');
          throw new Error('No data returned from API');
        }
        
        // Log the structure of the data to help diagnose issues
        console.log('RAG result data keys:', Object.keys(data));
        
        // Try different possible structures for the RAG result
        let resultText = '';
        
        // Option 1: data.result is a string directly containing the markdown
        if (data.result && typeof data.result === 'string') {
          console.log('Found result as string');
          resultText = data.result;
        } 
        // Option 2: data.result.result is a string
        else if (data.result && data.result.result && typeof data.result.result === 'string') {
          console.log('Found result.result as string');
          resultText = data.result.result;
        }
        // Option 3: data.result is an object with a text or content field
        else if (data.result && typeof data.result === 'object') {
          if (data.result.text && typeof data.result.text === 'string') {
            console.log('Found result.text as string');
            resultText = data.result.text;
          } else if (data.result.content && typeof data.result.content === 'string') {
            console.log('Found result.content as string');
            resultText = data.result.content;
          }
        }
        // Option 4: data itself contains the introduction text
        else if (typeof data === 'string') {
          console.log('Data itself is a string');
          resultText = data;
        }
        
        if (resultText) {
          console.log('RAG result text (first 100 chars):', resultText.substring(0, 100));
          
          // Extract the introduction section (between # Introduction and the next #)
          if (resultText.includes('# Introduction')) {
            console.log('Found Introduction header in RAG result');
            const parts = resultText.split('# Introduction');
            if (parts.length > 1) {
              const afterIntro = parts[1];
              const nextHeaderIndex = afterIntro.indexOf('#');
              
              let introText;
              if (nextHeaderIndex !== -1) {
                introText = afterIntro.substring(0, nextHeaderIndex).trim();
              } else {
                introText = afterIntro.trim();
              }
              
              console.log('Extracted introduction (first 100 chars):', introText.substring(0, 100));
              setIntroduction(introText || 'No introduction available.');
            } else {
              console.log('Split on Introduction header returned unexpected result');
              setIntroduction('No introduction content available.');
            }
          } else {
            // If there's no Introduction header, use the first paragraph
            console.log('No Introduction header found, using first paragraph');
            const firstParagraph = resultText.split('\n\n')[0]?.trim();
            console.log('Using first paragraph as introduction:', firstParagraph);
            setIntroduction(firstParagraph || 'No introduction available.');
          }
        } else {
          console.error('Could not find introduction text in RAG result:', data);
          setIntroductionError('Could not find introduction text in RAG result');
          setIntroduction('No introduction available.');
        }
        setIntroductionLoading(false);
      } catch (error) {
        console.error('Error fetching introduction:', error);
        setIntroductionError(`Failed to load introduction: ${error instanceof Error ? error.message : 'Unknown error'}`);
        setIntroductionLoading(false);
      }
    };

    fetchIntroduction();
  }, [assessment_id]);

  useEffect(() => {
    const fetchReportData = async () => {
      if (!assessment_id) {
        console.log('No assessment_id provided');
        return;
      }

      console.log('Fetching report data for assessment_id:', assessment_id);
      try {
        console.log('Making API call to getReport...');
        const data = await apiService.getReport(assessment_id);
        console.log('Received report data:', data);
        
        if (data && data.result) {
          // Extract the nested data from the response with proper type checking
          const threatModel = data.result.threat_model;
          const dreadAssessment = data.result.dread_assessment;
          const mitigation = data.result.mitigation;
          const attackTree = data.result.attack_tree;

          // Helper functions to transform API response to match our interfaces
          const transformThreatModel = (data: any): ThreatModelData => ({
            timestamp: data.timestamp,
            result: {
              result: {
                raw_response: {
                  threat_model: data.result.result.raw_response?.threat_model || [],
                  improvement_suggestions: data.result.result.raw_response?.improvement_suggestions || []
                },
                markdown: data.result.result.markdown || '',
                threat_model: data.result.result.threat_model
              }
            }
          });

          const transformDreadAssessment = (data: any): DreadAssessmentData => ({
            timestamp: data.timestamp,
            result: {
              result: {
                raw_response: {
                  'Risk Assessment': data.result.result.raw_response?.['Risk Assessment'] || []
                },
                markdown: data.result.result.markdown || ''
              }
            }
          });

          const transformMitigation = (data: any): MitigationData => ({
            timestamp: data.timestamp,
            result: {
              result: {
                markdown: data.result.result.markdown || '',
                raw_response: {
                  mitigations: data.result.result.raw_response?.mitigations || []
                }
              }
            }
          });

          const transformAttackTree = (data: any): AttackTreeData => ({
            timestamp: data.timestamp,
            result: {
              result: {
                markdown: data.result.result.markdown || '',
                attack_tree: data.result.result.attack_tree
              }
            }
          });

          // Extract and transform the data to match our interfaces
          setReportData({
            threat_model: {
              data: threatModel ? transformThreatModel(threatModel) : null,
              loading: false,
              error: null
            },
            dread_assessment: {
              data: dreadAssessment ? transformDreadAssessment(dreadAssessment) : null,
              loading: false,
              error: null
            },
            mitigation: {
              data: mitigation ? transformMitigation(mitigation) : null,
              loading: false,
              error: null
            },
            attack_tree: {
              data: attackTree ? transformAttackTree(attackTree) : null,
              loading: false,
              error: null
            }
          });
        } else {
          console.error('Invalid data structure received:', data);
          throw new Error('Invalid data structure received from server');
        }
      } catch (err) {
        console.error('Error fetching report:', err);
        setReportData({
          threat_model: { data: null, loading: false, error: 'Failed to load threat model' },
          dread_assessment: { data: null, loading: false, error: 'Failed to load DREAD assessment' },
          mitigation: { data: null, loading: false, error: 'Failed to load mitigations' },
          attack_tree: { data: null, loading: false, error: 'Failed to load attack tree' }
        });
      }
    };

    fetchReportData();
  }, [assessment_id]);

  const handleChatClick = () => {
    if (assessment_id) {
      navigate(`/chat/${assessment_id}`);
    }
  };

  const reportRef = useRef<HTMLDivElement>(null);
  const threatModelRef = useRef<HTMLDivElement>(null);
  const coverPageRef = useRef<HTMLDivElement>(null);

  // Function to generate simplified mermaid diagram without styling
  const generateSimplifiedMermaidDiagram = (nodes: AttackTreeNode[]): string => {
    let mermaidContent = "graph TD\n";
    const processedNodeIds = new Set<string>();
    
    // Function to recursively process nodes and their connections
    const processNode = (node: AttackTreeNode) => {
      if (processedNodeIds.has(node.id)) return;
      processedNodeIds.add(node.id);
      
      // Add node definition
      mermaidContent += `    ${node.id}["${node.label.replace(/"/g, "'")}"]\n`;
      
      // Process children and connections
      if (node.children && node.children.length > 0) {
        node.children.forEach(child => {
          // Add connection
          mermaidContent += `    ${node.id} --> ${child.id}\n`;
          
          // Process child node
          processNode(child);
        });
      }
    };
    
    // Get the root node
    const rootNode = nodes.find(node => node.type === 'goal') || nodes[0];
    if (rootNode) {
      processNode(rootNode);
    }
    
    return mermaidContent;
  };

  const handleDownload = async () => {
    if (!assessment_id || !reportRef.current || !threatModelRef.current || !coverPageRef.current) return;

    try {
      setDownloading(true);
      setDownloadError(null);

      // Create a temporary container for the PDF content
      const tempContainer = document.createElement('div');
      
      // Add the cover page
      const coverPage = document.createElement('div');
      coverPage.style.cssText = `
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
        padding: 40px;
        page-break-after: always;
      `;
      
      coverPage.innerHTML = `
        <div style="text-align: center;">
        <h1 style="font-size: 30px; font-weight: bold; color: #1f2937; margin-bottom: 32px;">
            Threat Modelling Report
          </h1>
          <h2 style="font-size: 32px; font-weight: bold; color: #1f2937; margin-bottom: 32px;">
            ${assessmentDetails?.projectName || 'Security Assessment Report'}
          </h2>
          <p style="font-size: 18px; color: #6b7280; margin-top: 32px;">
            ${new Date().toLocaleDateString()}
          </p>
          <p style="font-size: 14px; color: #4b5563; margin-top: 16px;">
            Note: This report is generated using <b>${assessmentDetails?.threatModelingMethodology}</b> methodology.
          </p>
        </div>
      `;
      
      tempContainer.appendChild(coverPage);
      
      // We're not adding the introduction as a separate page anymore
      // This will prevent duplication issues
      console.log('Skipping separate introduction page in PDF export');
      
      // Simply clone all content sections except the cover page and hidden elements
      const allContent = Array.from(reportRef.current.children).filter(
        child => child !== coverPageRef.current && !child.classList.contains('print:hidden')
      );
      
      console.log(`Adding ${allContent.length} sections to PDF`);
      
      // Process each section
      allContent.forEach(child => {
        // Check if this is the attack tree section
        if (child.querySelector('.bg-gradient-to-r.from-blue-500.to-blue-700')) {
          // This is the attack tree section - create a modified version with mermaid diagram
          const attackTreeSection = child.cloneNode(true) as HTMLElement;
          
          // Find the visualization container and replace it with mermaid diagram
          const visualizationContainer = attackTreeSection.querySelector('.w-full.border.border-gray-200.rounded-lg.overflow-hidden');
          
          if (visualizationContainer && reportData.attack_tree.data?.result?.result?.attack_tree?.nodes) {
            // Generate mermaid diagram
            const mermaidDiagram = generateSimplifiedMermaidDiagram(reportData.attack_tree.data.result.result.attack_tree.nodes);
            
            // Replace the visualization with mermaid code
            visualizationContainer.innerHTML = `
              <div style="padding: 20px; background-color: #f8fafc; border-radius: 8px; width: 100%; max-width: none;">
                <h3 style="font-size: 18px; margin-bottom: 16px; color: #1e3a8a;">Attack Tree Diagram</h3>
                <pre style="background-color: #f1f5f9; padding: 16px; border-radius: 8px; overflow: visible; font-family: monospace; font-size: 12px; white-space: pre-wrap; word-break: break-word; width: 100%;">
\`\`\`mermaid
${mermaidDiagram}
\`\`\`
                </pre>
              </div>
            `;
            
            // Remove any height constraints that might cause cropping
            if (visualizationContainer.hasAttribute('style')) {
              const style = visualizationContainer.getAttribute('style') || '';
              visualizationContainer.setAttribute('style', style.replace(/height:[^;]+;?/g, ''));
            }
          }
          
          tempContainer.appendChild(attackTreeSection);
        } else {
          // For other sections, just clone them
          tempContainer.appendChild(child.cloneNode(true));
        }
      });

      const opt = {
        margin: 10,
        filename: `security-assessment-report-${assessment_id}.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { 
          scale: 2,
          useCORS: true,
          logging: true
        },
        jsPDF: { 
          unit: 'mm', 
          format: 'a4', 
          orientation: 'portrait' as 'portrait'
        }
      };

      await html2pdf().set(opt).from(tempContainer).save();
    } catch (err) {
      console.error('Error generating PDF:', err);
      setDownloadError('Failed to generate PDF report');
    } finally {
      setDownloading(false);
    }
  };

  const handleDownloadJson = async () => {
    if (!assessment_id) return;

    try {
      setDownloadingMarkdown(true);
      setDownloadError(null);

      // Create a JSON object with all the report data including the introduction
      const jsonReportData = {
        metadata: {
          id: assessment_id,
          name: assessmentDetails ? `${assessmentDetails.projectName}` : assessment_id,
          methodology: assessmentDetails?.threatModelingMethodology || '',
          timestamp: new Date().toISOString(),
          generated: new Date().toLocaleDateString()
        },
        introduction: introduction || '',
        additional_info: {
          functional_flows: additionalInfo.functional_flows || null,
          third_party_integrations: additionalInfo.third_party_integrations || null
        },
        threat_model: reportData.threat_model.data?.result?.result?.raw_response || null,
        dread_assessment: reportData.dread_assessment.data?.result?.result?.raw_response || null,
        mitigation: reportData.mitigation.data?.result?.result?.raw_response || null,
        attack_tree: reportData.attack_tree.data?.result?.result?.attack_tree || null
      };

      // Create a blob with the JSON data
      const blob = new Blob([JSON.stringify(jsonReportData, null, 2)], { type: 'application/json' });
      
      // Create a download link
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `threat-shield-report-${assessment_id}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Error downloading JSON report:', err);
      setDownloadError('Failed to download JSON report');
    } finally {
      setDownloadingMarkdown(false);
    }
  };

  const handleDownloadBasicPdf = async () => {
    if (!assessment_id) return;

    try {
      setDownloadingMarkdown(true);
      setDownloadError(null);

      // Generate markdown content
      let markdownContent = `# Threat Modelling Report\n\n`;
      
      // Add report header
      markdownContent += `## Security Assessment Report\n\n`;
      markdownContent += `- **Name**: ${assessmentDetails ? `${assessmentDetails.projectName}` : assessment_id}\n`;
      markdownContent += `- **Methodology**:  ${assessmentDetails?.threatModelingMethodology}\n`;
      markdownContent += `- **Assessment ID**: ${assessment_id}\n`;
      markdownContent += `- **Generated**: ${new Date().toLocaleDateString()}\n\n`;

      // Add introduction section if available
      if (introduction) {
        markdownContent += `## Introduction\n\n${introduction}\n\n`;
      }

      // Add functional flows section if available
      if (additionalInfo.functional_flows) {
        markdownContent += `## Functional Flows\n\n${additionalInfo.functional_flows}\n\n`;
      }

      // Add third party integrations section if available
      if (additionalInfo.third_party_integrations) {
        markdownContent += `## Third Party Integrations\n\n${additionalInfo.third_party_integrations}\n\n`;
      }

      // Add Threat Model section
      if (reportData.threat_model.data) {
        markdownContent += `## Threat Model Analysis\n\n`;
        
        // Add threat model summary
        const threatModelData = reportData.threat_model.data.result.result;
        const threatCount = threatModelData.raw_response.threat_model?.length || 0;
        
        markdownContent += `### Threat Summary\n\n`;
        markdownContent += `- **Total Threats**: ${threatCount}\n`;
        
        // Calculate most common threat type
        if (threatCount > 0) {
          const threatTypes = threatModelData.raw_response.threat_model.map((t: Threat) => t['Threat Type']);
          const counts: Record<string, number> = {};
          threatTypes.forEach((type: string) => {
            counts[type] = (counts[type] || 0) + 1;
          });
          
          let maxType = '';
          let maxCount = 0;
          Object.entries(counts).forEach(([type, count]) => {
            if (count > maxCount) {
              maxType = type;
              maxCount = count;
            }
          });
          
          markdownContent += `- **Most Common Threat**: ${maxType || 'None'}\n`;
        }
        
        markdownContent += `- **Improvement Suggestions**: ${threatModelData.raw_response.improvement_suggestions?.length || 0}\n\n`;
        
        // Add threats table
        markdownContent += `### Threats\n\n`;
        markdownContent += `| Threat Type | Scenario | Potential Impact |\n`;
        markdownContent += `| ----------- | -------- | ---------------- |\n`;
        
        threatModelData.raw_response.threat_model?.forEach((threat: Threat) => {
          markdownContent += `| ${threat['Threat Type']} | ${threat['Scenario']} | ${threat['Potential Impact']} |\n`;
        });
        
        markdownContent += `\n`;
        
        // Add improvement suggestions
        markdownContent += `### Improvement Suggestions\n\n`;
        threatModelData.raw_response.improvement_suggestions?.forEach((suggestion: string, index: number) => {
          markdownContent += `${index + 1}. ${suggestion}\n`;
        });
        
        markdownContent += `\n`;
      }

      // Add DREAD Assessment section
      if (reportData.dread_assessment.data) {
        markdownContent += `## DREAD Risk Assessment\n\n`;
        
        const dreadData = reportData.dread_assessment.data.result.result.raw_response['Risk Assessment'] || [];
        
        if (dreadData.length > 0) {
          // Calculate averages
          let totalDamage = 0;
          let totalReproducibility = 0;
          let totalExploitability = 0;
          let totalAffectedUsers = 0;
          let totalDiscoverability = 0;
          
          dreadData.forEach((item: DreadAssessmentItem) => {
            totalDamage += Number(item['Damage Potential']) || 0;
            totalReproducibility += Number(item['Reproducibility']) || 0;
            totalExploitability += Number(item['Exploitability']) || 0;
            totalAffectedUsers += Number(item['Affected Users']) || 0;
            totalDiscoverability += Number(item['Discoverability']) || 0;
          });
          
          const count = dreadData.length;
          const avgDamage = totalDamage / count;
          const avgReproducibility = totalReproducibility / count;
          const avgExploitability = totalExploitability / count;
          const avgAffectedUsers = totalAffectedUsers / count;
          const avgDiscoverability = totalDiscoverability / count;
          
          // Find highest risk threat
          let highestRiskThreat = null;
          let highestRiskScore = 0;
          
          dreadData.forEach((item: DreadAssessmentItem) => {
            const score = (
              Number(item['Damage Potential']) +
              Number(item['Reproducibility']) +
              Number(item['Exploitability']) +
              Number(item['Affected Users']) +
              Number(item['Discoverability'])
            ) || 0;
            
            if (score > highestRiskScore) {
              highestRiskScore = score;
              highestRiskThreat = item;
            }
          });
          
          // Add DREAD summary
          markdownContent += `### DREAD Risk Summary\n\n`;
          markdownContent += `- **Average DREAD Score**: ${((avgDamage + avgReproducibility + avgExploitability + avgAffectedUsers + avgDiscoverability) / 5).toFixed(1)}\n`;
          
          // Determine highest risk category
          const scores = [
            { name: 'Damage', value: avgDamage },
            { name: 'Reproducibility', value: avgReproducibility },
            { name: 'Exploitability', value: avgExploitability },
            { name: 'Affected Users', value: avgAffectedUsers },
            { name: 'Discoverability', value: avgDiscoverability }
          ];
          
          scores.sort((a, b) => b.value - a.value);
          markdownContent += `- **Highest Risk Category**: ${scores[0].name} (Score: ${scores[0].value.toFixed(1)})\n`;
          markdownContent += `- **Threats Assessed**: ${dreadData.length}\n`;
          
          if (highestRiskThreat) {
            markdownContent += `- **Highest Risk Threat**: ${highestRiskThreat['Threat Type']} (Score: ${highestRiskScore})\n\n`;
          }
          
          // Add DREAD assessment table
          markdownContent += `### DREAD Assessment\n\n`;
          markdownContent += `| Threat Type | Scenario | Damage | Reproducibility | Exploitability | Affected Users | Discoverability |\n`;
          markdownContent += `| ----------- | -------- | ------ | --------------- | -------------- | -------------- | --------------- |\n`;
          
          dreadData.forEach((assessment: DreadAssessmentItem) => {
            markdownContent += `| ${assessment['Threat Type']} | ${assessment['Scenario']} | ${assessment['Damage Potential']} | ${assessment['Reproducibility']} | ${assessment['Exploitability']} | ${assessment['Affected Users']} | ${assessment['Discoverability']} |\n`;
          });
          
          markdownContent += `\n`;
        } else {
          markdownContent += `No DREAD assessment data available.\n\n`;
        }
      }
      
      // Add Mitigation section
      if (reportData.mitigation.data) {
        markdownContent += `## Mitigation Strategies\n\n`;
        
        const mitigations = reportData.mitigation.data.result.result.raw_response?.mitigations || [];
        
        if (mitigations.length > 0) {
          // Create table header
          markdownContent += `| Threat Type | Scenario | Suggested Mitigation(s) |\n`;
          markdownContent += `| ----------- | -------- | ---------------------- |\n`;
          
          // Add table rows
          mitigations.forEach((mitigation: MitigationItem) => {
            const threatType = mitigation['Threat Type'] || 'Unknown';
            const scenario = mitigation['Scenario'] || '';
            const mitigationText = mitigation['Suggested Mitigation(s)'] || '';
            
            // Format the mitigation text to work well in markdown table
            const formattedMitigation = mitigationText.replace(/\n/g, ' ').replace(/\|/g, '\\|');
            
            markdownContent += `| ${threatType} | ${scenario} | ${formattedMitigation} |\n`;
          });
          
          markdownContent += `\n`;
        } else {
          markdownContent += `No mitigation data available.\n\n`;
        }
      }

      // Enhanced markdown to HTML conversion function
      const markdownToHtml = (markdown: string) => {
        // Process markdown in stages for better conversion
        let html = markdown;
        
        // Headers
        html = html.replace(/^# (.*$)/gm, '<h1 style="font-size: 24px; margin-top: 24px; margin-bottom: 16px; font-weight: bold; color: #1f2937;">$1</h1>');
        html = html.replace(/^## (.*$)/gm, '<h2 style="font-size: 20px; margin-top: 20px; margin-bottom: 14px; font-weight: bold; color: #374151;">$1</h2>');
        html = html.replace(/^### (.*$)/gm, '<h3 style="font-size: 18px; margin-top: 18px; margin-bottom: 12px; font-weight: bold; color: #4b5563;">$1</h3>');
        
        // Text formatting
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
        
        // Lists
        html = html.replace(/^\s*[-*+]\s+(.*?)$/gm, '<li style="margin-bottom: 6px;">$1</li>');
        html = html.replace(/(<li.*?>.*?<\/li>)(\s*<li.*?>)/g, '$1$2');
        html = html.replace(/(<li.*?>.*?<\/li>)+/g, '<ul style="margin-top: 10px; margin-bottom: 10px; padding-left: 20px;">$&</ul>');
        
        // Numbered lists
        html = html.replace(/^\s*(\d+)\.\s+(.*?)$/gm, '<li style="margin-bottom: 6px;">$2</li>');
        html = html.replace(/(<li.*?>.*?<\/li>)(\s*<li.*?>)/g, '$1$2');
        html = html.replace(/(<li.*?>.*?<\/li>)+/g, '<ol style="margin-top: 10px; margin-bottom: 10px; padding-left: 20px;">$&</ol>');
        
        // Paragraphs
        html = html.replace(/^(?!<[a-z][^>]*>)([^<].*?)$/gm, '<p style="margin-top: 10px; margin-bottom: 10px;">$1</p>');
        
        // Tables - more robust table handling
        const tableRegex = /\|(.+)\|\n\|[-:| ]+\|\n((?:\|.+\|\n)+)/g;
        html = html.replace(tableRegex, (match, headerRow, bodyRows) => {
          // Process header
          const headers = headerRow.split('|').map((cell: string) => cell.trim()).filter(Boolean);
          const headerHtml = headers.map((header: string) => `<th style="padding: 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: bold;">${header}</th>`).join('');
          
          // Process body rows
          const rows = bodyRows.trim().split('\n');
          const bodyHtml = rows.map((row: string) => {
            const cells = row.split('|').map((cell: string) => cell.trim()).filter(Boolean);
            return `<tr>${cells.map((cell: string) => `<td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${cell}</td>`).join('')}</tr>`;
          }).join('');
          
          return `<table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
            <thead><tr>${headerHtml}</tr></thead>
            <tbody>${bodyHtml}</tbody>
          </table>`;
        });
        
        // Fix any remaining newlines
        html = html.replace(/\n\n+/g, '<br/><br/>');
        
        return html;
      };

      // Create HTML content
      const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Threat Shield Report</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
            h1 { color: #1f2937; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px; }
            h2 { color: #374151; margin-top: 30px; }
            h3 { color: #4b5563; }
            table { border-collapse: collapse; width: 100%; margin: 20px 0; }
            td, th { padding: 8px; text-align: left; }
            tr:nth-child(even) { background-color: #f9fafb; }
          </style>
        </head>
        <body>
          ${markdownToHtml(markdownContent)}
        </body>
        </html>
      `;

      // Create a temporary container with the HTML content
      const tempContainer = document.createElement('div');
      tempContainer.innerHTML = htmlContent;
      
      // Use html2pdf to convert to PDF
      const opt = {
        margin: 10,
        filename: `security-assessment-report-basic-${assessment_id}.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2 },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' as 'portrait' }
      };

      await html2pdf().set(opt).from(tempContainer).save();
      
    } catch (err) {
      console.error('Error generating basic PDF report:', err);
      setDownloadError('Failed to generate basic PDF report');
    } finally {
      setDownloadingMarkdown(false);
    }
  };

  const handleDownloadMarkdown = async () => {
    if (!assessment_id) return;

    try {
      setDownloadingMarkdown(true);
      setDownloadError(null);

      // Generate markdown content
      let markdownContent = `# Threat Modelling Report\n\n`;
      
      // Add report header
      markdownContent += `## Security Assessment Report\n\n`;
      markdownContent += `- **Name**: ${assessmentDetails ? `${assessmentDetails.projectName}` : assessment_id}\n`;
      markdownContent += `- **Methodology**:  ${assessmentDetails?.threatModelingMethodology}\n`;
      markdownContent += `- **Assessment ID**: ${assessment_id}\n`;
      markdownContent += `- **Generated**: ${new Date().toLocaleDateString()}\n\n`;

      // Add introduction section if available
      if (introduction) {
        markdownContent += `## Introduction\n\n${introduction}\n\n`;
      }

      // Add functional flows section if available
      if (additionalInfo.functional_flows) {
        markdownContent += `## Functional Flows\n\n${additionalInfo.functional_flows}\n\n`;
      }

      // Add third party integrations section if available
      if (additionalInfo.third_party_integrations) {
        markdownContent += `## Third Party Integrations\n\n${additionalInfo.third_party_integrations}\n\n`;
      }

      // Add Threat Model section
      if (reportData.threat_model.data) {
        markdownContent += `## Threat Model Analysis\n\n`;
        
        // Add threat model summary
        const threatModelData = reportData.threat_model.data.result.result;
        const threatCount = threatModelData.raw_response.threat_model?.length || 0;
        
        markdownContent += `### Threat Summary\n\n`;
        markdownContent += `- **Total Threats**: ${threatCount}\n`;
        
        // Calculate most common threat type
        if (threatCount > 0) {
          const threatTypes = threatModelData.raw_response.threat_model.map((t: Threat) => t['Threat Type']);
          const counts: Record<string, number> = {};
          threatTypes.forEach((type: string) => {
            counts[type] = (counts[type] || 0) + 1;
          });
          
          let maxType = '';
          let maxCount = 0;
          Object.entries(counts).forEach(([type, count]) => {
            if (count > maxCount) {
              maxType = type;
              maxCount = count;
            }
          });
          
          markdownContent += `- **Most Common Threat**: ${maxType || 'None'}\n`;
        }
        
        markdownContent += `- **Improvement Suggestions**: ${threatModelData.raw_response.improvement_suggestions?.length || 0}\n\n`;
        
        // Add threats table
        markdownContent += `### Threats\n\n`;
        markdownContent += `| Threat Type | Scenario | Potential Impact |\n`;
        markdownContent += `| ----------- | -------- | ---------------- |\n`;
        
        threatModelData.raw_response.threat_model?.forEach((threat: Threat) => {
          markdownContent += `| ${threat['Threat Type']} | ${threat['Scenario']} | ${threat['Potential Impact']} |\n`;
        });
        
        markdownContent += `\n`;
        
        // Add improvement suggestions
        markdownContent += `### Improvement Suggestions\n\n`;
        threatModelData.raw_response.improvement_suggestions?.forEach((suggestion: string, index: number) => {
          markdownContent += `${index + 1}. ${suggestion}\n`;
        });
        
        markdownContent += `\n`;
      }
      
      // Function to generate simplified mermaid diagram without styling
      const generateSimplifiedMermaidDiagram = (nodes: AttackTreeNode[]): string => {
        let mermaidContent = "graph TD\n";
        const processedNodeIds = new Set<string>();
        
        // Function to recursively process nodes and their connections
        const processNode = (node: AttackTreeNode) => {
          if (processedNodeIds.has(node.id)) return;
          processedNodeIds.add(node.id);
          
          // Add node definition
          mermaidContent += `    ${node.id}["${node.label.replace(/"/g, "'")}"]\n`;
          
          // Process children and connections
          if (node.children && node.children.length > 0) {
            node.children.forEach(child => {
              // Add connection
              mermaidContent += `    ${node.id} --> ${child.id}\n`;
              
              // Process child node
              processNode(child);
            });
          }
        };
        
        // Get the root node
        const rootNode = nodes.find(node => node.type === 'goal') || nodes[0];
        if (rootNode) {
          processNode(rootNode);
        }
        
        return mermaidContent;
      };

      // Add Attack Tree section
      if (reportData.attack_tree.data) {
        markdownContent += `## Attack Tree Analysis\n\n`;
        
        // Get the attack tree data
        const attackTreeData = reportData.attack_tree.data.result.result;
        
        // Generate mermaid diagram
        if (attackTreeData.attack_tree?.nodes) {
          // Generate simplified mermaid diagram from nodes
          const mermaidDiagram = generateSimplifiedMermaidDiagram(attackTreeData.attack_tree.nodes);
          markdownContent += `\`\`\`mermaid\n${mermaidDiagram}\`\`\`\n\n`;
        } else {
          // Fallback to the provided static mermaid diagram
          markdownContent += `\`\`\`mermaid\ngraph TD
    A1["Compromise Web Application to Access Top Secret Bank Balance Details"]
    B1["Exploit SSO Vulnerabilities"]
    A1 --> B1
    C1["Phish SSO Admin for Credentials"]
    B1 --> C1
    C2["Steal Session Tokens via Hijacking"]
    B1 --> C2
    C3["Brute Force SSO Interface"]
    B1 --> C3
    C4["Exploit SSO Misconfigurations"]
    B1 --> C4
    B2["Exploit Web Application Vulnerabilities"]
    A1 --> B2
    C1["SQL Injection"]
    B2 --> C1
    C2["Cross-Site Scripting"]
    B2 --> C2
    C3["Remote Code Execution"]
    B2 --> C3
    C4["Parameter Tampering"]
    B2 --> C4
    B3["Launch Network-Level Attacks"]
    A1 --> B3
    C1["Man-in-the-Middle over Public Networks"]
    B3 --> C1
    C2["DNS Spoofing or Poisoning"]
    B3 --> C2
    B4["Leverage Insider Access or Social Engineering"]
    A1 --> B4
    C1["Insider with Privileged Access"]
    B4 --> C1
    C2["Social Engineering Employees"]
    B4 --> C2\n\`\`\`\n\n`;
        }
      }
      
      // Add DREAD Assessment section
      if (reportData.dread_assessment.data) {
        markdownContent += `## DREAD Risk Assessment\n\n`;
        
        const dreadData = reportData.dread_assessment.data.result.result.raw_response['Risk Assessment'] || [];
        
        if (dreadData.length > 0) {
          // Calculate averages
          let totalDamage = 0;
          let totalReproducibility = 0;
          let totalExploitability = 0;
          let totalAffectedUsers = 0;
          let totalDiscoverability = 0;
          
          dreadData.forEach((item: DreadAssessmentItem) => {
            totalDamage += Number(item['Damage Potential']) || 0;
            totalReproducibility += Number(item['Reproducibility']) || 0;
            totalExploitability += Number(item['Exploitability']) || 0;
            totalAffectedUsers += Number(item['Affected Users']) || 0;
            totalDiscoverability += Number(item['Discoverability']) || 0;
          });
          
          const count = dreadData.length;
          const avgDamage = totalDamage / count;
          const avgReproducibility = totalReproducibility / count;
          const avgExploitability = totalExploitability / count;
          const avgAffectedUsers = totalAffectedUsers / count;
          const avgDiscoverability = totalDiscoverability / count;
          
          // Find highest risk threat
          let highestRiskThreat = null;
          let highestRiskScore = 0;
          
          dreadData.forEach((item: DreadAssessmentItem) => {
            const score = (
              Number(item['Damage Potential']) +
              Number(item['Reproducibility']) +
              Number(item['Exploitability']) +
              Number(item['Affected Users']) +
              Number(item['Discoverability'])
            ) || 0;
            
            if (score > highestRiskScore) {
              highestRiskScore = score;
              highestRiskThreat = item;
            }
          });
          
          // Add DREAD summary
          markdownContent += `### DREAD Risk Summary\n\n`;
          markdownContent += `- **Average DREAD Score**: ${((avgDamage + avgReproducibility + avgExploitability + avgAffectedUsers + avgDiscoverability) / 5).toFixed(1)}\n`;
          
          // Determine highest risk category
          const scores = [
            { name: 'Damage', value: avgDamage },
            { name: 'Reproducibility', value: avgReproducibility },
            { name: 'Exploitability', value: avgExploitability },
            { name: 'Affected Users', value: avgAffectedUsers },
            { name: 'Discoverability', value: avgDiscoverability }
          ];
          
          scores.sort((a, b) => b.value - a.value);
          markdownContent += `- **Highest Risk Category**: ${scores[0].name} (Score: ${scores[0].value.toFixed(1)})\n`;
          markdownContent += `- **Threats Assessed**: ${dreadData.length}\n`;
          
          if (highestRiskThreat) {
            markdownContent += `- **Highest Risk Threat**: ${highestRiskThreat['Threat Type']} (Score: ${highestRiskScore})\n\n`;
          }
          
          // Add DREAD assessment table
          markdownContent += `### DREAD Assessment\n\n`;
          markdownContent += `| Threat Type | Scenario | Damage | Reproducibility | Exploitability | Affected Users | Discoverability |\n`;
          markdownContent += `| ----------- | -------- | ------ | --------------- | -------------- | -------------- | --------------- |\n`;
          
          dreadData.forEach((assessment: DreadAssessmentItem) => {
            markdownContent += `| ${assessment['Threat Type']} | ${assessment['Scenario']} | ${assessment['Damage Potential']} | ${assessment['Reproducibility']} | ${assessment['Exploitability']} | ${assessment['Affected Users']} | ${assessment['Discoverability']} |\n`;
          });
          
          markdownContent += `\n`;
        } else {
          markdownContent += `No DREAD assessment data available.\n\n`;
        }
      }
      
      // Add Mitigation section
      if (reportData.mitigation.data) {
        markdownContent += `## Mitigation Strategies\n\n`;
        
        const mitigations = reportData.mitigation.data.result.result.raw_response?.mitigations || [];
        
        if (mitigations.length > 0) {
          // Create table header
          markdownContent += `| Threat Type | Scenario | Suggested Mitigation(s) |\n`;
          markdownContent += `| ----------- | -------- | ---------------------- |\n`;
          
          // Add table rows
          mitigations.forEach((mitigation: MitigationItem) => {
            const threatType = mitigation['Threat Type'] || 'Unknown';
            const scenario = mitigation['Scenario'] || '';
            const mitigationText = mitigation['Suggested Mitigation(s)'] || '';
            
            // Format the mitigation text to work well in markdown table
            const formattedMitigation = mitigationText.replace(/\n/g, ' ').replace(/\|/g, '\\|');
            
            markdownContent += `| ${threatType} | ${scenario} | ${formattedMitigation} |\n`;
          });
          
          markdownContent += `\n`;
        } else {
          markdownContent += `No mitigation data available.\n\n`;
        }
      }
      
      // Create a blob and download the markdown file
      const blob = new Blob([markdownContent], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `security-assessment-report-${assessment_id}.md`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
    } catch (err) {
      console.error('Error generating markdown report:', err);
      setDownloadError('Failed to generate markdown report');
    } finally {
      setDownloadingMarkdown(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4" ref={reportRef}>
      {/* Cover Page - Hidden in UI */}
      <div ref={coverPageRef} className="hidden">
        <div className="text-center">
        <h1 className="text-5xl font-bold text-gray-800 mb-8">
            Threat Modelling Report
          </h1>
          <h2 className="text-5xl font-bold text-gray-800 mb-8">
            {assessmentDetails?.projectName || 'Security Assessment Report'}
          </h2>
          <p className="text-xl text-gray-500 mt-8">
            {new Date().toLocaleDateString()}
          </p>
        </div>
      </div>

      {/* Main Report Header with Gradient - Only visible in UI */}
      <div className="bg-gradient-to-r from-blue-600 to-indigo-800 rounded-lg shadow-lg p-5 mb-6 text-white print:hidden">
        <h1 className="text-3xl font-bold mb-2">Security Assessment Report</h1>
        <div className="flex justify-between items-center">
          <div>
          <p className="text-blue-100">
            Name: {assessmentDetails ? 
              `${assessmentDetails.projectName}` 
              : assessment_id}
          </p>
            
            <p className="text-blue-100">Methodology: {assessmentDetails?.threatModelingMethodology}</p>
            <p className="text-blue-100">Assessment ID: {assessment_id}</p>
            <p className="text-blue-100">Generated: {new Date().toLocaleDateString()}</p>
          </div>
          <div className="flex gap-4 relative">
            <div ref={downloadMenuRef}>
              <button
                onClick={() => setShowDownloadOptions(!showDownloadOptions)}
                className="flex items-center px-4 py-2 text-sm font-medium text-indigo-800 bg-white hover:bg-blue-50 rounded-lg transition-colors duration-200 shadow-md"
                disabled={downloading || downloadingMarkdown}
              >
                {downloading || downloadingMarkdown ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-indigo-800" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Downloading...
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                    </svg>
                    Download
                    <svg className="w-4 h-4 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </>
                )}
              </button>
              
              {showDownloadOptions && (
                <div className="absolute mt-2 w-64 bg-gray-800 rounded-md shadow-lg z-10 overflow-hidden">
                  <div className="py-1">
                    <button
                      onClick={() => {
                        setShowDownloadOptions(false);
                        handleDownloadMarkdown();
                      }}
                      className="w-full text-left px-4 py-3 text-sm text-white hover:bg-gray-700 transition-colors duration-150"
                    >
                      Download as Markdown File
                    </button>
                    <button
                      onClick={() => {
                        setShowDownloadOptions(false);
                        handleDownloadJson();
                      }}
                      className="w-full text-left px-4 py-3 text-sm text-white hover:bg-gray-700 transition-colors duration-150"
                    >
                      Download as JSON File
                    </button>
                    {/* Basic PDF download feature removed */}
                    <button
                      onClick={() => {
                        setShowDownloadOptions(false);
                        handleDownload();
                      }}
                      className="w-full text-left px-4 py-3 text-sm text-white hover:bg-gray-700 transition-colors duration-150"
                    >
                      Download as PDF (Enriched)
                    </button>
                  </div>
                </div>
              )}
            </div>
            <button
              onClick={handleChatClick}
              className="flex items-center px-4 py-2 text-sm font-medium text-indigo-800 bg-white hover:bg-blue-50 rounded-lg transition-colors duration-200 shadow-md"
            >
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
              Chat About Report
            </button>
          </div>
        </div>
      </div>

      {downloadError && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md text-red-700">
          <div className="flex items-center">
            <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>{downloadError}</span>
          </div>
        </div>
      )}

      <div className="space-y-8">
        {/* About Box - Introduction Section */}
        {introductionLoading ? (
          <div className="bg-white shadow-lg rounded-lg overflow-hidden border border-gray-200 p-6">
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-600"></div>
            </div>
          </div>
        ) : introductionError ? (
          <div className="bg-white shadow-lg rounded-lg overflow-hidden border border-gray-200 p-6">
            <div className="bg-red-50 p-4 rounded-lg text-red-600 border border-red-200">
              <div className="flex items-center">
                <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {introductionError}
              </div>
            </div>
          </div>
        ) : introduction || additionalInfo.functional_flows || additionalInfo.third_party_integrations ? (
          <div className="bg-white shadow-lg rounded-lg overflow-hidden border border-gray-200">
            <div className="bg-gradient-to-r from-blue-500 to-blue-700 px-6 py-4">
              <div className="flex items-center">
                <div className="bg-white p-2 rounded-full mr-3 shadow-md">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h2 className="text-2xl font-bold text-white">Introduction</h2>
              </div>
            </div>
            <div className="p-6">
              {introduction && <p className="text-gray-700 mb-6">{introduction}</p>}
              
              {/* Additional Info Sections */}
              {(additionalInfo.functional_flows || additionalInfo.third_party_integrations) && (
                <div className="space-y-6">
                  {additionalInfo.functional_flows && (
                    <div>
                      <h3 className="text-lg font-semibold text-gray-800 mb-3">Functional Flows</h3>
                      <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
                        <p className="text-gray-700 whitespace-pre-wrap">{additionalInfo.functional_flows}</p>
                      </div>
                    </div>
                  )}
                  
                  {additionalInfo.third_party_integrations && (
                    <div>
                      <h3 className="text-lg font-semibold text-gray-800 mb-3">Third Party Integrations</h3>
                      <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
                        <p className="text-gray-700 whitespace-pre-wrap">{additionalInfo.third_party_integrations}</p>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        ) : null}

        {/* Threat Model Section */}
        <div ref={threatModelRef}>
        <div className="bg-white shadow-lg rounded-lg overflow-hidden border border-gray-200">
          <div className="bg-gradient-to-r from-red-500 to-red-700 px-6 py-4">
            <div className="flex items-center">
              <div className="bg-white p-2 rounded-full mr-3 shadow-md">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <h2 className="text-2xl font-bold text-white">Threat Model Analysis</h2>
            </div>
            <div>
            {/* <p className="text-white mt-1">
              {assessmentDetails ? 
              `${assessmentDetails.projectName} - ${new Date(assessmentDetails.timestamp).toLocaleDateString()}` 
              : assessment_id}
            </p> */}
            </div>
          </div>
          <div className="p-6">
            {reportData.threat_model.loading ? (
              <div className="flex items-center justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-red-600"></div>
              </div>
            ) : reportData.threat_model.error ? (
              <div className="bg-red-50 p-4 rounded-lg text-red-600 border border-red-200">
                <div className="flex items-center">
                  <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {reportData.threat_model.error}
                </div>
              </div>
            ) : reportData.threat_model.data ? (
              <div>
                {/* Threat Model Summary Cards */}
                <div className="mb-8">
                  <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Threat Summary
                  </h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* Total Threats Card */}
                    <div className="bg-gradient-to-br from-red-50 to-red-100 rounded-lg p-4 border border-red-200 shadow-sm">
                      <div className="flex justify-between items-center">
                        <div>
                          <p className="text-sm text-red-700 font-medium">Total Threats</p>
                          <p className="text-3xl font-bold text-red-800">
                            {reportData.threat_model.data?.result?.result?.raw_response?.threat_model?.length || 0}
                          </p>
                        </div>
                        <div className="bg-red-200 p-3 rounded-full">
                          <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                          </svg>
                        </div>
                      </div>
                    </div>
                    
                    {/* Most Common Threat Type */}
                    <div className="bg-gradient-to-br from-orange-50 to-orange-100 rounded-lg p-4 border border-orange-200 shadow-sm">
                      <div className="flex justify-between items-center">
                        <div>
                          <p className="text-sm text-orange-700 font-medium">Most Common Threat</p>
                          <p className="text-xl font-bold text-orange-800 mt-1">
                            {(() => {
                              const threats = reportData.threat_model.data?.result?.result?.raw_response?.threat_model || [];
                              const threatTypes = threats.map((t: Threat) => t['Threat Type']);
                              const counts: Record<string, number> = {};
                              threatTypes.forEach((type: string) => {
                                counts[type] = (counts[type] || 0) + 1;
                              });
                              
                              let maxType = '';
                              let maxCount = 0;
                              Object.entries(counts).forEach(([type, count]) => {
                                if (count > maxCount) {
                                  maxType = type;
                                  maxCount = count;
                                }
                              });
                              
                              return maxType || 'None';
                            })()}
                          </p>
                        </div>
                        <div className="bg-orange-200 p-3 rounded-full">
                          <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-orange-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
                          </svg>
                        </div>
                      </div>
                    </div>
                    
                    {/* Improvement Suggestions */}
                    <div className="bg-gradient-to-br from-green-50 to-green-100 rounded-lg p-4 border border-green-200 shadow-sm">
                      <div className="flex justify-between items-center">
                        <div>
                          <p className="text-sm text-green-700 font-medium">Improvement Suggestions</p>
                          <p className="text-3xl font-bold text-green-800">
                            {reportData.threat_model.data?.result?.result?.raw_response?.improvement_suggestions?.length || 0}
                          </p>
                        </div>
                        <div className="bg-green-200 p-3 rounded-full">
                          <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                          </svg>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Threats Table */}
                <div className="table-container shadow-sm mb-6 overflow-hidden rounded-lg border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threat Type</th>
                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scenario</th>
                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Potential Impact</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {reportData.threat_model.data?.result?.result?.raw_response?.threat_model?.map((threat: Threat, index: number) => (
                        <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                          <td className="px-6 py-4 whitespace-normal text-sm font-medium text-red-700 border-l-4 border-red-500">
                            <div className="flex items-center">
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                              </svg>
                              {threat['Threat Type']}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-normal text-sm text-gray-700">{threat['Scenario']}</td>
                          <td className="px-6 py-4 whitespace-normal text-sm text-gray-700">{threat['Potential Impact']}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Improvement Suggestions */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                    Improvement Suggestions
                  </h3>
                  <div className="bg-green-50 border border-green-200 rounded-lg p-4 shadow-sm">
                    <ul className="list-disc pl-5 space-y-3 text-gray-700">
                      {reportData.threat_model.data?.result?.result?.raw_response?.improvement_suggestions?.map((suggestion: string, index: number) => (
                        <li key={index} className="pb-2 border-b border-green-100 last:border-0 last:pb-0">{suggestion}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-gray-50 p-4 rounded-lg text-gray-500 border border-gray-200">
                No threat model data available
              </div>
            )}
          </div>
        </div>

        </div>
        
        {/* DREAD Assessment Section */}
        <div className="bg-white shadow-lg rounded-lg overflow-hidden border border-gray-200" style={{ pageBreakBefore: 'always' }}>
          <div className="bg-gradient-to-r from-yellow-500 to-yellow-700 px-6 py-4">
            <div className="flex items-center">
              <div className="bg-white p-2 rounded-full mr-3 shadow-md">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-yellow-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <h2 className="text-2xl font-bold text-white">DREAD Risk Assessment</h2>
            </div>
          </div>
          <div className="p-6">
            {reportData.dread_assessment.loading ? (
              <div className="flex items-center justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-yellow-600"></div>
              </div>
            ) : reportData.dread_assessment.error ? (
              <div className="bg-red-50 p-4 rounded-lg text-red-600 border border-red-200">
                <div className="flex items-center">
                  <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {reportData.dread_assessment.error}
                </div>
              </div>
            ) : reportData.dread_assessment.data ? (
              <div>
                {/* DREAD Assessment Summary */}
                <div className="mb-8">
                  <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-yellow-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    DREAD Risk Summary
                  </h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    {(() => {
                      const dreadData = reportData.dread_assessment.data?.result?.result?.raw_response?.['Risk Assessment'] || [];
                      
                      // Calculate averages
                      let totalDamage = 0;
                      let totalReproducibility = 0;
                      let totalExploitability = 0;
                      let totalAffectedUsers = 0;
                      let totalDiscoverability = 0;
                      
                      dreadData.forEach((item: DreadAssessmentItem) => {
                        totalDamage += Number(item['Damage Potential']) || 0;
                        totalReproducibility += Number(item['Reproducibility']) || 0;
                        totalExploitability += Number(item['Exploitability']) || 0;
                        totalAffectedUsers += Number(item['Affected Users']) || 0;
                        totalDiscoverability += Number(item['Discoverability']) || 0;
                      });
                      
                      const count = dreadData.length || 1;
                      const avgDamage = totalDamage / count;
                      const avgReproducibility = totalReproducibility / count;
                      const avgExploitability = totalExploitability / count;
                      const avgAffectedUsers = totalAffectedUsers / count;
                      const avgDiscoverability = totalDiscoverability / count;
                      
                      // Find highest risk threat
                      let highestRiskThreat = null;
                      let highestRiskScore = 0;
                      
                      dreadData.forEach((item: DreadAssessmentItem) => {
                        const score = (
                          Number(item['Damage Potential']) +
                          Number(item['Reproducibility']) +
                          Number(item['Exploitability']) +
                          Number(item['Affected Users']) +
                          Number(item['Discoverability'])
                        ) || 0;
                        
                        if (score > highestRiskScore) {
                          highestRiskScore = score;
                          highestRiskThreat = item;
                        }
                      });
                      
                      return (
                        <>
                          {/* Average DREAD Score */}
                          <div className="bg-gradient-to-br from-yellow-50 to-yellow-100 rounded-lg p-4 border border-yellow-200 shadow-sm">
                            <p className="text-sm text-yellow-700 font-medium">Average DREAD Score</p>
                            <p className="text-3xl font-bold text-yellow-800 mt-1">
                              {((avgDamage + avgReproducibility + avgExploitability + avgAffectedUsers + avgDiscoverability) / 5).toFixed(1)}
                            </p>
                            <div className="mt-2 h-2 bg-gray-200 rounded-full overflow-hidden">
                              <div 
                                className="h-full bg-yellow-500" 
                                style={{ 
                                  width: `${((avgDamage + avgReproducibility + avgExploitability + avgAffectedUsers + avgDiscoverability) / 5) * 10}%` 
                                }}
                              ></div>
                            </div>
                          </div>
                          
                          {/* Highest Risk Category */}
                          <div className="bg-gradient-to-br from-orange-50 to-orange-100 rounded-lg p-4 border border-orange-200 shadow-sm">
                            <p className="text-sm text-orange-700 font-medium">Highest Risk Category</p>
                            <p className="text-xl font-bold text-orange-800 mt-1">
                              {(() => {
                                const scores = [
                                  { name: 'Damage', value: avgDamage },
                                  { name: 'Reproducibility', value: avgReproducibility },
                                  { name: 'Exploitability', value: avgExploitability },
                                  { name: 'Affected Users', value: avgAffectedUsers },
                                  { name: 'Discoverability', value: avgDiscoverability }
                                ];
                                
                                scores.sort((a, b) => b.value - a.value);
                                return scores[0].name;
                              })()}
                            </p>
                            <p className="text-sm text-orange-600 mt-1">
                              Score: {Math.max(avgDamage, avgReproducibility, avgExploitability, avgAffectedUsers, avgDiscoverability).toFixed(1)}
                            </p>
                          </div>
                          
                          {/* Total Threats Assessed */}
                          <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-lg p-4 border border-blue-200 shadow-sm">
                            <p className="text-sm text-blue-700 font-medium">Threats Assessed</p>
                            <p className="text-3xl font-bold text-blue-800 mt-1">{dreadData.length}</p>
                            <p className="text-sm text-blue-600 mt-1">
                              {dreadData.length > 0 ? 'Complete assessment' : 'No threats assessed'}
                            </p>
                          </div>
                          
                          {/* Highest Risk Threat */}
                          <div className="bg-gradient-to-br from-red-50 to-red-100 rounded-lg p-4 border border-red-200 shadow-sm">
                            <p className="text-sm text-red-700 font-medium">Highest Risk Threat</p>
                            <p className="text-lg font-bold text-red-800 mt-1 truncate">
                              {highestRiskThreat ? highestRiskThreat['Threat Type'] : 'None'}
                            </p>
                            <p className="text-sm text-red-600 mt-1">
                              {highestRiskThreat ? `Score: ${highestRiskScore}` : 'No threats found'}
                            </p>
                          </div>
                        </>
                      );
                    })()}
                  </div>
                </div>
                
                {/* DREAD Assessment Table */}
                <div className="table-container shadow-sm overflow-hidden rounded-lg border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threat Type</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scenario</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Damage</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reproducibility</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Exploitability</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Affected Users</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Discoverability</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {reportData.dread_assessment.data?.result?.result?.raw_response?.['Risk Assessment']?.map((assessment: DreadAssessmentItem, index: number) => (
                        <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                          <td className="px-4 py-4 whitespace-normal text-sm font-medium text-yellow-700 border-l-4 border-yellow-500">
                            {assessment['Threat Type']}
                          </td>
                          <td className="px-4 py-4 whitespace-normal text-sm text-gray-700">{assessment['Scenario']}</td>
                          <td className="px-4 py-4 whitespace-normal text-sm">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              assessment['Damage Potential'] > 7 ? 'bg-red-100 text-red-800' : 
                              assessment['Damage Potential'] > 4 ? 'bg-yellow-100 text-yellow-800' : 
                              'bg-green-100 text-green-800'
                            }`}>
                              {assessment['Damage Potential']}
                            </span>
                          </td>
                          <td className="px-4 py-4 whitespace-normal text-sm">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              assessment['Reproducibility'] > 7 ? 'bg-red-100 text-red-800' : 
                              assessment['Reproducibility'] > 4 ? 'bg-yellow-100 text-yellow-800' : 
                              'bg-green-100 text-green-800'
                            }`}>
                              {assessment['Reproducibility']}
                            </span>
                          </td>
                          <td className="px-4 py-4 whitespace-normal text-sm">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              assessment['Exploitability'] > 7 ? 'bg-red-100 text-red-800' : 
                              assessment['Exploitability'] > 4 ? 'bg-yellow-100 text-yellow-800' : 
                              'bg-green-100 text-green-800'
                            }`}>
                              {assessment['Exploitability']}
                            </span>
                          </td>
                          <td className="px-4 py-4 whitespace-normal text-sm">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              assessment['Affected Users'] > 7 ? 'bg-red-100 text-red-800' : 
                              assessment['Affected Users'] > 4 ? 'bg-yellow-100 text-yellow-800' : 
                              'bg-green-100 text-green-800'
                            }`}>
                              {assessment['Affected Users']}
                            </span>
                          </td>
                          <td className="px-4 py-4 whitespace-normal text-sm">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              assessment['Discoverability'] > 7 ? 'bg-red-100 text-red-800' : 
                              assessment['Discoverability'] > 4 ? 'bg-yellow-100 text-yellow-800' : 
                              'bg-green-100 text-green-800'
                            }`}>
                              {assessment['Discoverability']}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="bg-gray-50 p-4 rounded-lg text-gray-500 border border-gray-200">
                No DREAD assessment data available
              </div>
            )}
          </div>
        </div>

        {/* Attack Tree Section */}
        <div className="bg-white shadow-lg rounded-lg overflow-hidden border border-gray-200" style={{ pageBreakBefore: 'always' }}>
          <div className="bg-gradient-to-r from-blue-500 to-blue-700 px-6 py-4">
            <div className="flex items-center">
              <div className="bg-white p-2 rounded-full mr-3 shadow-md">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
                </svg>
              </div>
              <h2 className="text-2xl font-bold text-white">Attack Tree Analysis</h2>
            </div>
          </div>
          <div className="p-6">
            {reportData.attack_tree.loading ? (
              <div className="flex items-center justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-600"></div>
              </div>
            ) : reportData.attack_tree.error ? (
              <div className="bg-red-50 p-4 rounded-lg text-red-600 border border-red-200">
                <div className="flex items-center">
                  <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {reportData.attack_tree.error}
                </div>
              </div>
            ) : reportData.attack_tree.data ? (
              <div>
                <div style={{ height: (reportData.attack_tree.data?.result?.result?.attack_tree?.nodes?.filter(node => node.type === 'goal')?.length || 0) > 1 ? 800 : 600 }} className="w-full border border-gray-200 rounded-lg overflow-hidden">
                  <AttackTreeVisualization attackTreeData={reportData.attack_tree.data?.result?.result} />
                </div>
              </div>
            ) : (
              <div className="bg-gray-50 p-4 rounded-lg text-gray-500 border border-gray-200">
                No attack tree data available
              </div>
            )}
          </div>
        </div>

        {/* Mitigation Section */}
        <div className="bg-white shadow-lg rounded-lg overflow-hidden border border-gray-200" style={{ pageBreakBefore: 'always' }}>
          <div className="bg-gradient-to-r from-green-500 to-green-700 px-6 py-4">
            <div className="flex items-center">
              <div className="bg-white p-2 rounded-full mr-3 shadow-md">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <h2 className="text-2xl font-bold text-white">Mitigation Strategies</h2>
            </div>
          </div>
          <div className="p-6">
            {reportData.mitigation.loading ? (
              <div className="flex items-center justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-green-600"></div>
              </div>
            ) : reportData.mitigation.error ? (
              <div className="bg-red-50 p-4 rounded-lg text-red-600 border border-red-200">
                <div className="flex items-center">
                  <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {reportData.mitigation.error}
                </div>
              </div>
            ) : reportData.mitigation.data ? (
              <div>
                {/* Mitigation Table */}
                <div className="table-container shadow-sm overflow-hidden rounded-lg border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        {(() => {
                          return (
                            <>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threat Type</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-1/4">Scenario</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Mitigation Strategy</th>
                            </>
                          );
                        })()}
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {(() => {
                        const mitigations = reportData.mitigation.data?.result?.result?.raw_response?.mitigations || [];
                        return mitigations.map((mitigation: MitigationItem, index: number) => (
                          <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                            <td className="px-6 py-4 whitespace-normal text-sm font-medium text-green-700 border-l-4 border-green-500">
                              <div className="flex items-center">
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                                {mitigation['Threat Type'] || 'Unknown'}
                              </div>
                            </td>
                            <td className="px-6 py-4 whitespace-normal text-sm text-gray-700">{mitigation['Scenario']}</td>
                            <td className="px-6 py-4 whitespace-normal text-sm text-gray-700">
                              <div className="prose prose-blue max-w-none">
                                {mitigation['Mitigations']?.length > 0 ? (
                                  <ul className="list-none">
                                    {mitigation['Mitigations'].map((item, i) => (
                                      <li key={i} className="before:content-['-'] before:mr-2">{item}</li>
                                    ))}
                                  </ul>
                                ) : mitigation['Suggested Mitigation(s)'] && typeof mitigation['Suggested Mitigation(s)'] === 'string' ? (
                                  <ul className="list-none">
                                    {mitigation['Suggested Mitigation(s)']
                                      .split('. ')
                                      .map((item, i) => {
                                        // Remove any leading or trailing numbers from the item
                                        let cleanedItem = item.trim()
                                          .replace(/^[\d]+[\.\s]*/, '') // Remove leading numbers like "1. " or "1" or "1"
                                          .replace(/\s\d+$/, ''); // Remove trailing numbers like " 1" or " 2"
                                        
                                        // Additional check to remove standalone numbers at the beginning
                                        if (/^\d+$/.test(cleanedItem.split(' ')[0])) {
                                          cleanedItem = cleanedItem.replace(/^\d+\s*/, '');
                                        }
                                        return cleanedItem ? <li key={i} className="before:content-['-'] before:mr-2">{cleanedItem}</li> : null;
                                      })
                                      .filter(Boolean)
                                    }
                                  </ul>
                                ) : (
                                  'No mitigation details available'
                                )}
                              </div>
                            </td>
                          </tr>
                        ));
                      })()}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="bg-gray-50 p-4 rounded-lg text-gray-500 border border-gray-200">
                No mitigation data available
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Report;
