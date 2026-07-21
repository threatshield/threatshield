import React, { useState, useEffect, useRef, useMemo } from 'react';
import html2pdf from 'html2pdf.js';
import { useParams, useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import MermaidDiagram from '../components/common/MermaidDiagram';
import { 
  Threat, 
  DreadAssessmentItem, 
  AttackTreeNode,
  MitigationItem,
  PastaThreat
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
  businessRiskType?: string;
  scenario: string;
  mitigation: string;
  isPasta?: boolean;
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
    
    // Check if this is a PASTA table (has Business Risk Type column)
    const isPasta = headerCells.some(cell => cell.toLowerCase().includes('business risk type'));
    
    let threatTypeIndex = -1;
    let businessRiskTypeIndex = -1;
    let scenarioIndex = -1;
    let mitigationIndex = -1;
    
    headerCells.forEach((cell, index) => {
      if (cell.toLowerCase().includes('threat type')) threatTypeIndex = index;
      if (cell.toLowerCase().includes('business risk type')) businessRiskTypeIndex = index;
      if (cell.toLowerCase().includes('scenario')) scenarioIndex = index;
      if (cell.toLowerCase().includes('mitigation')) mitigationIndex = index;
    });
    
    // For PASTA, we need Business Risk Type and Scenario
    // For STRIDE, we need Threat Type and Scenario
    if ((isPasta && (businessRiskTypeIndex === -1 || scenarioIndex === -1)) || 
        (!isPasta && (threatTypeIndex === -1 || scenarioIndex === -1)) || 
        mitigationIndex === -1) {
      console.error('Could not identify all required columns in the header');
      return [];
    }
    
    return dataRows.map(row => {
      // Remove leading/trailing whitespace and split by |
      const cells = row.split('|').map(cell => cell.trim());
      
      // Extract values using the determined indices
      const threatType = isPasta ? 
        (cells[threatTypeIndex] || 'Unknown') : 
        (cells[threatTypeIndex] || 'Unknown');
      
      const businessRiskType = isPasta ? 
        (cells[businessRiskTypeIndex] || 'Unknown') : 
        undefined;
      
      const scenario = cells[scenarioIndex] || 'Unknown';
      const mitigation = cells[mitigationIndex] || '';
      
      return {
        threatType: threatType,
        businessRiskType: businessRiskType,
        scenario: scenario,
        mitigation: mitigation,
        isPasta: isPasta
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
  
  const [isPasta, setIsPasta] = useState<boolean>(false);
  
  const processAttackTreeData = (treeNodes: AttackTreeNode[]) => {
    try {
      const flowNodes: Node<any>[] = [];
      const flowEdges: Edge<any>[] = [];
      
      // Create a map to store node positions
      const nodePositions: Record<string, { x: number, y: number }> = {};
      
      // Define spacing configurations for different methodologies
      const spacingConfig: {
        [key: string]: {
          baseWidth: number;
          level0: { xGap: number };
          level1: { xGapMultiplier: number; siblingFactor: number };
          level2: { xGapMultiplier: number; siblingFactor: number };
          level3?: { xGapMultiplier: number; siblingFactor: number; groupFactor?: number };
          verticalBase: number;
          verticalIncrement: number;
          horizontalOffset: number | { default: number; vulnerability: number };
        }
      } = {
        STRIDE: {
          baseWidth: 250, // Reduced base width for STRIDE
          level0: { xGap: 0 },
          level1: { xGapMultiplier: 1.8, siblingFactor: 0.5 }, // Increased spacing for n-1 layer (attack methods)
          level2: { xGapMultiplier: 1.0, siblingFactor: 0.6 }, // Reduced multiplier
          verticalBase: 160, // Reduced vertical spacing
          verticalIncrement: 25, // Reduced vertical increment
          horizontalOffset: 15 // Reduced horizontal offset
        },
        PASTA: {
          baseWidth: 350, // Slightly reduced base width for PASTA
          level0: { xGap: 0 },
          level1: { xGapMultiplier: 5.0, siblingFactor: 0.7 }, // Super root to business impacts
          level2: { xGapMultiplier: 1.8, siblingFactor: 0.8 }, // Business impacts to attack methods
          level3: { 
            xGapMultiplier: 0.2, 
            siblingFactor: 1.8,
            groupFactor: 0.2 // Smaller group factor to cluster vulnerabilities closer
          }, 
          verticalBase: 220, // Slightly reduced vertical base
          verticalIncrement: 35, // Slightly reduced vertical increment
          horizontalOffset: {
            default: 20,
            vulnerability: 30 // Reduced offset for vulnerabilities
          }
        }
      };
      
      // Check if we have multiple root/goal nodes (PASTA methodology)
      const rootGoalNodes = treeNodes.filter(node => node.type === 'goal');
      const isPastaStructure = rootGoalNodes.length > 1;
      
      // Set isPasta state based on structure
      const isPasta = isPastaStructure;
      setIsPasta(isPasta);
      
      console.log(`Using ${isPasta ? 'PASTA' : 'STRIDE'} spacing configuration`);
      const config = spacingConfig[isPasta ? 'PASTA' : 'STRIDE'];
      
      // Create nodes function with optimized positioning for attack trees
      const createNodes = (node: AttackTreeNode, level: number, position: number, totalSiblings: number, parentX: number = 0, isPasta: boolean = false): void => {
        // Get the appropriate configuration based on methodology
        const cfg = isPasta ? spacingConfig.PASTA : spacingConfig.STRIDE;
        
        // Dynamic spacing based on tree structure with increased gaps
        const baseWidth = cfg.baseWidth;
        
        // Calculate horizontal gap based on level and siblings with wider spacing
        let xGap: number = 0;
        if (level === 0) {
          // Root node
          xGap = 0;
        } else if (level === 1) {
          // First level nodes
          if (isPasta && node.id === 'super-root') {
            xGap = baseWidth * cfg.level1.xGapMultiplier * Math.max(1, totalSiblings * cfg.level1.siblingFactor);
          } else {
            xGap = baseWidth * cfg.level1.xGapMultiplier * Math.max(1, totalSiblings * cfg.level1.siblingFactor);
          }
        } else if (level === 2 && isPasta) {
          // For PASTA, level 2 are the attack methods under business impacts
          xGap = baseWidth * cfg.level2.xGapMultiplier * Math.max(1, totalSiblings * cfg.level2.siblingFactor);
        } else if (level === 3 && isPasta && cfg.level3) {
          // For PASTA, level 3 are the vulnerabilities
          // Group them closer together under their parent attack method
          xGap = baseWidth * cfg.level3.xGapMultiplier * Math.max(1, totalSiblings * cfg.level3.siblingFactor);
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
          
          // For PASTA methodology, handle level 3 nodes (vulnerabilities) specially
          if (isPasta && level === 3) {
            // Group vulnerabilities closer together under their parent attack method
            // Use a smaller offset to keep them more clustered
            const groupingFactor = cfg.level3?.groupFactor || 0.2;
            x += offsetMultiplier * 20 * groupingFactor; // Much smaller offset to group vulnerabilities
            
            // Add a slight vertical stagger to prevent direct overlaps
            y += (position % 2) * 15; // Stagger odd/even nodes vertically
          } else if (isPasta && level > 3) {
            // Higher levels in PASTA
            x += offsetMultiplier * 30;
          } else {
            // STRIDE or other levels in PASTA
            x += offsetMultiplier * (isPasta ? 25 : 15); // Different offset based on methodology
          }
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
            minWidth: isPasta && (level === 3 || node.type === 'vulnerability') ? '220px' : '180px', // Wider minimum width for vulnerability nodes
            maxWidth: '400px', // Increased maximum width for all nodes
            padding: '10px', // Added more padding for better text spacing
            fontSize: '14px' // Slightly larger font for better readability
          }
        });
        
        // Process children if any
        if (node.children && node.children.length > 0) {
          node.children.forEach((childNode, idx) => {
            createNodes(childNode, level + 1, idx, node.children!.length, x, isPasta);
          });
        }
      };
      
      // Check if we have multiple root/goal nodes (PASTA methodology)
      const goalNodes = treeNodes.filter(node => node.type === 'goal');
      
      let rootNode;
      if (goalNodes.length > 1) {
        // Create a synthetic super root for PASTA methodology
        rootNode = {
          id: 'super-root',
          type: 'goal' as const,  // Explicitly type as 'goal' to match AttackTreeNode interface
          label: 'Business Impact',
          children: goalNodes
        };
      } else {
        // Use the existing root node for STRIDE methodology
        rootNode = goalNodes[0] || treeNodes[0];
      }
      
      if (rootNode) {
        // Start creating nodes from the root
        createNodes(rootNode, 0, 0, 1, 0, isPasta);
        
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
  interface DiagramData {
    intro: string;
    diagram: string;
    description: string;
  }

  const [additionalInfo, setAdditionalInfo] = useState<{
    functional_flows: string | null;
    third_party_integrations: string | null;
    data_flow_diagrams: DiagramData | null;
    mermaid_flow_diagrams: DiagramData | null;
  }>({ 
    functional_flows: null, 
    third_party_integrations: null,
    data_flow_diagrams: null,
    mermaid_flow_diagrams: null
  });

  // State for section collapse
  const [activeSection, setActiveSection] = useState<string>('functional_flows');
  const [collapsedSections, setCollapsedSections] = useState({
    functional_flows: false,
    third_party_integrations: false,
    data_flow_diagrams: false,
    mermaid_flow_diagrams: false
  });

  // Toggle section collapse
  const toggleSection = (section: keyof typeof collapsedSections) => {
    setCollapsedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  // Function to extract diagram content from string if needed
  const extractDiagramContent = (content: string | DiagramData | null): DiagramData | null => {
    if (!content) return null;
    if (typeof content === 'object') return content;

    // Try to find mermaid diagram in the content
    const mermaidMatch = content.match(/```mermaid\n([\s\S]*?)```/);
    if (!mermaidMatch) return null;

    const diagram = mermaidMatch[1];
    const parts = content.split('```');
    const intro = parts[0].trim();
    const description = parts[parts.length - 1].trim();

    return {
      intro,
      diagram,
      description
    };
  };
  const [additionalInfoLoading, setAdditionalInfoLoading] = useState<boolean>(true);
  const [additionalInfoError, setAdditionalInfoError] = useState<string | null>(null);
  const [assessmentDetails, setAssessmentDetails] = useState<{
    department: string;
    projectName: string;
    timestamp: string;
    threatModelingMethodology: string;
  } | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [downloadingMarkdown, setDownloadingMarkdown] = useState(false);
  const [downloadingTmBom, setDownloadingTmBom] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [showDownloadOptions, setShowDownloadOptions] = useState(false);
  const downloadMenuRef = useRef<HTMLDivElement>(null);
  const [activeMainTab, setActiveMainTab] = useState<string>('overview');
  const [testCasesData, setTestCasesData] = useState<any>(null);
  const [testCasesLoading, setTestCasesLoading] = useState<boolean>(false);
  const [testCasesError, setTestCasesError] = useState<string | null>(null);
  
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
                department: report.details.department,
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
            third_party_integrations: data.result.third_party_integrations || null,
            data_flow_diagrams: extractDiagramContent(data.result.data_flow_diagrams),
            mermaid_flow_diagrams: extractDiagramContent(data.result.mermaid_flow_diagrams)
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

        const data = await apiService.getRAGResult(assessment_id);

        if (!data) {
          throw new Error('No data returned from API');
        }
        
        // Try different possible structures for the RAG result
        let resultText = '';

        // Option 1: data.result.result.app_summary (storage wraps file content under result; file has result.app_summary)
        if (data.result?.result?.app_summary && typeof data.result.result.app_summary === 'string') {
          resultText = data.result.result.app_summary;
        }
        // Option 2: data.result.app_summary (flat wrap)
        else if (data.result && typeof data.result === 'object' && typeof data.result.app_summary === 'string') {
          resultText = data.result.app_summary;
        }
        // Option 3: data.result is a string directly containing the markdown
        else if (data.result && typeof data.result === 'string') {
          resultText = data.result;
        }
        // Option 4: data.result.result is a string
        else if (data.result?.result && typeof data.result.result === 'string') {
          resultText = data.result.result;
        }
        // Option 5: data itself contains the introduction text
        else if (typeof data === 'string') {
          resultText = data;
        }
        
        if (resultText) {
          // Strip a lone "# Introduction" header if present (the section label is shown in UI already)
          const cleaned = resultText.replace(/^#\s*Introduction\s*\n?/i, '').trim();
          setIntroduction(cleaned || resultText.trim());
        } else {
          setIntroductionError('Could not find introduction text in RAG result');
          setIntroduction(null);
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


  useEffect(() => {
    const fetchTestCases = async () => {
      if (!assessment_id) return;
      try {
        setTestCasesLoading(true);
        const data = await apiService.getSecurityTestCases(assessment_id);
        setTestCasesData(data);
      } catch (err) {
        setTestCasesError('Failed to load test cases');
      } finally {
        setTestCasesLoading(false);
      }
    };
    fetchTestCases();
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
    
    // Check if we have multiple root/goal nodes (PASTA methodology)
    const goalNodes = nodes.filter(node => node.type === 'goal');
    const isPasta = goalNodes.length > 1;
    
    if (isPasta) {
      // Create a synthetic super root for PASTA methodology
      const superRootId = 'super-root';
      mermaidContent += `    ${superRootId}["Business Impact"]\n`;
      
      // Connect super root to all goal nodes
      goalNodes.forEach(goalNode => {
        mermaidContent += `    ${superRootId} --> ${goalNode.id}\n`;
        processNode(goalNode);
      });
    } else {
      // Use the existing root node for STRIDE methodology
      const rootNode = goalNodes[0] || nodes[0];
      if (rootNode) {
        processNode(rootNode);
      }
    }
    
    return mermaidContent;
  };

  const handleDownload = async () => {
    if (!assessment_id) return;
    try {
      setDownloading(true);
      setDownloadError(null);
      const blob = await apiService.downloadPdf(assessment_id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `threatshield-report-${assessment_id}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Error downloading PDF report:', err);
      setDownloadError('Failed to download PDF report. Please try again.');
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
          name: assessmentDetails ? `[${assessmentDetails.department}] - ${assessmentDetails.projectName}` : assessment_id,
          methodology: assessmentDetails?.threatModelingMethodology || '',
          timestamp: new Date().toISOString(),
          generated: new Date().toLocaleDateString()
        },
        introduction: introduction || '',
        additional_info: {
          functional_flows: additionalInfo.functional_flows || null,
          third_party_integrations: additionalInfo.third_party_integrations || null,
          data_flow_diagrams: additionalInfo.data_flow_diagrams ? {
            intro: additionalInfo.data_flow_diagrams.intro || null,
            diagram: additionalInfo.data_flow_diagrams.diagram || null,
            description: additionalInfo.data_flow_diagrams.description || null
          } : null,
          mermaid_flow_diagrams: additionalInfo.mermaid_flow_diagrams ? {
            intro: additionalInfo.mermaid_flow_diagrams.intro || null,
            diagram: additionalInfo.mermaid_flow_diagrams.diagram || null,
            description: additionalInfo.mermaid_flow_diagrams.description || null
          } : null
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
      markdownContent += `- **Name**: ${assessmentDetails ? `[${assessmentDetails.department}] - ${assessmentDetails.projectName}` : assessment_id}\n`;
      markdownContent += `- **Methodology**:  ${assessmentDetails?.threatModelingMethodology}\n`;
      markdownContent += `- **Assessment ID**: ${assessment_id}\n`;
      markdownContent += `- **Generated**: ${new Date().toLocaleDateString()}\n\n`;

      // Add introduction section if available
      if (introduction) {
        markdownContent += `## Introduction\n\n${introduction}\n\n`;
      }

      // Add functional flows section if available
      if (additionalInfo.functional_flows) {
        const cleanedFlows = additionalInfo.functional_flows
          .split('\n')
          .map(line => line.replace(/^##\s*/, '').trim())
          .join('\n');
        markdownContent += `## Functional Flows\n\n${cleanedFlows}\n\n`;
      }

      // Add third party integrations section if available
      if (additionalInfo.third_party_integrations) {
        const cleanedIntegrations = additionalInfo.third_party_integrations
          .split('\n')
          .map(line => line.replace(/^##\s*/, '').trim())
          .join('\n');
        markdownContent += `## Third Party Integrations\n\n${cleanedIntegrations}\n\n`;
      }

      // Add Data Flow Diagram section if available
      if (additionalInfo.data_flow_diagrams) {
        markdownContent += `## Data Flow Diagram\n\n`;
        
        if (additionalInfo.data_flow_diagrams.intro) {
          markdownContent += `### Introduction\n\n${additionalInfo.data_flow_diagrams.intro}\n\n`;
        }
        
        if (additionalInfo.data_flow_diagrams.diagram) {
          markdownContent += `### Diagram\n\n\`\`\`mermaid\n${additionalInfo.data_flow_diagrams.diagram}\n\`\`\`\n\n`;
        }
        
        if (additionalInfo.data_flow_diagrams.description) {
          markdownContent += `### Description\n\n${additionalInfo.data_flow_diagrams.description}\n\n`;
        }
      }

      // Add Architecture Diagram section if available
      if (additionalInfo.mermaid_flow_diagrams) {
        markdownContent += `## Architecture Diagram\n\n`;
        
        if (additionalInfo.mermaid_flow_diagrams.intro) {
          markdownContent += `### Introduction\n\n${additionalInfo.mermaid_flow_diagrams.intro}\n\n`;
        }
        
        if (additionalInfo.mermaid_flow_diagrams.diagram) {
          markdownContent += `### Diagram\n\n\`\`\`mermaid\n${additionalInfo.mermaid_flow_diagrams.diagram}\n\`\`\`\n\n`;
        }
        
        if (additionalInfo.mermaid_flow_diagrams.description) {
          markdownContent += `### Description\n\n${additionalInfo.mermaid_flow_diagrams.description}\n\n`;
        }
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
          // Check if this is a PASTA table by looking for Business Risk Type in the first item
          const isPasta = mitigations.length > 0 && ('Business Risk Type' in mitigations[0] || 'PASTA Stage' in mitigations[0]);
          
          // Create appropriate table header based on methodology
          if (isPasta) {
            markdownContent += `| Business Risk Type | Threat Type | Scenario | Suggested Mitigation(s) |\n`;
            markdownContent += `| ----------------- | ----------- | -------- | ---------------------- |\n`;
            
            // Add table rows for PASTA
            mitigations.forEach((mitigation: MitigationItem) => {
              const businessRiskType = Array.isArray(mitigation['Business Risk Type']) 
                ? mitigation['Business Risk Type'].join(', ')
                : mitigation['Business Risk Type'] || 'Unknown';
              
              const threatType = mitigation['Threat Type'] || 'Unknown';
              const scenario = mitigation['Scenario'] || '';
              const mitigationText = mitigation['Suggested Mitigation(s)'] || '';
              
              // Format the mitigation text to work well in markdown table
              const formattedMitigation = mitigationText.replace(/\n/g, ' ').replace(/\|/g, '\\|');
              
              markdownContent += `| ${businessRiskType} | ${threatType} | ${scenario} | ${formattedMitigation} |\n`;
            });
          } else {
            // STRIDE format
            markdownContent += `| Threat Type | Scenario | Suggested Mitigation(s) |\n`;
            markdownContent += `| ----------- | -------- | ---------------------- |\n`;
            
            // Add table rows for STRIDE
            mitigations.forEach((mitigation: MitigationItem) => {
              const threatType = mitigation['Threat Type'] || 'Unknown';
              const scenario = mitigation['Scenario'] || '';
              const mitigationText = mitigation['Suggested Mitigation(s)'] || '';
              
              // Format the mitigation text to work well in markdown table
              const formattedMitigation = mitigationText.replace(/\n/g, ' ').replace(/\|/g, '\\|');
              
              markdownContent += `| ${threatType} | ${scenario} | ${formattedMitigation} |\n`;
            });
          }
          
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
      markdownContent += `- **Name**: ${assessmentDetails ? `[${assessmentDetails.department}] - ${assessmentDetails.projectName}` : assessment_id}\n`;
      markdownContent += `- **Methodology**:  ${assessmentDetails?.threatModelingMethodology}\n`;
      markdownContent += `- **Assessment ID**: ${assessment_id}\n`;
      markdownContent += `- **Generated**: ${new Date().toLocaleDateString()}\n\n`;

      // Add introduction section if available
      if (introduction) {
        markdownContent += `## Introduction\n\n${introduction}\n\n`;
      }

      // Add functional flows section if available
      if (additionalInfo.functional_flows) {
        const cleanedFlows = additionalInfo.functional_flows
          .split('\n')
          .map(line => {
            // Remove any ## headers and trim
            line = line.replace(/^#+\s*/g, '').trim();
            // Remove any bold markers
            line = line.replace(/\*\*(.*?)\*\*/g, '$1');
            return line;
          })
          .filter(line => line) // Remove empty lines
          .join('\n');
        markdownContent += `## Functional Flows\n\n${cleanedFlows}\n\n`;
      }

      // Add third party integrations section if available
      if (additionalInfo.third_party_integrations) {
        const cleanedIntegrations = additionalInfo.third_party_integrations
          .split('\n')
          .map(line => {
            // Remove any ## headers and trim
            line = line.replace(/^#+\s*/g, '').trim();
            // Remove any bold markers
            line = line.replace(/\*\*(.*?)\*\*/g, '$1');
            return line;
          })
          .filter(line => line) // Remove empty lines
          .join('\n');
        markdownContent += `## Third Party Integrations\n\n${cleanedIntegrations}\n\n`;
      }

      // Add Data Flow Diagram section if available
      if (additionalInfo.data_flow_diagrams) {
        markdownContent += `## Data Flow Diagram\n\n`;
        
        if (additionalInfo.data_flow_diagrams.intro) {
          markdownContent += `### Introduction\n\n${additionalInfo.data_flow_diagrams.intro}\n\n`;
        }
        
        if (additionalInfo.data_flow_diagrams.diagram) {
          markdownContent += `### Diagram\n\n\`\`\`mermaid\n${additionalInfo.data_flow_diagrams.diagram}\n\`\`\`\n\n`;
        }
      }

      // Add Architecture Diagram section if available
      if (additionalInfo.mermaid_flow_diagrams) {
        markdownContent += `## Architecture Diagram\n\n`;
        
        if (additionalInfo.mermaid_flow_diagrams.intro) {
          markdownContent += `### Introduction\n\n${additionalInfo.mermaid_flow_diagrams.intro}\n\n`;
        }
        
        if (additionalInfo.mermaid_flow_diagrams.diagram) {
          markdownContent += `### Diagram\n\n\`\`\`mermaid\n${additionalInfo.mermaid_flow_diagrams.diagram}\n\`\`\`\n\n`;
        }
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
        
        // Check if we have multiple root/goal nodes (PASTA methodology)
        const goalNodes = nodes.filter(node => node.type === 'goal');
        const isPasta = goalNodes.length > 1;
        
        if (isPasta) {
          // Create a synthetic super root for PASTA methodology
          const superRootId = 'super-root';
          mermaidContent += `    ${superRootId}["Business Impact"]\n`;
          
          // Connect super root to all goal nodes
          goalNodes.forEach(goalNode => {
            mermaidContent += `    ${superRootId} --> ${goalNode.id}\n`;
            processNode(goalNode);
          });
        } else {
          // Use the existing root node for STRIDE methodology
          const rootNode = goalNodes[0] || nodes[0];
          if (rootNode) {
            processNode(rootNode);
          }
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
          // Check if this is a PASTA table by looking for Business Risk Type in the first item
          const isPasta = mitigations.length > 0 && ('Business Risk Type' in mitigations[0] || 'PASTA Stage' in mitigations[0]);
          
          // Create appropriate table header based on methodology
          if (isPasta) {
            markdownContent += `| Business Risk Type | Threat Type | Scenario | Suggested Mitigation(s) |\n`;
            markdownContent += `| ----------------- | ----------- | -------- | ---------------------- |\n`;
            
            // Add table rows for PASTA
            mitigations.forEach((mitigation: MitigationItem) => {
              const businessRiskType = Array.isArray(mitigation['Business Risk Type']) 
                ? mitigation['Business Risk Type'].join(', ')
                : mitigation['Business Risk Type'] || 'Unknown';
              
              const threatType = mitigation['Threat Type'] || 'Unknown';
              const scenario = mitigation['Scenario'] || '';
              const mitigationText = mitigation['Suggested Mitigation(s)'] || '';
              
              // Format the mitigation text to work well in markdown table
              const formattedMitigation = mitigationText.replace(/\n/g, ' ').replace(/\|/g, '\\|');
              
              markdownContent += `| ${businessRiskType} | ${threatType} | ${scenario} | ${formattedMitigation} |\n`;
            });
          } else {
            // STRIDE format
            markdownContent += `| Threat Type | Scenario | Suggested Mitigation(s) |\n`;
            markdownContent += `| ----------- | -------- | ---------------------- |\n`;
            
            // Add table rows for STRIDE
            mitigations.forEach((mitigation: MitigationItem) => {
              const threatType = mitigation['Threat Type'] || 'Unknown';
              const scenario = mitigation['Scenario'] || '';
              const mitigationText = mitigation['Suggested Mitigation(s)'] || '';
              
              // Format the mitigation text to work well in markdown table
              const formattedMitigation = mitigationText.replace(/\n/g, ' ').replace(/\|/g, '\\|');
              
              markdownContent += `| ${threatType} | ${scenario} | ${formattedMitigation} |\n`;
            });
          }
          
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

  const handleDownloadTmBom = async () => {
    if (!assessment_id) return;
    try {
      setDownloadingTmBom(true);
      setDownloadError(null);
      const blob = await apiService.downloadTmBom(assessment_id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `tmbom-${assessment_id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setDownloadError(err.message || 'Failed to download TM-BOM');
    } finally {
      setDownloadingTmBom(false);
    }
  };

  return (
    <>
    {/* Hidden cover page for print/PDF */}
    <div ref={coverPageRef} className="hidden">
      <div className="text-center">
        <h1 className="text-5xl font-bold text-gray-800 mb-8">Threat Modelling Report</h1>
        <h2 className="text-5xl font-bold text-gray-800 mb-8">
          {assessmentDetails?.projectName || 'Security Assessment Report'}
        </h2>
        {assessmentDetails?.department && (
          <p className="text-2xl text-gray-600 mt-4">{assessmentDetails.department}</p>
        )}
        <p className="text-xl text-gray-500 mt-8">{new Date().toLocaleDateString()}</p>
      </div>
    </div>

    <div className="min-h-screen bg-slate-50 dark:bg-gray-950" ref={reportRef}>
      {/* Sticky header + tab nav */}
      <div className="sticky top-0 z-30 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 shadow-sm print:hidden">
        <div className="px-6 py-3 flex items-center justify-between gap-4">
          <div className="min-w-0 flex-1">
            <p className="text-xs font-medium tracking-widest uppercase text-gray-400 mb-0.5">
              ThreatShield · Security Assessment
            </p>
            <h1 className="text-lg font-semibold text-gray-900 dark:text-white leading-tight truncate">
              {assessmentDetails ? assessmentDetails.projectName : 'Security Assessment Report'}
            </h1>
            <div className="flex flex-wrap gap-x-5 gap-y-0 text-xs text-gray-400 mt-0.5">
              {assessmentDetails?.department && <span>{assessmentDetails.department}</span>}
              <span>{assessmentDetails?.threatModelingMethodology || 'STRIDE'}</span>
              <span>{new Date().toLocaleDateString('en-US', {year:'numeric', month:'short', day:'numeric'})}</span>
            </div>
          </div>
          <div className="flex gap-2 shrink-0">
            <div ref={downloadMenuRef} className="relative">
              <button
                onClick={() => setShowDownloadOptions(!showDownloadOptions)}
                className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded border border-gray-800 dark:border-gray-600 bg-gray-900 dark:bg-gray-800 text-white hover:bg-gray-700 transition-colors"
                disabled={downloading || downloadingMarkdown}
              >
                {downloading || downloadingMarkdown ? (
                  <>
                    <svg className="animate-spin h-3.5 w-3.5" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Exporting...
                  </>
                ) : (
                  <>
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                    </svg>
                    Export
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </>
                )}
              </button>
              {showDownloadOptions && (
                <div className="absolute right-0 mt-1 w-52 rounded-md shadow-lg bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 z-50">
                  <div className="py-1">
                    <button
                      onClick={() => { setShowDownloadOptions(false); handleDownload(); }}
                      className="w-full text-left px-4 py-3 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 flex items-center gap-3 transition-colors"
                    >
                      <svg className="w-4 h-4 text-gray-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      <div>
                        <div className="font-medium">Download PDF</div>
                        <div className="text-xs text-gray-400">Full security report</div>
                      </div>
                    </button>
                    <div className="border-t border-gray-100 dark:border-gray-800" />
                    <button
                      onClick={() => { setShowDownloadOptions(false); handleDownloadMarkdown(); }}
                      className="w-full text-left px-4 py-3 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 flex items-center gap-3 transition-colors"
                    >
                      <svg className="w-4 h-4 text-gray-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      <div>
                        <div className="font-medium">Download Markdown</div>
                        <div className="text-xs text-gray-400">.md file</div>
                      </div>
                    </button>
                    <div className="border-t border-gray-100 dark:border-gray-800" />
                    <button
                      onClick={() => { setShowDownloadOptions(false); handleDownloadJson(); }}
                      className="w-full text-left px-4 py-3 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 flex items-center gap-3 transition-colors"
                    >
                      <svg className="w-4 h-4 text-gray-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582 4-8 4" />
                      </svg>
                      <div>
                        <div className="font-medium">Download JSON</div>
                        <div className="text-xs text-gray-400">Raw assessment data</div>
                      </div>
                    </button>
                    <div className="border-t border-gray-100 dark:border-gray-800" />
                    <button
                      onClick={() => { setShowDownloadOptions(false); handleDownloadTmBom(); }}
                      className="w-full text-left px-4 py-3 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 flex items-center gap-3 transition-colors"
                    >
                      <svg className="w-4 h-4 text-cyan-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      <div>
                        <div className="font-medium">Download TM-BOM</div>
                        <div className="text-xs text-gray-400">Threat Model Bill of Materials</div>
                      </div>
                    </button>
                  </div>
                </div>
              )}
            </div>
            <button
              onClick={handleChatClick}
              className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
              Ask AI
            </button>
          </div>
        </div>

        {/* Tab navigation */}
        <div className="px-6 flex overflow-x-auto border-t border-gray-100 dark:border-gray-800">
          {[
            { id: 'overview',    label: 'Overview' },
            { id: 'threats',     label: 'Threat Model' },
            { id: 'dread',       label: 'DREAD' },
            { id: 'mitigations', label: 'Mitigations' },
            { id: 'attack_tree', label: 'Attack Tree' },
            { id: 'dfd',         label: 'DFD' },
            { id: 'test_cases',  label: 'Test Cases' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveMainTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium whitespace-nowrap border-b-2 transition-colors ${
                activeMainTab === tab.id
                  ? 'border-gray-900 dark:border-gray-100 text-gray-900 dark:text-white'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {downloadError && (
        <div className="mx-6 mt-4 p-3 bg-red-50 border border-red-200 rounded-md text-red-700 flex items-center gap-2 text-sm">
          <svg className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>{downloadError}</span>
        </div>
      )}

      {/* Tab content */}
      <div className="px-6 py-6 w-full">

        {/* Overview Tab */}
        {activeMainTab === 'overview' && (
          <div className="space-y-6">

        {/* ── Metrics Cards ── */}
        {(() => {
          const threats: any[] = reportData.threat_model.data?.result?.result?.raw_response?.threat_model || [];
          const dreadItems: any[] = reportData.dread_assessment.data?.result?.result?.raw_response?.['Risk Assessment'] || [];
          const totalThreats = threats.length;
          const highCriticalCount = dreadItems.filter((item: any) => {
            const sum = Number(item['Damage Potential'] || 0) + Number(item['Reproducibility'] || 0) +
              Number(item['Exploitability'] || 0) + Number(item['Affected Users'] || 0) + Number(item['Discoverability'] || 0);
            return (sum / 5) >= 8;
          }).length;
          const totalTestCases = (testCasesData?.result?.test_cases || []).reduce(
            (acc: number, g: any) => acc + (g.test_cases?.length || 0), 0
          );
          const categoryMap: Record<string, number> = {};
          threats.forEach((t: any) => {
            const type = t['Threat Type'] || 'Other';
            categoryMap[type] = (categoryMap[type] || 0) + 1;
          });
          const strideColors: Record<string, string> = {
            'Spoofing':               'bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300 border-purple-200 dark:border-purple-700',
            'Tampering':              'bg-orange-50 dark:bg-orange-900/20 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-700',
            'Repudiation':            'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-300 border-yellow-200 dark:border-yellow-700',
            'Information Disclosure': 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-700',
            'Denial of Service':      'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 border-red-200 dark:border-red-700',
            'Elevation of Privilege': 'bg-rose-50 dark:bg-rose-900/20 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-700',
          };
          if (totalThreats === 0 && dreadItems.length === 0) return null;
          return (
            <div>
              {/* Summary row */}
              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-5 flex flex-col gap-1">
                  <span className="text-xs font-semibold uppercase tracking-widest text-gray-400">Total Issues</span>
                  <span className="text-4xl font-bold text-gray-900 dark:text-white">{totalThreats}</span>
                  <span className="text-xs text-gray-400">threats identified</span>
                </div>
                <div className="bg-white dark:bg-gray-900 rounded-xl border border-red-200 dark:border-red-800 p-5 flex flex-col gap-1">
                  <span className="text-xs font-semibold uppercase tracking-widest text-red-400">High / Critical</span>
                  <span className="text-4xl font-bold text-red-600 dark:text-red-400">{highCriticalCount}</span>
                  <span className="text-xs text-gray-400">DREAD avg score ≥ 8</span>
                </div>
                <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-5 flex flex-col gap-1">
                  <span className="text-xs font-semibold uppercase tracking-widest text-gray-400">Test Cases</span>
                  <span className="text-4xl font-bold text-gray-900 dark:text-white">{totalTestCases}</span>
                  <span className="text-xs text-gray-400">security test cases</span>
                </div>
              </div>

              {/* Per-category row */}
              {Object.keys(categoryMap).length > 0 && (
                <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
                  {Object.entries(categoryMap).map(([cat, count]) => (
                    <div key={cat} className={`rounded-lg border p-3 flex flex-col gap-0.5 ${strideColors[cat] || 'bg-gray-50 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-gray-200 dark:border-gray-700'}`}>
                      <span className="text-2xl font-bold">{count}</span>
                      <span className="text-xs font-medium leading-tight">{cat}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })()}

        {/* About Box - Introduction Section */}
        {introductionLoading ? (
          <div className="bg-white dark:bg-gray-900/80 shadow-lg rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700/60 p-6">
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-600"></div>
            </div>
          </div>
        ) : introductionError ? (
          <div className="bg-white dark:bg-gray-900/80 shadow-lg rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700/60 p-6">
            <div className="bg-red-50 p-4 rounded-lg text-red-600 border border-red-200">
              <div className="flex items-center">
                <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {introductionError}
              </div>
            </div>
          </div>
        ) : introduction || additionalInfo.functional_flows || additionalInfo.third_party_integrations || additionalInfo.data_flow_diagrams || additionalInfo.mermaid_flow_diagrams ? (
          <div className="bg-white dark:bg-gray-900/80 shadow-lg rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700/60">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700/60 flex items-center gap-3">
              <div className="w-0.5 h-5 bg-gray-800 dark:bg-gray-400 rounded-full shrink-0" />
              <h2 className="text-base font-semibold text-gray-900 dark:text-white tracking-tight">Introduction</h2>
            </div>
            <div className="p-6">
              {introduction && (
                <div className="text-gray-700 dark:text-slate-300 mb-6 space-y-2">
                  {introduction.split('\n').map((line, idx) => {
                    if (line.match(/^#+\s/)) return <h4 key={idx} className="font-semibold mt-3 mb-1">{line.replace(/^#+\s/, '')}</h4>;
                    const clean = line.replace(/\*\*(.*?)\*\*/g, '$1');
                    return <p key={idx}>{clean}</p>;
                  })}
                </div>
              )}
              
              {/* Section Toggle */}
              <div className="mb-6">
                <div className="bg-gray-100 dark:bg-gray-800 p-2 rounded-lg flex space-x-2">
                  <button
                    onClick={() => setActiveSection('functional_flows')}
                    className={`flex-1 px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 ${
                      activeSection === 'functional_flows'
                        ? 'bg-white dark:bg-gray-800 text-gray-900 dark:text-slate-200 shadow-sm'
                        : 'text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-200'
                    }`}
                  >
                    Functional Flows
                  </button>
                  <button
                    onClick={() => setActiveSection('third_party_integrations')}
                    className={`flex-1 px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 ${
                      activeSection === 'third_party_integrations'
                        ? 'bg-white dark:bg-gray-800 text-gray-900 dark:text-slate-200 shadow-sm'
                        : 'text-gray-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-200'
                    }`}
                  >
                    Third Party
                  </button>
                </div>
              </div>

              {/* Additional Info Sections */}
              {(additionalInfo.functional_flows || additionalInfo.third_party_integrations) && (
                <div className="space-y-6">
                  {additionalInfo.functional_flows && activeSection === 'functional_flows' && (
                    <div>
                      <div className="flex justify-between items-center mb-3">
                        <h3 className="text-lg font-semibold text-gray-800 dark:text-slate-200">Functional Flows</h3>
                        <button
                          onClick={() => toggleSection('functional_flows')}
                          className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-full transition-colors duration-200"
                        >
                          <svg
                            className={`w-6 h-6 transform transition-transform duration-200 ${collapsedSections.functional_flows ? '-rotate-90' : ''}`}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </button>
                      </div>
                      <div className={`bg-gray-50 dark:bg-gray-800/60 p-4 rounded-lg border border-gray-200 dark:border-gray-700 transition-all duration-200 overflow-hidden ${
                        collapsedSections.functional_flows ? 'h-0 p-0 border-0' : ''
                      }`}>
                        <div className="text-gray-700 dark:text-slate-300">
                          {additionalInfo.functional_flows.split('\n').map((line, index) => {
                            // Check if line starts with any number of #
                            if (line.match(/^#+\s/)) {
                              return <h4 key={index} className="text-md font-semibold mt-3 mb-2">{line.replace(/^#+\s/, '')}</h4>;
                            }
                            // Remove bold text markers
                            const cleanLine = line.replace(/\*\*(.*?)\*\*/g, '$1');
                            return <p key={index} className="mb-2">{cleanLine}</p>;
                          })}
                        </div>
                      </div>
                    </div>
                  )}
                  
                  {additionalInfo.third_party_integrations && activeSection === 'third_party_integrations' && (
                    <div>
                      <div className="flex justify-between items-center mb-3">
                        <h3 className="text-lg font-semibold text-gray-800 dark:text-slate-200">Third Party Integrations</h3>
                        <button
                          onClick={() => toggleSection('third_party_integrations')}
                          className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-full transition-colors duration-200"
                        >
                          <svg
                            className={`w-6 h-6 transform transition-transform duration-200 ${collapsedSections.third_party_integrations ? '-rotate-90' : ''}`}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </button>
                      </div>
                      <div className={`bg-gray-50 dark:bg-gray-800/60 p-4 rounded-lg border border-gray-200 dark:border-gray-700 transition-all duration-200 overflow-hidden ${
                        collapsedSections.third_party_integrations ? 'h-0 p-0 border-0' : ''
                      }`}>
                        <div className="text-gray-700 dark:text-slate-300">
                          {additionalInfo.third_party_integrations.split('\n').map((line, index) => {
                            // Check if line starts with any number of #
                            if (line.match(/^#+\s/)) {
                              return <h4 key={index} className="text-md font-semibold mt-3 mb-2">{line.replace(/^#+\s/, '')}</h4>;
                            }
                            // Remove bold text markers
                            const cleanLine = line.replace(/\*\*(.*?)\*\*/g, '$1');
                            return <p key={index} className="mb-2">{cleanLine}</p>;
                          })}
                        </div>
                      </div>
                    </div>
                  )}

                </div>
              )}
            </div>
          </div>
        ) : null}
          </div>
        )}

        {/* Threats Tab */}
        {activeMainTab === 'threats' && (
        <div className="bg-white dark:bg-gray-900/80 shadow-lg rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700/60">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700/60 flex items-center gap-3">
            <div className="w-0.5 h-5 bg-gray-800 dark:bg-gray-400 rounded-full shrink-0" />
            <h2 className="text-base font-semibold text-gray-900 dark:text-white tracking-tight">Threat Model Analysis</h2>
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
                  <h3 className="text-lg font-semibold text-gray-800 dark:text-slate-200 mb-4 flex items-center">
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
                <div className="table-container shadow-sm mb-6 overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
                  <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead className="bg-gray-50 dark:bg-gray-800">
                      <tr>
                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Threat Type</th>
                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Scenario</th>
                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Potential Impact</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white dark:bg-gray-900/80 divide-y divide-gray-200 dark:divide-gray-700">
                      {reportData.threat_model.data?.result?.result?.raw_response?.threat_model?.map((threat: Threat, index: number) => (
                        <tr key={index} className={index % 2 === 0 ? 'bg-white dark:bg-gray-900/80' : 'bg-gray-50 dark:bg-gray-800/60'}>
                          <td className="px-6 py-4 whitespace-normal text-sm font-medium text-red-700 border-l-4 border-red-500">
                            <div className="flex items-center">
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                              </svg>
                              {threat['Threat Type']}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-normal text-sm text-gray-700 dark:text-slate-300">{threat['Scenario']}</td>
                          <td className="px-6 py-4 whitespace-normal text-sm text-gray-700 dark:text-slate-300">{threat['Potential Impact']}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

              </div>
            ) : (
              <div className="bg-gray-50 dark:bg-gray-800/60 p-4 rounded-lg text-gray-500 dark:text-slate-400 border border-gray-200 dark:border-gray-700">
                No threat model data available
              </div>
            )}
          </div>
        </div>
        )}

        {/* DREAD Tab */}
        {activeMainTab === 'dread' && (
          <div className="bg-white dark:bg-gray-900/80 shadow-lg rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700/60">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700/60 flex items-center gap-3">
            <div className="w-0.5 h-5 bg-gray-800 dark:bg-gray-400 rounded-full shrink-0" />
            <h2 className="text-base font-semibold text-gray-900 dark:text-white tracking-tight">DREAD Risk Assessment</h2>
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
                  <h3 className="text-lg font-semibold text-gray-800 dark:text-slate-200 mb-4 flex items-center">
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
                            <div className="mt-2 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
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
                <div className="table-container shadow-sm overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
                  <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead className="bg-gray-50 dark:bg-gray-800">
                      <tr>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Threat Type</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Scenario</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Damage</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Reproducibility</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Exploitability</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Affected Users</th>
                        <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Discoverability</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white dark:bg-gray-900/80 divide-y divide-gray-200 dark:divide-gray-700">
                      {reportData.dread_assessment.data?.result?.result?.raw_response?.['Risk Assessment']?.map((assessment: DreadAssessmentItem, index: number) => (
                        <tr key={index} className={index % 2 === 0 ? 'bg-white dark:bg-gray-900/80' : 'bg-gray-50 dark:bg-gray-800/60'}>
                          <td className="px-4 py-4 whitespace-normal text-sm font-medium text-yellow-700 border-l-4 border-yellow-500">
                            {assessment['Threat Type']}
                          </td>
                          <td className="px-4 py-4 whitespace-normal text-sm text-gray-700 dark:text-slate-300">{assessment['Scenario']}</td>
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
              <div className="bg-gray-50 dark:bg-gray-800/60 p-4 rounded-lg text-gray-500 dark:text-slate-400 border border-gray-200 dark:border-gray-700">
                No DREAD assessment data available
              </div>
            )}
          </div>
        </div>
        )}

        {/* Attack Tree Tab */}
        {activeMainTab === 'attack_tree' && (
          <div className="bg-white dark:bg-gray-900/80 shadow-lg rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700/60">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700/60 flex items-center gap-3">
            <div className="w-0.5 h-5 bg-gray-800 dark:bg-gray-400 rounded-full shrink-0" />
            <h2 className="text-base font-semibold text-gray-900 dark:text-white tracking-tight">Attack Tree Analysis</h2>
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
                <div style={{ height: (reportData.attack_tree.data?.result?.result?.attack_tree?.nodes?.filter(node => node.type === 'goal')?.length || 0) > 1 ? 800 : 600 }} className="w-full border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                  <AttackTreeVisualization attackTreeData={reportData.attack_tree.data?.result?.result} />
                </div>
              </div>
            ) : (
              <div className="bg-gray-50 dark:bg-gray-800/60 p-4 rounded-lg text-gray-500 dark:text-slate-400 border border-gray-200 dark:border-gray-700">
                No attack tree data available
              </div>
            )}
          </div>
        </div>
        )}

        {/* Mitigations Tab */}
        {activeMainTab === 'mitigations' && (
        <div className="bg-white dark:bg-gray-900/80 shadow-lg rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700/60">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700/60 flex items-center gap-3">
            <div className="w-0.5 h-5 bg-gray-800 dark:bg-gray-400 rounded-full shrink-0" />
            <h2 className="text-base font-semibold text-gray-900 dark:text-white tracking-tight">Mitigation Recommendations</h2>
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
                <div className="table-container shadow-sm overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
                  <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead className="bg-gray-50 dark:bg-gray-800">
                      <tr>
                        {(() => {
                          const mitigations = reportData.mitigation.data?.result?.result?.raw_response?.mitigations || [];
                          // Check if this is a PASTA table by looking for Business Risk Type in the first item
                          const isPasta = mitigations.length > 0 && ('Business Risk Type' in mitigations[0] || 'PASTA Stage' in mitigations[0]);
                          
                          return isPasta ? (
                            <>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Business Risk Type</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Threat Type</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider w-1/4">Scenario</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Mitigation Strategy</th>
                            </>
                          ) : (
                            <>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Threat Type</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider w-1/4">Scenario</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">Mitigation Strategy</th>
                            </>
                          );
                        })()}
                      </tr>
                    </thead>
                    <tbody className="bg-white dark:bg-gray-900/80 divide-y divide-gray-200 dark:divide-gray-700">
                      {(() => {
                        const mitigations = reportData.mitigation.data?.result?.result?.raw_response?.mitigations || [];
                        // Check if this is a PASTA table by looking for Business Risk Type in the first item
                        const isPasta = mitigations.length > 0 && ('Business Risk Type' in mitigations[0] || 'PASTA Stage' in mitigations[0]);
                        
                        return mitigations.map((mitigation: MitigationItem, index: number) => (
                          <tr key={index} className={index % 2 === 0 ? 'bg-white dark:bg-gray-900/80' : 'bg-gray-50 dark:bg-gray-800/60'}>
                            {isPasta ? (
                              <>
                                <td className="px-6 py-4 whitespace-normal text-sm text-gray-700 dark:text-slate-300">
                                  {Array.isArray(mitigation['Business Risk Type']) 
                                    ? mitigation['Business Risk Type'].join(', ')
                                    : mitigation['Business Risk Type'] || 'Unknown'}
                                </td>
                                <td className="px-6 py-4 whitespace-normal text-sm font-medium text-green-700">
                                  <div className="flex items-center">
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                    </svg>
                                    {mitigation['Threat Type'] || 'Unknown'}
                                  </div>
                                </td>
                                <td className="px-6 py-4 whitespace-normal text-sm text-gray-700 dark:text-slate-300">{mitigation['Scenario']}</td>
                                <td className="px-6 py-4 whitespace-normal text-sm text-gray-700 dark:text-slate-300">
                                  <div className="prose prose-blue max-w-none">
                                    {mitigation['Suggested Mitigation(s)'] && typeof mitigation['Suggested Mitigation(s)'] === 'string'
                                      ? <ul className="list-none">
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
                                      : 'No mitigation details available'}
                                  </div>
                                </td>
                              </>
                            ) : (
                              <>
                                <td className="px-6 py-4 whitespace-normal text-sm font-medium text-green-700">
                                  <div className="flex items-center">
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                    </svg>
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                    </svg>
                                    {mitigation['Threat Type'] || 'Unknown'}
                                  </div>
                                </td>
                                <td className="px-6 py-4 whitespace-normal text-sm text-gray-700 dark:text-slate-300">{mitigation['Scenario']}</td>
                                <td className="px-6 py-4 whitespace-normal text-sm text-gray-700 dark:text-slate-300">
                                  <div className="prose prose-blue max-w-none">
                                    {mitigation['Suggested Mitigation(s)'] && typeof mitigation['Suggested Mitigation(s)'] === 'string'
                                      ? <ul className="list-none">
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
                                      : 'No mitigation details available'}
                                  </div>
                                </td>
                              </>
                            )}
                          </tr>
                        ));
                      })()}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="bg-gray-50 dark:bg-gray-800/60 p-4 rounded-lg text-gray-500 dark:text-slate-400 border border-gray-200 dark:border-gray-700">
                No mitigation data available
              </div>
            )}
          </div>
        </div>
        )}

        {/* DFD Tab */}
        {activeMainTab === 'dfd' && (
          <div className="space-y-6">
            {/* Data Flow Diagram */}
            {additionalInfo.data_flow_diagrams ? (
              <div className="bg-white dark:bg-gray-900/80 shadow-sm rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700/60">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700/60 flex items-center gap-3">
                  <div className="w-0.5 h-5 bg-gray-800 dark:bg-gray-400 rounded-full shrink-0" />
                  <h2 className="text-base font-semibold text-gray-900 dark:text-white tracking-tight">Data Flow Diagram</h2>
                </div>
                <div className="p-6">
                  {additionalInfo.data_flow_diagrams.intro && (
                    <p className="text-sm text-gray-600 dark:text-slate-400 mb-4">{additionalInfo.data_flow_diagrams.intro}</p>
                  )}
                  {additionalInfo.data_flow_diagrams.diagram && (
                    <div className="mb-6">
                      <MermaidDiagram content={additionalInfo.data_flow_diagrams.diagram} />
                    </div>
                  )}
                  {additionalInfo.data_flow_diagrams.description && (
                    <div className="mt-4 text-sm text-gray-700 dark:text-slate-300 space-y-2">
                      {additionalInfo.data_flow_diagrams.description.split('\n').map((line: string, idx: number) => {
                        if (line.match(/^#+\s/)) return <h4 key={idx} className="font-semibold mt-3 mb-1">{line.replace(/^#+\s/, '')}</h4>;
                        if (line.startsWith('•')) return (
                          <p key={idx} className="ml-4 flex items-start gap-2">
                            <span>•</span><span>{line.substring(1).trim().replace(/\*\*(.*?)\*\*/g, '$1')}</span>
                          </p>
                        );
                        return <p key={idx}>{line.replace(/\*\*(.*?)\*\*/g, '$1')}</p>;
                      })}
                    </div>
                  )}
                </div>
              </div>
            ) : null}

            {/* Architecture / Functional Flow Diagram */}
            {additionalInfo.mermaid_flow_diagrams ? (
              <div className="bg-white dark:bg-gray-900/80 shadow-sm rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700/60">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700/60 flex items-center gap-3">
                  <div className="w-0.5 h-5 bg-gray-800 dark:bg-gray-400 rounded-full shrink-0" />
                  <h2 className="text-base font-semibold text-gray-900 dark:text-white tracking-tight">Architecture Diagram</h2>
                </div>
                <div className="p-6">
                  {additionalInfo.mermaid_flow_diagrams.intro && (
                    <p className="text-sm text-gray-600 dark:text-slate-400 mb-4">{additionalInfo.mermaid_flow_diagrams.intro}</p>
                  )}
                  {additionalInfo.mermaid_flow_diagrams.diagram && (
                    <div className="mb-6">
                      <MermaidDiagram content={additionalInfo.mermaid_flow_diagrams.diagram} />
                    </div>
                  )}
                  {additionalInfo.mermaid_flow_diagrams.description && (
                    <div className="mt-4 text-sm text-gray-700 dark:text-slate-300 space-y-2">
                      {additionalInfo.mermaid_flow_diagrams.description.split('\n').map((line: string, idx: number) => {
                        if (line.match(/^#+\s/)) return <h4 key={idx} className="font-semibold mt-3 mb-1">{line.replace(/^#+\s/, '')}</h4>;
                        if (line.startsWith('•')) return (
                          <p key={idx} className="ml-4 flex items-start gap-2">
                            <span>•</span><span>{line.substring(1).trim().replace(/\*\*(.*?)\*\*/g, '$1')}</span>
                          </p>
                        );
                        return <p key={idx}>{line.replace(/\*\*(.*?)\*\*/g, '$1')}</p>;
                      })}
                    </div>
                  )}
                </div>
              </div>
            ) : null}

            {!additionalInfo.data_flow_diagrams && !additionalInfo.mermaid_flow_diagrams && (
              <div className="py-8 text-center text-gray-400 text-sm">No diagram data available for this assessment.</div>
            )}
          </div>
        )}

        {/* Test Cases Tab */}
        {activeMainTab === 'test_cases' && (
          <div className="bg-white dark:bg-gray-900/80 shadow-sm rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700/60">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700/60 flex items-center gap-3">
              <div className="w-0.5 h-5 bg-gray-800 dark:bg-gray-400 rounded-full shrink-0" />
              <h2 className="text-base font-semibold text-gray-900 dark:text-white tracking-tight">Security Test Cases</h2>
            </div>
            <div className="p-6">
              {testCasesLoading ? (
                <div className="flex items-center justify-center py-12">
                  <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-gray-600"></div>
                </div>
              ) : testCasesError ? (
                <div className="bg-red-50 p-4 rounded-lg text-red-600 border border-red-200">{testCasesError}</div>
              ) : testCasesData?.result?.test_cases?.length > 0 ? (
                <div className="space-y-8">
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    ASVS-aligned test cases for validating security controls. Adapt these best-practice verification steps to your testing environment.
                  </p>
                  {testCasesData.result.test_cases.map((group: any, gi: number) => (
                    <div key={gi} className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                      <div className="bg-gray-50 dark:bg-gray-800 px-5 py-3 border-b border-gray-200 dark:border-gray-700">
                        <div className="flex items-start gap-3">
                          <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-gray-200 dark:bg-gray-700 text-xs font-semibold text-gray-600 dark:text-gray-300 shrink-0 mt-0.5">{gi + 1}</span>
                          <div className="min-w-0">
                            <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{group['Threat Type'] || 'General'}</h3>
                            {group['Scenario'] && (
                              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5 line-clamp-2">{group['Scenario']}</p>
                            )}
                            {group['asvs_requirement'] && (
                              <p className="text-xs text-gray-400 mt-0.5 font-mono">{group['asvs_requirement']}</p>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="divide-y divide-gray-100 dark:divide-gray-800">
                        {(group.test_cases || []).map((tc: any, ti: number) => (
                          <div key={ti} className="px-5 py-4">
                            <div className="flex items-start gap-3">
                              <span className="text-xs font-medium text-gray-400 w-5 shrink-0 pt-0.5">{ti + 1}.</span>
                              <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium text-gray-800 dark:text-gray-200 mb-2">{tc.test_description || tc.description || ''}</p>
                                {Array.isArray(tc.steps) && tc.steps.length > 0 && (
                                  <div className="mb-2">
                                    <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Steps</p>
                                    <ol className="space-y-0.5">
                                      {tc.steps.map((step: string, si: number) => (
                                        <li key={si} className="text-xs text-gray-600 dark:text-gray-400">{step}</li>
                                      ))}
                                    </ol>
                                  </div>
                                )}
                                {tc.expected_result && (
                                  <div className="mt-1">
                                    <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">Expected: </span>
                                    <span className="text-xs text-gray-600 dark:text-gray-400">{tc.expected_result}</span>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-8 text-center text-gray-400 text-sm">No test case data available for this assessment.</div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
    </>
  );
};

export default Report;
