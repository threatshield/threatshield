import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import NavigationButtons from '../components/common/NavigationButtons';
import { useAssessment } from '../context/AssessmentContext';
import { apiService, API_BASE_URL } from '../services/api';
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

interface AttackTreeNode {
  id: string;
  type: 'goal' | 'attack' | 'vulnerability';
  label: string;
  children?: AttackTreeNode[];
}

interface AttackTreeResponse {
  timestamp: string;
  result: {
    attack_tree: {
      nodes: AttackTreeNode[];
    };
    markdown: string;
  };
}

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

const nodeTypes: NodeTypes = {
  goal: GoalNode,
  attack: AttackNode,
  vulnerability: VulnerabilityNode,
};

const AttackTree: React.FC = () => {
  const navigate = useNavigate();
  const { assessment_id } = useParams<{ assessment_id: string }>();
  const { setAttackTreeData: setContextAttackTreeData, attackTreeData: contextAttackTreeData } = useAssessment();
  const [attackTreeData, setAttackTreeData] = useState<AttackTreeResponse | null>(null);
  const [dreadData, setDreadData] = useState<any | null>(null);
  const [mitigationData, setMitigationData] = useState<any | null>(null);
  const [nodes, setNodes] = useState<Node<any>[]>([]);
  const [edges, setEdges] = useState<Edge<any>[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [assessmentDetails, setAssessmentDetails] = useState<{
    department: string;
    projectName: string;
    timestamp: string;
    threatModelingMethodology?: string;
  } | null>(null);
  const [isPasta, setIsPasta] = useState<boolean>(false);

  // Fetch assessment details from storage history and additional details
  useEffect(() => {
    const fetchAssessmentDetails = async () => {
      if (assessment_id) {
        try {
          // Fetch basic details from storage history
          const response = await apiService.getStorageHistory();
          let details = null;

          if (response && response.data) {
            const report = response.data.find(r => r.id === assessment_id);
            if (report && report.details) {
              details = report.details;
            } else {
              console.error('Report or details not found for assessment ID:', assessment_id);
            }
          } else {
            console.error('Failed to fetch storage history');
          }

          // Fetch additional details including threatModelingMethodology
          try {
            const additionalDetailsResponse = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=additionalinfo`);
            if (additionalDetailsResponse.ok) {
              const additionalData = await additionalDetailsResponse.json();
              if (additionalData && additionalData.result) {
                const methodology = additionalData.result.threatModelingMethodology ||
                                   additionalData.result.methodology ||
                                   'STRIDE'; // Default to STRIDE if not specified

                // Ensure all required properties are present
                if (details) {
                  details = {
                    department: details.department || 'Unknown',
                    projectName: details.projectName || 'Unknown Project',
                    timestamp: details.timestamp || new Date().toISOString(),
                    threatModelingMethodology: methodology
                  };
                } else {
                  details = {
                    department: 'Unknown',
                    projectName: 'Unknown Project',
                    timestamp: new Date().toISOString(),
                    threatModelingMethodology: methodology
                  };
                }
                console.log('Threat modeling methodology:', details.threatModelingMethodology);
              }
            }
          } catch (additionalError) {
            console.error('Error fetching additional details:', additionalError);
          }

          // Ensure we have valid details before setting state
          if (details) {
            setAssessmentDetails(details);
          }
        } catch (error) {
          console.error('Error fetching assessment details:', error);
        }
      }
    };

    fetchAssessmentDetails();
  }, [assessment_id]);

  useEffect(() => {
    const fetchData = async () => {
      if (!assessment_id) {
        setError('No assessment ID provided');
        return;
      }

      try {
        setLoading(true);
        console.log('Fetching attack tree data for assessment ID:', assessment_id);

        // Direct API call to storage endpoint to ensure we get the latest data
        const response = await fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=attack_tree`);
        if (!response.ok) {
          throw new Error(`Failed to fetch attack tree data: ${response.status}`);
        }

        const data = await response.json();
        console.log('Raw attack tree data:', JSON.stringify(data, null, 2));

        // Handle various possible response structures
        let processedData: AttackTreeResponse | null = null;
        let treeNodes: AttackTreeNode[] | null = null;

        // Case 1: Double-nested result structure (result.result.attack_tree)
        if (data?.result?.result?.attack_tree?.nodes) {
          console.log('Found double-nested result structure');
          processedData = {
            timestamp: data.timestamp,
            result: data.result.result
          };
          treeNodes = data.result.result.attack_tree.nodes;
        }
        // Case 2: Standard structure (result.attack_tree)
        else if (data?.result?.attack_tree?.nodes) {
          console.log('Found standard result structure');
          processedData = data;
          treeNodes = data.result.attack_tree.nodes;
        }
        // Case 3: Nodes directly in result
        else if (data?.result?.nodes) {
          console.log('Found nodes directly in result');
          processedData = {
            timestamp: data.timestamp || new Date().toISOString(),
            result: {
              attack_tree: {
                nodes: data.result.nodes
              },
              markdown: data.result.markdown || ''
            }
          };
          treeNodes = data.result.nodes;
        }

        if (processedData && treeNodes) {
          console.log('Processed attack tree data:', processedData);
          setAttackTreeData(processedData);
          setContextAttackTreeData(processedData);
          processAttackTreeData(treeNodes);
        } else {
          console.error('Could not process attack tree data from response:', data);

          // Fallback to service method if direct API call doesn't work
          console.log('Falling back to service method');
          const attackTreeResponse = await apiService.getAttackTree(assessment_id);
          if (attackTreeResponse?.result?.attack_tree?.nodes) {
            setAttackTreeData(attackTreeResponse);
            setContextAttackTreeData(attackTreeResponse);
            processAttackTreeData(attackTreeResponse.result.attack_tree.nodes);
          } else {
            throw new Error('Invalid attack tree data format received');
          }
        }

        // Fetch DREAD and mitigation data in parallel
        const [dreadResponse, mitigationResponse] = await Promise.allSettled([
          apiService.getDreadAssessment(assessment_id),
          apiService.getMitigations(assessment_id)
        ]);

        setDreadData(dreadResponse.status === 'fulfilled' ? dreadResponse.value : null);
        setMitigationData(mitigationResponse.status === 'fulfilled' ? mitigationResponse.value : null);

      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to load attack tree data';
        setError(errorMessage);
        console.error('Error in data fetching:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    // Remove contextAttackTreeData from dependencies to prevent unnecessary re-renders
  }, [assessment_id, setContextAttackTreeData]);

  const processAttackTreeData = (treeNodes: AttackTreeNode[]) => {
    try {
      const flowNodes: Node<any>[] = [];
      const flowEdges: Edge<any>[] = [];

      // Create a map to store node positions
      const nodePositions: Record<string, { x: number, y: number }> = {};

      // Function to generate dynamic PASTA configuration based on node counts
      const generatePASTAConfig = (nodeCounts: { level1: number; level2: number; level3Max: number }) => {
        const { level1, level2, level3Max } = nodeCounts;

        return {
          baseWidth: 350 + 50 * Math.max(level1, 1), // scale with business impacts
          level0: { xGap: 0 },
          level1: {
            xGapMultiplier: Math.max(5, 3 + level1 * 0.5), // space out level 1 (business impact)
            siblingFactor: 0.8
          },
          level2: {
            xGapMultiplier: Math.max(2, 1 + level2 * 0.2), // space out attack methods
            siblingFactor: 0.9
          },
          level3: {
            xGapMultiplier: Math.max(1.5, 1 + level3Max * 0.3), // space out based on child count
            siblingFactor: 1.1
          },
          verticalBase: 250,
          verticalIncrement: 50,
          horizontalOffset: {
            default: 30,
            vulnerability: Math.max(40, level3Max * 10) // adapt based on depth
          }
        };
      };

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
          baseWidth: 250,
          level0: { xGap: 0 },
          level1: { xGapMultiplier: 1.8, siblingFactor: 0.5 },
          level2: { xGapMultiplier: 1.0, siblingFactor: 0.6 },
          verticalBase: 160,
          verticalIncrement: 25,
          horizontalOffset: 15
        },
        PASTA: {
          baseWidth: 400,
          level0: { xGap: 0 },
          level1: { xGapMultiplier: 5.5, siblingFactor: 0.8 },
          level2: { xGapMultiplier: 2.0, siblingFactor: 0.9 },
          level3: {
            xGapMultiplier: 1.4,
            siblingFactor: 1.2
          },
          verticalBase: 260,
          verticalIncrement: 50,
          horizontalOffset: {
            default: 30,
            vulnerability: 40
          }
        }
      };

      // Check if we have multiple root/goal nodes (PASTA methodology)
      const rootGoalNodes = treeNodes.filter(node => node.type === 'goal');
      const isPastaStructure = rootGoalNodes.length > 1;

      // Determine methodology based on assessment details or tree structure
      let methodology = 'STRIDE';

      // Use assessment details if available, otherwise use tree structure
      if (assessmentDetails?.threatModelingMethodology) {
        methodology = assessmentDetails.threatModelingMethodology.toUpperCase() === 'PASTA' ? 'PASTA' : 'STRIDE';
      } else {
        methodology = isPastaStructure ? 'PASTA' : 'STRIDE';
      }

      const isPasta = methodology === 'PASTA';
      setIsPasta(isPasta); // Update state for use in the component

      // For PASTA methodology, count nodes at each level to generate dynamic configuration
      let config = spacingConfig[methodology];

      if (isPasta) {
        const level1Count = rootGoalNodes.length;
        let level2Count = 0;
        let level3MaxCount = 0;

        rootGoalNodes.forEach(goalNode => {
          if (goalNode.children && goalNode.children.length > 0) {
            level2Count += goalNode.children.length;
            goalNode.children.forEach(attackMethod => {
              if (attackMethod.children && attackMethod.children.length > 0) {
                level3MaxCount = Math.max(level3MaxCount, attackMethod.children.length);
              }
            });
          }
        });

        console.log(`PASTA node counts - Business Impacts: ${level1Count}, Attack Methods: ${level2Count}, Max Vulnerabilities: ${level3MaxCount}`);

        config = generatePASTAConfig({
          level1: level1Count,
          level2: level2Count,
          level3Max: level3MaxCount
        });

        console.log('Using dynamically generated PASTA configuration:', config);
      } else {
        console.log(`Using static ${methodology} spacing configuration`);
      }

      // Create nodes function with optimized positioning for attack trees
      const createNodes = (node: AttackTreeNode, level: number, position: number, totalSiblings: number, parentX: number = 0, isPasta: boolean = false): void => {
        const cfg = isPasta ? spacingConfig.PASTA : spacingConfig.STRIDE;
        const baseWidth = cfg.baseWidth;

        let xGap: number = 0;
        if (level === 0) {
          xGap = 0;
        } else if (level === 1) {
          if (isPasta && node.id === 'super-root') {
            xGap = baseWidth * cfg.level1.xGapMultiplier * Math.max(1, totalSiblings * cfg.level1.siblingFactor);
          } else {
            xGap = baseWidth * cfg.level1.xGapMultiplier * Math.max(1, totalSiblings * cfg.level1.siblingFactor);
          }
        } else if (level === 2 && isPasta) {
          xGap = baseWidth * cfg.level2.xGapMultiplier * Math.max(1, totalSiblings * cfg.level2.siblingFactor);
        } else if (level === 3 && isPasta && cfg.level3) {
          xGap = baseWidth * cfg.level3.xGapMultiplier * Math.max(1, totalSiblings * cfg.level3.siblingFactor);
        } else {
          let xGapMultiplier = 1.2;
          let siblingFactor = 0.4;

          if (level === 2 && cfg.level2) {
            xGapMultiplier = cfg.level2.xGapMultiplier;
            siblingFactor = cfg.level2.siblingFactor;
          } else if (level === 1 && cfg.level1) {
            xGapMultiplier = cfg.level1.xGapMultiplier;
            siblingFactor = cfg.level1.siblingFactor;
          }

          xGap = baseWidth * xGapMultiplier * Math.max(1, totalSiblings * siblingFactor);
        }

        const yGap: number = cfg.verticalBase + (level * cfg.verticalIncrement);

        let x: number = 0;
        let y: number = level * yGap;

        if (level === 0) {
          x = 0;
        } else if (level === 1) {
          const totalWidth: number = xGap * (totalSiblings - 1);
          const startX: number = -totalWidth / 2;
          x = startX + (position * xGap);
        } else {
          const childOffset: number = ((totalSiblings - 1) * xGap) / 2;
          x = parentX - childOffset + (position * xGap);

          const offsetMultiplier: number = position - (totalSiblings - 1) / 2;

          if (isPasta && level === 3) {
            const groupingFactor = cfg.level3?.groupFactor || 0.2;
            x += offsetMultiplier * 20 * groupingFactor;
            y += (position % 2) * 15;
          } else if (isPasta && level > 3) {
            x += offsetMultiplier * 30;
          } else {
            x += offsetMultiplier * (isPasta ? 25 : 15);
          }
        }

        nodePositions[node.id] = { x, y };

        flowNodes.push({
          id: node.id,
          type: node.type || 'goal',
          position: { x, y },
          data: { label: node.label },
          style: {
            width: 'auto',
            minWidth: isPasta && (level === 3 || node.type === 'vulnerability') ? '220px' : '180px',
            maxWidth: '400px',
            padding: '10px',
            fontSize: '14px'
          }
        });

        if (node.children && node.children.length > 0) {
          node.children.forEach((childNode, idx) => {
            createNodes(childNode, level + 1, idx, node.children!.length, x, isPasta);
          });
        }
      };

      const goalNodes = treeNodes.filter(node => node.type === 'goal');

      let rootNode;
      if (goalNodes.length > 1) {
        rootNode = {
          id: 'super-root',
          type: 'goal' as const,
          label: 'Business Impact',
          children: goalNodes
        };
      } else {
        rootNode = goalNodes[0] || treeNodes[0];
      }

      const isPastaMethodology = goalNodes.length > 1;
      setIsPasta(isPastaMethodology);

      if (rootNode) {
        createNodes(rootNode, 0, 0, 1, 0, isPastaMethodology);

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

              createEdges(childNode);
            });
          }
        };

        createEdges(rootNode);

        if (flowNodes.length > 0 && flowEdges.length > 0) {
          setNodes(flowNodes);
          setEdges(flowEdges);
        } else {
          console.error("No nodes or edges to set");
        }
      }
    } catch (error) {
      console.error("Error processing attack tree data:", error);
      setError("Failed to process attack tree visualization. Please try again.");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-14 h-14">
            <div className="absolute inset-0 rounded-full border-2 border-slate-100 dark:border-gray-700"></div>
            <div className="absolute inset-0 rounded-full border-2 border-t-[#0052cc] animate-spin"></div>
          </div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Loading attack tree...</p>
        </div>
      </div>
    );
  }

  if (error || !attackTreeData) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-transparent flex items-center justify-center p-6">
        <div className="bg-white dark:bg-gray-900/80 border border-red-100 dark:border-red-900/40 rounded-2xl p-10 text-center max-w-md shadow-sm">
          <div className="w-14 h-14 rounded-2xl bg-red-50 dark:bg-red-900/20 border border-red-100 dark:border-red-800/40 flex items-center justify-center mx-auto mb-4">
            <svg className="h-7 w-7 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100 mb-2">Failed to Load Attack Tree</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">{error || 'Failed to load attack tree data.'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-transparent">
      <div className="max-w-screen-2xl mx-auto px-6 py-8">

        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
                  <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
                  </svg>
                </div>
                <h1 className="text-2xl font-bold text-slate-800 dark:text-slate-100">Attack Tree Analysis</h1>
              </div>
              {assessmentDetails ? (
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold bg-slate-100 dark:bg-gray-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-gray-700 uppercase tracking-wide">
                    {assessmentDetails.department}
                  </span>
                  <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{assessmentDetails.projectName}</span>
                  <span className="text-xs text-slate-400 dark:text-slate-500">&middot; {new Date(assessmentDetails.timestamp).toLocaleDateString()}</span>
                </div>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">{assessment_id}</p>
              )}
            </div>

            {/* Interactive mode button */}
            <button
              onClick={() => navigate(`/interactive-threat-model/${assessment_id}`)}
              className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-900/80 border border-slate-200 dark:border-gray-700/60 text-slate-600 dark:text-slate-300 text-sm font-medium rounded-lg hover:border-[#0052cc]/40 hover:text-[#0052cc] hover:bg-blue-50/50 dark:hover:bg-blue-950/30 transition-all duration-200 shadow-sm"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 10l-2 1m0 0l-2-1m2 1v2.5M20 7l-2 1m2-1l-2-1m2 1v2.5M14 4l-2-1-2 1M4 7l2-1M4 7l2 1M4 7v2.5M12 21l-2-1m2 1l2-1m-2 1v-2.5M6 18l-2-1v-2.5M18 18l2-1v-2.5" />
              </svg>
              Interactive Mode
            </button>
          </div>

          {/* Navigation strip */}
          <div className="mt-5">
            <NavigationButtons
              assessment_id={assessment_id!}
              currentPage="view-attack-tree"
              viewMode={true}
              hasAttackTree={!!attackTreeData}
              hasDread={!!dreadData}
              hasMitigation={!!mitigationData}
            />
          </div>
        </div>

        {/* Legend */}
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm mb-6 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Legend</h2>
          </div>
          <div className="px-6 py-4 flex flex-wrap gap-6">
            <div className="flex items-center gap-2">
              <div className="w-5 h-5 bg-red-100 border border-red-200 rounded flex-shrink-0"></div>
              <span className="text-sm text-slate-600 dark:text-slate-300">Attack Goal</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-5 h-5 bg-yellow-100 border border-yellow-200 rounded flex-shrink-0"></div>
              <span className="text-sm text-slate-600 dark:text-slate-300">Attack Method</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-5 h-5 bg-blue-100 border border-blue-200 rounded flex-shrink-0"></div>
              <span className="text-sm text-slate-600 dark:text-slate-300">Vulnerability</span>
            </div>
          </div>
        </div>

        {/* Attack Tree Visualization */}
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm mb-6 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
            <div className="flex items-center gap-3">
              <div className="w-7 h-7 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/40 flex items-center justify-center">
                <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
                </svg>
              </div>
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Attack Tree Visualization</h2>
            </div>
          </div>
          <div style={{ height: isPasta ? '800px' : '600px' }} className="border-0">
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
          </div>
        </div>

        {/* Understanding Attack Trees */}
        <div className="bg-white dark:bg-gray-900/80 rounded-xl border border-slate-200 dark:border-gray-700/60 shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-800">
            <div className="flex items-center gap-3">
              <div className="w-7 h-7 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/40 flex items-center justify-center">
                <svg className="h-4 w-4 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Understanding Attack Trees</h2>
            </div>
          </div>
          <div className="px-6 py-5">
            <p className="text-sm text-slate-600 dark:text-slate-300 mb-4 leading-relaxed">
              Attack trees are graphical representations of potential attacks on a system, showing how an attacker might exploit vulnerabilities to achieve their goals. The tree structure helps visualize:
            </p>
            <ul className="space-y-2 mb-4">
              {[
                { bold: 'Attack Goals', text: '– The ultimate objective an attacker wants to achieve' },
                { bold: 'Attack Methods', text: '– Different approaches or techniques that could be used' },
                { bold: 'Vulnerabilities', text: '– Specific weaknesses that could be exploited' },
              ].map((item, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-slate-600 dark:text-slate-300">
                  <span className="text-[#0052cc] mt-1 flex-shrink-0">
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                    </svg>
                  </span>
                  <span><strong className="text-slate-700 dark:text-slate-200">{item.bold}</strong> {item.text}</span>
                </li>
              ))}
            </ul>
            <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
              By understanding these attack paths, security teams can prioritize mitigation efforts and implement appropriate security controls to protect against the most critical threats.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
};

export default AttackTree;
