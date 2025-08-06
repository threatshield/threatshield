import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
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

import { AttackTreeResponse } from '../types/reportTypes';

interface AttackTreeNode {
  id: string;
  type: 'goal' | 'attack' | 'vulnerability';
  label: string;
  children?: AttackTreeNode[];
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
    projectName: string;
    timestamp: string;
    threatModelingMethodology?: string;
  } | null>(null);

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
                    projectName: details.projectName || 'Unknown Project',
                    timestamp: details.timestamp || new Date().toISOString(),
                    threatModelingMethodology: methodology
                  };
                } else {
                  details = {
                    projectName: 'Unknown Project',
                    timestamp: new Date().toISOString(),
                    threatModelingMethodology: methodology
                  };
                }
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
            result: {
              result: {
                markdown: data.result.result.markdown,
                attack_tree: {
                  nodes: data.result.result.attack_tree.nodes
                }
              }
            }
          };
          treeNodes = data.result.result.attack_tree?.nodes;
        } 
        // Case 2: Standard structure (result.attack_tree)
        else if (data?.result?.attack_tree?.nodes) {
          console.log('Found standard result structure');
          processedData = data;
          processedData = {
            timestamp: data.timestamp,
            result: {
              result: {
                markdown: data.result.markdown || '',
                attack_tree: {
                  nodes: data.result.attack_tree.nodes
                }
              }
            }
          };
          treeNodes = data.result.attack_tree?.nodes;
        }
        // Case 3: Nodes directly in result
        else if (data?.result?.nodes) {
          console.log('Found nodes directly in result');
          processedData = {
            timestamp: data.timestamp || new Date().toISOString(),
            result: {
              result: {
                markdown: data.result.markdown || '',
                attack_tree: {
                  nodes: data.result.nodes
                }
              }
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
          if (attackTreeResponse?.result?.result?.attack_tree?.nodes) {
            const processedResponse = {
              timestamp: attackTreeResponse.timestamp,
              result: {
                result: {
                  markdown: attackTreeResponse.result.result.markdown || '',
                  attack_tree: {
                    nodes: attackTreeResponse.result.result.attack_tree.nodes
                  }
                }
              }
            };
            setAttackTreeData(processedResponse);
            setContextAttackTreeData(processedResponse);
            processAttackTreeData(attackTreeResponse.result.result.attack_tree.nodes);
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
  }, [assessment_id, setContextAttackTreeData]);

  const processAttackTreeData = (treeNodes: AttackTreeNode[]) => {
    try {
      const flowNodes: Node<any>[] = [];
      const flowEdges: Edge<any>[] = [];
      
      // Create a map to store node positions
      const nodePositions: Record<string, { x: number, y: number }> = {};

      // Define spacing configuration
      const config = {
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
        // Dynamic spacing based on tree structure with increased gaps
        const baseWidth = config.baseWidth;
        
        // Calculate horizontal gap based on level and siblings with wider spacing
        let xGap: number = 0;
        if (level === 0) {
          xGap = 0;
        } else if (level === 1) {
          xGap = baseWidth * config.level1.xGapMultiplier * Math.max(1, totalSiblings * config.level1.siblingFactor);
        } else {
          xGap = baseWidth * config.level2.xGapMultiplier * Math.max(1, totalSiblings * config.level2.siblingFactor);
        }
        
        // Vertical spacing increases with depth
        const yGap: number = config.verticalBase + (level * config.verticalIncrement);
        
        // Calculate position with improved centering and wider distribution
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
          x += offsetMultiplier * config.horizontalOffset;
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
            minWidth: '180px',
            maxWidth: '400px',
            padding: '10px',
            fontSize: '14px'
          }
        });
        
        // Process children if any
        if (node.children && node.children.length > 0) {
          node.children.forEach((childNode, idx) => {
            createNodes(childNode, level + 1, idx, node.children!.length, x);
          });
        }
      };
      
      // Use the first node as root
      const rootNode = treeNodes[0];
      
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
        
        // Ensure nodes and edges are set correctly
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
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (error || !attackTreeData) {
    return (
      <div className="max-w-6xl mx-auto p-6">
        <div className="card p-8 text-center">
          <h2 className="text-xl font-semibold text-red-600 mb-4">Error Loading Attack Tree</h2>
          <p className="mb-4">{error || 'Failed to load attack tree data.'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="text-center mb-10">
        <h1 className="text-4xl font-bold text-[#0052cc] mb-2">Attack Tree Analysis</h1>
        <p className="text-xl text-gray-600 mb-2">Visual representation of attack paths and vulnerabilities</p>
        <p className="text-lg text-blue-600 mb-3">
          {assessmentDetails ? 
            `${assessmentDetails.projectName} - ${new Date(assessmentDetails.timestamp).toLocaleDateString()}` 
            : assessment_id}
        </p>
        
        <NavigationButtons
          assessment_id={assessment_id!}
          currentPage="view-attack-tree"
          viewMode={true}
          hasAttackTree={!!attackTreeData}
          hasDread={!!dreadData}
          hasMitigation={!!mitigationData}
        />
      </div>
      
      {/* Attack Tree Legend */}
      <div className="mb-10">
        <div className="flex items-center mb-4">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Legend</h2>
        </div>
        
        <div className="flex flex-wrap gap-4">
          <div className="flex items-center">
            <div className="w-6 h-6 bg-red-100 border border-red-200 rounded mr-2"></div>
            <span className="text-gray-700">Attack Goal</span>
          </div>
          <div className="flex items-center">
            <div className="w-6 h-6 bg-yellow-100 border border-yellow-200 rounded mr-2"></div>
            <span className="text-gray-700">Attack Method</span>
          </div>
          <div className="flex items-center">
            <div className="w-6 h-6 bg-blue-100 border border-blue-200 rounded mr-2"></div>
            <span className="text-gray-700">Vulnerability</span>
          </div>
        </div>
      </div>
      
      {/* Attack Tree Visualization */}
      <div className="card border border-blue-100 shadow-sm hover:shadow-md transition-shadow duration-200 mb-10">
        <div className="flex items-center mb-6 pb-4 border-b border-blue-100">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Attack Tree Visualization</h2>
        </div>
        
        <div style={{ height: '600px' }} className="border border-blue-100 rounded-lg">
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
      
      {/* Attack Tree Description */}
      <div>
          <div className="flex items-center mb-6">
          <div className="bg-blue-100 p-2 rounded-full mr-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-[#0052cc]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-[#172b4d]">Understanding Attack Trees</h2>
        </div>
        
        <div className="card border border-blue-100 shadow-sm hover:shadow-md transition-shadow duration-200">
          <p className="mb-4 text-[#172b4d]">
            Attack trees are graphical representations of potential attacks on a system, showing how an attacker might exploit vulnerabilities to achieve their goals. The tree structure helps visualize:
          </p>
          
          <ul className="list-disc pl-5 space-y-2 text-[#172b4d] mb-6">
            <li><strong>Attack Goals</strong> - The ultimate objective an attacker wants to achieve</li>
            <li><strong>Attack Methods</strong> - Different approaches or techniques that could be used</li>
            <li><strong>Vulnerabilities</strong> - Specific weaknesses that could be exploited</li>
          </ul>
          
          <p className="text-[#172b4d]">
            By understanding these attack paths, security teams can prioritize mitigation efforts and implement appropriate security controls to protect against the most critical threats.
          </p>
        </div>
      </div>
    </div>
  );
};

export default AttackTree;
