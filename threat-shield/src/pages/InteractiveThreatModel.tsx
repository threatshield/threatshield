import React, { useState, useEffect, useCallback, memo, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import ReactFlow, {
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  MarkerType,
  ReactFlowInstance,
  Handle,
  Position,
  NodeProps
} from 'reactflow';
import 'reactflow/dist/style.css';
import { apiService, API_BASE_URL } from '../services/api';
import { Threat, PastaThreat } from '../types/reportTypes';
import ASVSTestCases from '../components/common/ASVSTestCases';


const ThreatNode = memo(({ data }: NodeProps) => {
  return (
    <div 
      className="bg-white dark:bg-gray-800 border-2 border-gray-300 dark:border-gray-600 rounded-lg p-4 shadow-sm w-[250px] hover:shadow-lg hover:border-blue-300 dark:hover:border-blue-500 transition-all duration-200"
      style={{
        pointerEvents: 'auto',
        userSelect: 'text',
        WebkitFontSmoothing: 'antialiased',
        MozOsxFontSmoothing: 'grayscale',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px'
      }}
    >
      <Handle type="target" position={Position.Top} />
      <div 
        className="flex justify-between items-center"
        style={{
          pointerEvents: 'auto',
          userSelect: 'text',
          whiteSpace: 'normal',
          wordWrap: 'break-word',
          overflow: 'visible'
        }}
      >
        <span 
          className="font-medium text-gray-900 dark:text-slate-100"
          style={{
            pointerEvents: 'auto',
            userSelect: 'text',
            display: 'block',
            lineHeight: '1.4',
            whiteSpace: 'normal',
            wordBreak: 'break-word'
          }}
        >
          {data.threatType}
        </span>
        {data.dreadScore && (
          <span 
            className={`px-2 py-1 text-xs font-bold rounded-full flex-shrink-0 ${
              data.dreadScore >= 8 ? 'bg-red-50 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
              data.dreadScore >= 6 ? 'bg-yellow-50 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
              'bg-green-50 text-green-800 dark:bg-green-900/30 dark:text-green-300'
            }`}
            style={{
              pointerEvents: 'auto',
              userSelect: 'text'
            }}
          >
            {data.dreadScore.toFixed(1)}
          </span>
        )}
      </div>
      <div 
        className="text-sm text-gray-600 dark:text-slate-400"
        style={{
          pointerEvents: 'auto',
          userSelect: 'text',
          whiteSpace: 'normal',
          wordWrap: 'break-word',
          overflow: 'visible',
          lineHeight: '1.4',
          minHeight: '2.8em'
        }}
      >
        {data.scenario}
      </div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
});

ThreatNode.displayName = 'ThreatNode';


const ComponentNode = memo(({ data, selected }: NodeProps) => {
  return (
    <div
      className={`rounded-lg p-4 shadow-sm w-[200px] hover:shadow-lg transition-all duration-200 border-2 ${
        selected
          ? 'bg-blue-50 dark:bg-blue-900/50 border-[#0052cc] dark:border-blue-400 shadow-md'
          : 'bg-white dark:bg-gray-800 border-blue-200 dark:border-blue-700/60 hover:border-blue-300 dark:hover:border-blue-500'
      }`}
      style={{
        pointerEvents: 'auto',
        userSelect: 'text',
        WebkitFontSmoothing: 'antialiased',
        MozOsxFontSmoothing: 'grayscale',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px'
      }}
    >
      <Handle type="target" position={Position.Top} />
      <div 
        className="flex justify-between items-center"
        style={{
          pointerEvents: 'auto',
          userSelect: 'text',
          whiteSpace: 'normal',
          wordWrap: 'break-word',
          overflow: 'visible'
        }}
      >
        <span 
          className="font-medium text-gray-900 dark:text-slate-100"
          style={{
            pointerEvents: 'auto',
            userSelect: 'text',
            display: 'block',
            lineHeight: '1.4',
            whiteSpace: 'normal',
            wordBreak: 'break-word',
            flex: 1
          }}
        >
          {data.label}
        </span>
        {data.componentDreadScore !== undefined && (
          <span 
            className={`px-2 py-1 text-xs font-bold rounded-full flex-shrink-0 ${
              data.componentDreadScore >= 8 ? 'bg-red-50 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
              data.componentDreadScore >= 6 ? 'bg-yellow-50 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
              'bg-green-50 text-green-800 dark:bg-green-900/30 dark:text-green-300'
            }`}
            style={{
              pointerEvents: 'auto',
              userSelect: 'text'
            }}
          >
            {data.componentDreadScore.toFixed(1)}
          </span>
        )}
      </div>
      <div 
        className="flex flex-col items-center text-center"
        style={{
          pointerEvents: 'auto',
          userSelect: 'text'
        }}
      >
        <span 
          className="text-xs font-medium px-2 py-1 bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-300 rounded-full"
          style={{
            pointerEvents: 'auto',
            userSelect: 'text',
            whiteSpace: 'normal',
            wordWrap: 'break-word'
          }}
        >
          {data.type}
        </span>
      </div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
});

ComponentNode.displayName = 'ComponentNode';

const TRUST_BOUNDARY_COLORS = [
  { border: '#ef4444', bg: 'rgba(239, 68, 68, 0.04)' },
  { border: '#f59e0b', bg: 'rgba(245, 158, 11, 0.04)' },
  { border: '#3b82f6', bg: 'rgba(59, 130, 246, 0.04)' },
  { border: '#10b981', bg: 'rgba(16, 185, 129, 0.04)' },
  { border: '#8b5cf6', bg: 'rgba(139, 92, 246, 0.04)' },
];

const TrustBoundaryNode = memo(({ data }: NodeProps) => (
  <div style={{ width: '100%', height: '100%', border: `2px dashed ${data.color}`, borderRadius: '12px', backgroundColor: data.bgColor, pointerEvents: 'none', position: 'relative' }}>
    <div style={{ position: 'absolute', top: -14, left: 12, backgroundColor: data.color, color: 'white', fontSize: '11px', fontWeight: 600, padding: '2px 10px', borderRadius: '4px', whiteSpace: 'nowrap', pointerEvents: 'none' }}>
      {data.label}
    </div>
  </div>
));
TrustBoundaryNode.displayName = 'TrustBoundaryNode';

const nodeTypes = {
  threat: ThreatNode,
  component: ComponentNode,
  trustBoundary: TrustBoundaryNode,
};

interface ThreatModelResponse {
  timestamp: string;
  result: {
    raw_response: {
      threat_model: Threat[];
      improvement_suggestions: string[];
    };
    markdown: string;
  };
}

const CATEGORIES = [
  'Spoofing Identity',
  'Tampering with Data',
  'Repudiation of Actions',
  'Information Disclosure',
  'Denial of Service',
  'Elevation of Privilege'
] as const;

const InteractiveThreatModel: React.FC = () => {
  const [viewMode, setViewMode] = useState<string>('threats');
  const [activeCategory, setActiveCategory] = useState<string>('ALL');
  const [componentCategories] = useState<string[]>([
    "Client",
    "API Gateway",
    "Microservice",
    "Database",
    "Infrastructure",
    "External / Third-Party System"
  ]);
  const [selectedComponentCategory, setSelectedComponentCategory] = useState<string>('ALL');
  const [selectedComponent, setSelectedComponent] = useState<Node | null>(null);
  const { assessment_id } = useParams<{ assessment_id?: string }>();
  const navigate = useNavigate();
  const [assessmentDetails, setAssessmentDetails] = useState<{
    department: string;
    projectName: string;
    timestamp: string;
  } | null>(null);

  const [reactFlowInstance, setReactFlowInstance] = useState<ReactFlowInstance | null>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [architectureReactFlowInstance, setArchitectureReactFlowInstance] = useState<ReactFlowInstance | null>(null);
  const [architectureNodes, setArchitectureNodes, onArchitectureNodesChange] = useNodesState([]);
  const [architectureEdges, setArchitectureEdges, onArchitectureEdgesChange] = useEdgesState([]);
  const [threatModel, setThreatModel] = useState<ThreatModelResponse | null>(null);
  const [dreadData, setDreadData] = useState<any>(null);
  interface MitigationEntry {
    'Threat Type': string;
    'Scenario': string;
    'Suggested Mitigation(s)': string;
  }
  const [mitigationData, setMitigationData] = useState<Record<string, MitigationEntry>>({}); 
  const [asvsTestCasesData, setAsvsTestCasesData] = useState<any>(null);
  const [securityTestCasesData, setSecurityTestCasesData] = useState<any>(null);
  const [methodology, setMethodology] = useState<string>('STRIDE');
  const [dynamicCategories, setDynamicCategories] = useState<string[]>([]);
  const [isDiagramGenerating, setIsDiagramGenerating] = useState<boolean>(false);
  const [isDiagramMissing, setIsDiagramMissing] = useState<boolean>(false);
  const [showTrustBoundaries, setShowTrustBoundaries] = useState<boolean>(false);
  const [trustBoundaries, setTrustBoundaries] = useState<{ name: string; components: string[] }[]>([]);

  // Load threat model from storage
  // Load architecture diagram
  useEffect(() => {
    const loadArchitectureDiagram = async () => {
      if (!assessment_id || !threatModel?.result?.raw_response?.threat_model) return;
      
      // Log threat model data for debugging
      console.log('Threat model data:', threatModel.result.raw_response.threat_model);
      
      try {
        const data = await apiService.getAdditionalInfo(assessment_id);
        const diagramData = data?.result?.data_flow_diagrams;
        
        // Check if diagram data exists and has reactflow values
        if (!diagramData || !diagramData.reactflow) {
          console.warn('Diagram data is missing or reactflow key is empty');
          setIsDiagramMissing(true);
          return;
        }
        
        // Verify reactflow has actual values
        let reactflowData = diagramData.reactflow;
        if (typeof reactflowData === 'string' && reactflowData.trim() === '') {
          console.warn('Reactflow data is an empty string');
          setIsDiagramMissing(true);
          return;
        }
        
        setIsDiagramMissing(false);
        
        try {
          // Parse components list - handle both array and string formats
          const components = Array.isArray(diagramData.components) 
            ? diagramData.components 
            : typeof diagramData.components === 'string' 
              ? diagramData.components.replace(/[\[\]']/g, '').split(', ')
              : [];

          // Parse reactflow data - handle both object and string formats
          try {
            var parsedData = typeof diagramData.reactflow === 'string' 
              ? JSON.parse(diagramData.reactflow) 
              : diagramData.reactflow;
          } catch (parseError) {
            console.error('Error parsing reactflow data:', parseError);
            setIsDiagramMissing(true);
            return;
          }
          
          // Verify parsed data has nodes
          if (!parsedData || !parsedData.nodes || parsedData.nodes.length === 0) {
            console.warn('Reactflow data has no nodes');
            setIsDiagramMissing(true);
            return;
          }
          
          // Create components array with types from reactflow data
          const mappedComponents = components.map((name: string) => {
            const node = parsedData.nodes.find((n: any) => n.data.label === name);
            return {
              name,
              type: node?.type || 'Client' // Default to Client if type not found
            };
          });
          
      

          // Get mapping data if available
          const mappingData = diagramData.mapping || {};
          
          // Log mapping data for debugging
          console.log('Mapping data:', mappingData);
          console.log('Threat model:', threatModel?.result?.raw_response?.threat_model);

          // Transform nodes to add component type and additional data
          const transformedNodes = parsedData.nodes.map((node: any, index: number) => {
            // Find threats related to this component from mapping
            const relatedThreats = threatModel?.result?.raw_response?.threat_model
              .filter((threat: any) => {
                // Debug logging for threat matching
                console.log('Attempting to match threat:', {
                  scenario: threat.Scenario,
                  componentLabel: node.data.label
                });

                // Define the mapping entry type
                interface MappingEntry {
                  components: string[];
                }

                // Find matching mapping entry using flexible comparison
                const mappingEntry = Object.entries(mappingData)
                  .find(([key, _]) => {
                    const normalizedKey = key.replace(/^Scenario:\s*/, '').trim();
                    const normalizedScenario = threat.Scenario.trim();
                    const isMatch = normalizedKey === normalizedScenario;
                    
                    console.log('Comparing:', {
                      normalizedKey,
                      normalizedScenario,
                      isMatch
                    });
                    
                    return isMatch;
                  });

                if (!mappingEntry) {
                  console.log('No mapping entry found for threat:', threat.Scenario);
                  return false;
                }

                const [_, components] = mappingEntry;
                console.log('Found mapping entry:', components);

                if (!Array.isArray(components)) {
                  console.log('Components is not an array:', components);
                  return false;
                }

                // Check if this component is in the threat's mapped components
                const isComponentMapped = components.includes(node.data.label);
                console.log('Component mapped:', isComponentMapped);
                
                return isComponentMapped;
              })
              .map((threat: any) => threat.Scenario);

            console.log('Related threats for component', node.data.label, ':', relatedThreats);

            // Sort threats by severity if DREAD score is available
            const sortedThreats = [...relatedThreats].sort((a, b) => {
              const threatA = threatModel?.result?.raw_response?.threat_model?.find(
                (t: any) => t['Scenario'] === a
              );
              const threatB = threatModel?.result?.raw_response?.threat_model?.find(
                (t: any) => t['Scenario'] === b
              );
              
              const dreadScoreA = dreadData?.find((d: any) => 
                d['Threat Type'] === threatA?.['Threat Type'] && 
                d['Scenario'] === threatA?.['Scenario']
              );
              const dreadScoreB = dreadData?.find((d: any) => 
                d['Threat Type'] === threatB?.['Threat Type'] && 
                d['Scenario'] === threatB?.['Scenario']
              );
              
              if (dreadScoreA && dreadScoreB) {
                const scoreA = ([
                  dreadScoreA['Damage Potential'],
                  dreadScoreA['Reproducibility'],
                  dreadScoreA['Exploitability'],
                  dreadScoreA['Affected Users'],
                  dreadScoreA['Discoverability']
                ].reduce((a, b) => a + b, 0) / 5);
                
                const scoreB = ([
                  dreadScoreB['Damage Potential'],
                  dreadScoreB['Reproducibility'],
                  dreadScoreB['Exploitability'],
                  dreadScoreB['Affected Users'],
                  dreadScoreB['Discoverability']
                ].reduce((a, b) => a + b, 0) / 5);
                
                return scoreB - scoreA; // Sort by highest DREAD score first
              }
              return 0;
            });

            // Calculate component DREAD score
            const componentDreadScores = sortedThreats
              .map((threatScenario: string) => {
                const threatEntry = threatModel?.result?.raw_response?.threat_model?.find(
                  (threat) => threat['Scenario'] === threatScenario
                );
                if (!threatEntry) return null;

                const dreadInfo = dreadData?.find((d: any) => {
                  const normalizeString = (str: string) => str.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
                  return normalizeString(d['Threat Type']) === normalizeString(threatEntry['Threat Type']) && 
                         normalizeString(d['Scenario']) === normalizeString(threatEntry['Scenario']);
                });

                return dreadInfo ? 
                  (([
                    dreadInfo['Damage Potential'],
                    dreadInfo['Reproducibility'],
                    dreadInfo['Exploitability'],
                    dreadInfo['Affected Users'],
                    dreadInfo['Discoverability']
                  ].reduce((a, b) => a + b, 0) / 5)) : null;
              })
              .filter((score: number | null): score is number => score !== null);

            const componentDreadScore = componentDreadScores.length > 0 
              ? componentDreadScores.reduce((a: number, b: number) => a + b, 0) / componentDreadScores.length 
              : undefined;

            return {
              ...node,
              type: 'component',
              position: { x: 250 + index * 400, y: 150 + (index % 3) * 250 }, // Further increased spacing and 3 rows
              draggable: true, // Enable dragging
              data: {
                ...node.data,
                type: node.type || 'Client', // Use node.type from API response or default to 'Client'
                description: `This is the ${node.data.label} component`,
                dataFlows: [],
                securityControls: ['Input Validation', 'Access Control', 'Data Encryption'],
                relatedThreats: sortedThreats, // Use sorted threats ordered by DREAD score
                componentDreadScore: componentDreadScore
              },
              style: {
                width: 200,
                height: 'auto',
                minHeight: 100,
                padding: 0,
                border: 'none',
                borderRadius: 0,
                background: 'transparent'
              },
              className: 'relative'
            };
          });

          // Transform edges to add styling
          const transformedEdges = parsedData.edges.map((edge: any) => ({
            ...edge,
            animated: true,
            style: { stroke: '#94a3b8', strokeWidth: 2 },
            markerEnd: { type: MarkerType.Arrow, color: '#94a3b8' }
          }));

          console.log('Parsed DFD nodes:', transformedNodes);
          console.log('Parsed DFD edges:', transformedEdges);

          setArchitectureNodes(transformedNodes);
          setArchitectureEdges(transformedEdges);
          setTrustBoundaries(diagramData.trust_boundaries || []);
          
          // Force a re-render by triggering a state update
          setTimeout(() => {
            setArchitectureNodes(prev => [...prev]);
          }, 100);
        } catch (error) {
          console.error('Error parsing diagram data:', error);
        }
      } catch (error) {
        console.error('Error loading architecture diagram:', error);
        setIsDiagramMissing(true);
      }
    };

    loadArchitectureDiagram();
  }, [assessment_id, threatModel, dreadData, setArchitectureNodes, setArchitectureEdges]);

  // Handle regenerate diagrams
  const handleRegenerateDiagrams = async () => {
    if (!assessment_id) return;
    
    try {
      setIsDiagramGenerating(true);
      console.log('Regenerating diagrams for assessment:', assessment_id);
      
      // Call the generate diagrams API
      const result = await apiService.generateDiagrams(assessment_id);
      
      console.log('Diagrams regenerated successfully:', result);
      
      // Reload the architecture diagram
      const data = await apiService.getAdditionalInfo(assessment_id);
      if (data?.result?.data_flow_diagrams?.reactflow) {
        setIsDiagramMissing(false);
        
        // Trigger a re-load of the diagram by updating the threat model state
        if (threatModel) {
          setThreatModel({...threatModel});
        }
      } else {
        setIsDiagramMissing(true);
      }
    } catch (error) {
      console.error('Error regenerating diagrams:', error);
      alert('Failed to regenerate diagrams. Please try again.');
    } finally {
      setIsDiagramGenerating(false);
    }
  };

  useEffect(() => {
    const loadThreatModel = async () => {
      if (!assessment_id) return;
      try {
        // Fetch all data in parallel
        const [threatResponse, dreadResponse, mitigationsResponse, asvsResponse] = await Promise.all([
          fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=threat_model`),
          fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=dread_assessment`),
          fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=mitigation`),
          fetch(`${API_BASE_URL}/storage?assessment_id=${assessment_id}&assessment_name=test_cases`)
        ]);

        const response = threatResponse;
        if (!response.ok) {
          throw new Error('Failed to fetch threat model');
        }
        
        const data = await response.json();
        if (!data?.result?.result?.raw_response?.threat_model) {
          throw new Error('Invalid threat model data format');
        }
        
        // Transform the nested structure to match the expected format
        const transformedData: ThreatModelResponse = {
          timestamp: data.timestamp,
          result: data.result.result
        };
        
        // Process all data
        const [dreadJson, mitigationsJson, asvsJson] = await Promise.all([
          dreadResponse.ok ? dreadResponse.json() : null,
          mitigationsResponse.ok ? mitigationsResponse.json() : null,
          asvsResponse.ok ? asvsResponse.json() : null
        ]);

        // Fetch security test cases separately
        let securityTestCases = null;
        try {
          const securityResponse = await apiService.getSecurityTestCases(assessment_id);
          securityTestCases = securityResponse?.result?.test_cases || [];
          console.log('Security test cases loaded:', securityTestCases);
        } catch (error) {
          console.error('Error loading security test cases:', error);
        }

        console.log('Raw responses:', { 
          dread: dreadJson?.result?.result?.raw_response?.['Risk Assessment'],
          mitigations: mitigationsJson?.result?.result?.raw_response?.mitigations
        });

        // Extract data
        const riskAssessment = dreadJson?.result?.result?.raw_response?.['Risk Assessment'] || [];
        const mitigations = mitigationsJson?.result?.result?.raw_response?.mitigations || [];
        const asvsTestCases = asvsJson?.result?.test_cases || [];
        
        console.log('Risk Assessment:', riskAssessment);
        console.log('Raw mitigations:', mitigations);
        
        // Transform mitigations into a map for easier lookup
        const mitigationsMap = mitigations.reduce((acc: Record<string, MitigationEntry>, m: MitigationEntry) => {
          // Create a normalized key by removing whitespace and special characters
          const key = `${m['Threat Type']}_${m['Scenario']}`.replace(/[\s\W]+/g, '_').toLowerCase();
          if (!acc[key]) {
            acc[key] = m;
            console.log('Added mitigation for:', key);
          }
          return acc;
        }, {});
        
        console.log('Mitigations map:', mitigationsMap);
        
        // Log test cases for debugging
        console.log('Raw ASVS test cases:', asvsTestCases);

        // Get methodology first
        const details = await apiService.getDetails(assessment_id!);
        const currentMethodology = details.threatModelingMethodology;
        setMethodology(currentMethodology);

        // Set all data at once
        setDreadData(riskAssessment);
        setMitigationData(mitigationsMap);
        setAsvsTestCasesData(asvsTestCases);
        setSecurityTestCasesData(securityTestCases);
        setThreatModel(transformedData);

        // Process threat model as nodes
        const threats: Threat[] = transformedData.result.raw_response.threat_model || [];

        // Get categories based on methodology
        let categories: string[];
        if (currentMethodology === 'STRIDE') {
          categories = [...CATEGORIES];
        } else {
          // For PASTA, get unique Business Risk Types
          categories = Array.from(new Set(
            threats.flatMap(t => {
              const pastaThreat = t as PastaThreat;
              return Array.isArray(pastaThreat['Business Risk Type'])
                ? pastaThreat['Business Risk Type']
                : [pastaThreat['Business Risk Type']];
            })
          ));
        }
        
        // Convert threat model to nodes and edges
        const flowNodes: Node[] = [];
        const flowEdges: Edge[] = [];
        
        // Log sample data for debugging
        if (asvsTestCases.length > 0 && threats.length > 0) {
          console.log('Sample threat scenario:', threats[0]?.['Scenario']);
          console.log('Sample test case scenario:', asvsTestCases[0]?.['Scenario']);
        }
        const SPACING_X = 350;
        const SPACING_Y = 200;
        const CATEGORY_GAP_Y = 150;
        
        // Group threats by category based on methodology
        const threatsByCategory = new Map<string, Threat[]>();
        
        if (currentMethodology === 'STRIDE') {
          // For STRIDE, group by Threat Type
          CATEGORIES.forEach(category => {
            threatsByCategory.set(
              category,
              threats.filter(t => t['Threat Type'].startsWith(category.charAt(0)))
            );
          });
        } else {
          // For PASTA, group by Business Risk Type
          const businessRiskCategories = Array.from(new Set(
            threats.flatMap(t => {
              const pastaThreat = t as PastaThreat;
              return Array.isArray(pastaThreat['Business Risk Type'])
                ? pastaThreat['Business Risk Type']
                : [pastaThreat['Business Risk Type']];
            })
          ));
          
          businessRiskCategories.forEach(category => {
            threatsByCategory.set(
              category,
              threats.filter(t => {
                const pastaThreat = t as PastaThreat;
                const riskTypes = Array.isArray(pastaThreat['Business Risk Type'])
                  ? pastaThreat['Business Risk Type']
                  : [pastaThreat['Business Risk Type']];
                return riskTypes.includes(category);
              })
            );
          });
        }

        // Create nodes for each category
        let currentY = 50;
        
        categories.forEach((category) => {
          const categoryThreats = threatsByCategory.get(category) || [];
          if (categoryThreats.length === 0) return;

          categoryThreats.forEach((threat, index) => {
            const x = 100 + (index * SPACING_X);
            const node: Node = {
            id: `threat-${threat['Threat Type']}-${threats.indexOf(threat)}`,
            type: 'threat',
            position: { 
              x,
              y: currentY
            },
            data: { 
              label: `${threat['Threat Type']}\n${threat['Scenario'].substring(0, 50)}${threat['Scenario'].length > 50 ? '...' : ''}`,
              threatType: threat['Threat Type'],
              scenario: threat['Scenario'].substring(0, 50) + (threat['Scenario'].length > 50 ? '...' : ''),
              description: threat['Scenario'], // Full scenario text
              fullScenario: threat['Scenario'], // Store the complete scenario text
              impact: threat['Potential Impact'],
              confidence: (threat['Confidence'] as string) || 'Medium',
              businessRiskType: (threat as PastaThreat)['Business Risk Type'],
              pastaStage: (threat as PastaThreat)['PASTA Stage'],
              dreadScore: (() => {
                const dreadInfo = dreadData?.find((d: any) => {
                  // Normalize strings for comparison by removing whitespace and special characters
                  const normalizeString = (str: string) => str.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
                  return normalizeString(d['Threat Type']) === normalizeString(threat['Threat Type']) && 
                         normalizeString(d['Scenario']) === normalizeString(threat['Scenario']);
                });
                if (dreadInfo) {
                  const scores = [
                    dreadInfo['Damage Potential'],
                    dreadInfo['Reproducibility'],
                    dreadInfo['Exploitability'],
                    dreadInfo['Affected Users'],
                    dreadInfo['Discoverability']
                  ];
                  const average = scores.reduce((a, b) => a + b, 0) / scores.length;
                  console.log('DREAD scores for:', threat['Threat Type'], scores, 'Average:', average);
                  return average;
                }
                return null;
              })(),
              mitigations: (() => {
                // Find mitigation by matching threat type and scenario
                const mitigation = Object.values(mitigationData || {}).find((m: MitigationEntry) => {
                  // Normalize strings for comparison
                  const normalizeString = (str: string) => str.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
                  return normalizeString(m['Threat Type']) === normalizeString(threat['Threat Type']) &&
                         normalizeString(m['Scenario']) === normalizeString(threat['Scenario']);
                });

                if (mitigation) {
                  console.log('Found mitigation for:', threat['Scenario'], mitigation);
                  const mitigations = mitigation['Suggested Mitigation(s)']?.split(/[.;]/)
                    .map((m: string) => m.trim())
                    .filter((m: string) => m && m.length > 0)
                    .map((m: string) => m.replace(/^\s*[-•]\s*/, '').replace(/^\d+\.\s*/, '')) || [];
                  console.log('Processed mitigations:', mitigations);
                  return mitigations;
                }
                return [];
              })()
            },
            style: {
              width: 250,
              height: 'auto',
              minHeight: 100,
              padding: 0,
              border: 'none',
              borderRadius: 0,
              background: 'transparent'
            },
            className: 'relative'
          };
            flowNodes.push(node);
          });
          currentY += SPACING_Y + CATEGORY_GAP_Y;
        });

        // Create edges between threats in the same category
        // Create edges between threats in the same category
        Array.from(threatsByCategory.keys()).forEach(category => {
          const categoryThreats = threatsByCategory.get(category) || [];
          categoryThreats.forEach((_, i: number) => {
            if (i === 0) return;
              flowEdges.push({
                id: `edge-${category}-${i}`,
                source: `threat-${categoryThreats[i-1]['Threat Type']}-${threats.indexOf(categoryThreats[i-1])}`,
                target: `threat-${categoryThreats[i]['Threat Type']}-${threats.indexOf(categoryThreats[i])}`,
                animated: true,
                style: { 
                  stroke: '#94a3b8',
                  strokeWidth: 2,
                  strokeDasharray: 'none'
                },
                markerEnd: {
                  type: MarkerType.Arrow,
                  color: '#94a3b8'
                }
              });
          });
        });

        setNodes(flowNodes);
        setEdges(flowEdges);
      } catch (error) {
        console.error('Error loading threat model:', error);
      }
    };

    if (assessment_id) {
      loadThreatModel();
    }
  }, [assessment_id, setNodes, setEdges]);

  // Update nodes when data changes
  useEffect(() => {
    if (!threatModel || !dreadData || !mitigationData || !asvsTestCasesData) return;

    const threats: Threat[] = threatModel.result.raw_response.threat_model || [];
    const flowNodes = nodes.map(node => {
      const threat = threats.find(t => 
        node.id === `threat-${t['Threat Type']}-${threats.indexOf(t)}`
      );
      if (!threat) return node;

      const dreadInfo = dreadData?.find((d: any) => 
        d['Threat Type'] === threat['Threat Type'] && 
        d['Scenario'] === threat['Scenario']
      );

      const key = `${threat['Threat Type']}_${threat['Scenario']}`.replace(/[\s\W]+/g, '_').toLowerCase();
      const mitigation = mitigationData[key];

      const testCase = asvsTestCasesData.find((tc: any) => 
        tc['Threat Type'] === threat['Threat Type'] &&
        tc['Scenario'].trim() === threat['Scenario'].trim()
      );

      return {
        ...node,
        data: {
          ...node.data,
          dreadScore: dreadInfo ? 
            (([
              dreadInfo['Damage Potential'],
              dreadInfo['Reproducibility'],
              dreadInfo['Exploitability'],
              dreadInfo['Affected Users'],
              dreadInfo['Discoverability']
            ].reduce((a, b) => a + b, 0) / 5)) : null,
          mitigations: mitigation ? 
            (mitigation['Suggested Mitigation(s)']?.split(/[.;]/)
              .map((m: string) => m.trim())
              .filter((m: string) => m && m.length > 0 && !m.match(/^\s*$/))
              .map((m: string) => m.replace(/^\s*[-•]\s*/, '').replace(/^\d+\.\s*/, '')) || []) : [],
          asvsTestCases: testCase ? {
            asvs_requirement: testCase.asvs_requirement,
            test_cases: testCase.test_cases
          } : null
        }
      };
    });

    setNodes(flowNodes);
  }, [threatModel, dreadData, mitigationData, asvsTestCasesData]);

  // Fetch assessment details
  useEffect(() => {
    const fetchAssessmentDetails = async () => {
      if (assessment_id) {
        try {
          const response = await apiService.getStorageHistory();
          if (response && response.data) {
            const report = response.data.find(r => r.id === assessment_id);
            if (report && report.details) {
              setAssessmentDetails(report.details);
            }
          }
        } catch (error) {
          console.error('Error fetching assessment details:', error);
        }
      }
    };
    
    fetchAssessmentDetails();
  }, [assessment_id]);

  // Fetch threatModelingMethodology from details.json
  useEffect(() => {
    if (assessment_id) {
      apiService.getDetails(assessment_id)
        .then(details => setMethodology(details.threatModelingMethodology))
        .catch(err => console.error('Error fetching details:', err));
    }
  }, [assessment_id]);

  // Compute categories for PASTA if needed
  useEffect(() => {
    if (methodology !== 'STRIDE' && threatModel) {
      const cats = Array.from(new Set(
        threatModel.result.raw_response.threat_model.flatMap((t) => {
          const pastaThreat = t as PastaThreat;
          return Array.isArray(pastaThreat['Business Risk Type'])
            ? pastaThreat['Business Risk Type']
            : [pastaThreat['Business Risk Type']];
        })
      ));
      setDynamicCategories(cats);
    }
  }, [methodology, threatModel]);

  const architectureDisplayNodes = useMemo(() => {
    if (!showTrustBoundaries || trustBoundaries.length === 0 || architectureNodes.length === 0) return architectureNodes;
    const PADDING = 40, NODE_WIDTH = 200, NODE_HEIGHT = 130;
    const tbNodes = trustBoundaries.map((boundary, idx) => {
      const matched = architectureNodes.filter(n => boundary.components.includes(n.data.label));
      if (matched.length === 0) return null;
      const minX = Math.min(...matched.map(n => n.position.x)) - PADDING;
      const minY = Math.min(...matched.map(n => n.position.y)) - PADDING;
      const maxX = Math.max(...matched.map(n => n.position.x + NODE_WIDTH)) + PADDING;
      const maxY = Math.max(...matched.map(n => n.position.y + NODE_HEIGHT)) + PADDING;
      const colors = TRUST_BOUNDARY_COLORS[idx % TRUST_BOUNDARY_COLORS.length];
      return {
        id: `trust-boundary-${idx}`,
        type: 'trustBoundary',
        position: { x: minX, y: minY },
        data: { label: boundary.name, color: colors.border, bgColor: colors.bg },
        style: { width: maxX - minX, height: maxY - minY, pointerEvents: 'none' },
        selectable: false,
        draggable: false,
        zIndex: -1,
      } as Node;
    }).filter(Boolean) as Node[];
    return [...tbNodes, ...architectureNodes];
  }, [showTrustBoundaries, trustBoundaries, architectureNodes]);

  // Shared function for zooming to a node
  const zoomToNode = useCallback((node: Node) => {
    if (!reactFlowInstance) return;
    const zoomLevel = 1.5;
    const rfNode = reactFlowInstance.getNode(node.id);
    if (!rfNode || !rfNode.positionAbsolute) return;
    const { x, y } = rfNode.positionAbsolute;
    const width = rfNode.width ?? 250;
    const height = rfNode.height ?? 100;
    const centerX = x + width / 2;
    const centerY = y + height / 2;
    reactFlowInstance.setCenter(centerX, centerY, { zoom: zoomLevel, duration: 800 });
  }, [reactFlowInstance]);

  // Update node styles and selection
  const updateNodeSelection = useCallback((node: Node) => {
    setSelectedNode(node);
    
    const updatedNodes = nodes.map(n => ({
      ...n,
      style: {
        ...n.style,
        background: n.id === node.id ? 'rgb(239 246 255)' : '#ffffff',
        borderColor: n.id === node.id ? 'rgb(191 219 254)' : '#e2e8f0',
        borderWidth: n.id === node.id ? '2px' : '1px'
      }
    }));
    setNodes(updatedNodes);
    
    /* zoom moved to effect */
  }, [nodes, setNodes, zoomToNode]);

  const onNodeClick = useCallback((event: React.MouseEvent, node: Node) => {
    updateNodeSelection(node);
  }, [updateNodeSelection]);

  const [selectedNode, setSelectedNode] = useState<Node | null>(null);

  // auto-zoom when a node is selected (including from category list)
  useEffect(() => {
    if (selectedNode && reactFlowInstance) {
      zoomToNode(selectedNode);
    }
  }, [selectedNode, reactFlowInstance, zoomToNode]);

  // Initialize chat when component is selected (Architecture view)
  useEffect(() => {
    if (selectedComponent) {
      initializeComponentChat(selectedComponent.data.label);
    }
  }, [selectedComponent]);

  // Initialize chat when threat is selected (Threats view)
  useEffect(() => {
    if (selectedNode) {
      const threatId = `${selectedNode.data.threatType}_${selectedNode.data.fullScenario}`;
      initializeThreatChat(threatId);
    }
  }, [selectedNode]);
  const [activeTab, setActiveTab] = useState<string>('Threats');
  interface ChatMessage {
    type: 'user' | 'bot';
    text: string;
  }
  
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    { 
      type: 'bot', 
      text: 'Hi! I can help you understand more about this threat. You can ask about its impact, potential mitigations, or any security concerns.' 
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatLoading, setIsChatLoading] = useState(false);
  const [selectedTestCase, setSelectedTestCase] = useState<any | null>(null);
  
  // Store chat histories for different nodes/components
  const [componentChatHistories, setComponentChatHistories] = useState<Record<string, ChatMessage[]>>({});
  const [threatChatHistories, setThreatChatHistories] = useState<Record<string, ChatMessage[]>>({});

  // Initialize chat for a component
  const initializeComponentChat = (componentId: string) => {
    if (!componentChatHistories[componentId]) {
      setComponentChatHistories(prev => ({
        ...prev,
        [componentId]: [
          { 
            type: 'bot', 
            text: `Hi! I can help you understand more about the "${componentId}" component and its security threats. You can ask about threats, mitigations, DREAD scores, or any security concerns.` 
          }
        ]
      }));
    }
    setChatMessages(componentChatHistories[componentId] || [
      { 
        type: 'bot', 
        text: `Hi! I can help you understand more about the "${componentId}" component and its security threats. You can ask about threats, mitigations, DREAD scores, or any security concerns.` 
      }
    ]);
  };

  // Initialize chat for a threat
  const initializeThreatChat = (threatId: string) => {
    if (!threatChatHistories[threatId]) {
      setThreatChatHistories(prev => ({
        ...prev,
        [threatId]: [
          { 
            type: 'bot', 
            text: 'Hi! I can help you understand more about this threat. You can ask about its impact, potential mitigations, DREAD score, or any security concerns.' 
          }
        ]
      }));
    }
    setChatMessages(threatChatHistories[threatId] || [
      { 
        type: 'bot', 
        text: 'Hi! I can help you understand more about this threat. You can ask about its impact, potential mitigations, DREAD score, or any security concerns.' 
      }
    ]);
  };

  const handleValidationChange = async (testCase: any) => {
    try {
      const newValidatedStatus = !testCase.validated;
      console.log('[VALIDATION] Updating test case:', {
        scenario: testCase['Scenario'],
        threatType: testCase['Threat Type'],
        currentValidated: testCase.validated,
        newValidated: newValidatedStatus
      });
      
      await apiService.updateTestCaseValidation(assessment_id!, testCase['Scenario'], newValidatedStatus);
      
      // Update both ASVS and security test cases data - update the top-level validated field
      setAsvsTestCasesData((prevData: any[]) => 
        prevData?.map((tc: any) => {
          if (tc['Scenario'] === testCase['Scenario'] && tc['Threat Type'] === testCase['Threat Type']) {
            console.log('[VALIDATION] Updating ASVS test case to validated:', newValidatedStatus);
            return {
              ...tc,
              validated: newValidatedStatus
            };
          }
          return tc;
        }) || []
      );

      setSecurityTestCasesData((prevData: any[]) => 
        prevData?.map((tc: any) => {
          if (tc['Scenario'] === testCase['Scenario'] && tc['Threat Type'] === testCase['Threat Type']) {
            console.log('[VALIDATION] Updating security test case to validated:', newValidatedStatus);
            return {
              ...tc,
              validated: newValidatedStatus
            };
          }
          return tc;
        }) || []
      );
    } catch (error) {
      console.error('Failed to update test case validation:', error);
    }
  };

  const handleChatSubmit = async () => {
    if (!chatInput.trim() || !selectedComponent) return;

    const userMessage = chatInput.trim();
    
    // Build comprehensive context for all threats of the component
    const componentThreats = selectedComponent.data.relatedThreats || [];
    const normalize = (s: string) => (s || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
    
    const threatDetails = componentThreats.map((threatScenario: string) => {
      const threatEntry = threatModel?.result?.raw_response?.threat_model?.find(
        (threat) => threat['Scenario'] === threatScenario
      );
      
      if (!threatEntry) return null;

      // Find DREAD score
      const dreadInfo = dreadData?.find((d: any) => {
        return normalize(d['Threat Type']) === normalize(threatEntry['Threat Type']) && 
               normalize(d['Scenario']) === normalize(threatEntry['Scenario']);
      });

      const dreadScore = dreadInfo ? 
        (([
          dreadInfo['Damage Potential'],
          dreadInfo['Reproducibility'],
          dreadInfo['Exploitability'],
          dreadInfo['Affected Users'],
          dreadInfo['Discoverability']
        ].reduce((a, b) => a + b, 0) / 5)) : null;

      // Find mitigation
      const key = `${threatEntry['Threat Type']}_${threatEntry['Scenario']}`.replace(/[\s\W]+/g, '_').toLowerCase();
      const mitigation = mitigationData?.[key];

      // Find ASVS test case
      const asvsTc = asvsTestCasesData?.find((t: any) =>
        normalize(t['Scenario']) === normalize(threatEntry['Scenario']) &&
        normalize(t['Threat Type']) === normalize(threatEntry['Threat Type'])
      );

      // Find security test case
      const securityTc = securityTestCasesData?.find((t: any) =>
        normalize(t['Scenario']) === normalize(threatEntry['Scenario']) &&
        normalize(t['Threat Type']) === normalize(threatEntry['Threat Type'])
      );

      return {
        threatType: threatEntry['Threat Type'],
        scenario: threatEntry['Scenario'],
        impact: threatEntry['Potential Impact'],
        dreadScore: dreadScore,
        mitigation: mitigation?.['Suggested Mitigation(s)'] || 'No mitigation available',
        asvsRequirement: asvsTc?.asvs_requirement || securityTc?.asvs_requirement || 'No ASVS requirement available',
        testDescription: asvsTc?.test_cases?.[0]?.test_description || securityTc?.test_cases?.[0]?.test_description || 'No test case available'
      };
    }).filter(Boolean);

    const threatContext = `Component: "${selectedComponent.data.label}" (${selectedComponent.data.type})

Threats Analysis:
${threatDetails.map((threat: any, index: number) => `
${index + 1}. ${threat.threatType}
   Scenario: ${threat.scenario}
   Impact: ${threat.impact}
   DREAD Score: ${threat.dreadScore ? threat.dreadScore.toFixed(1) : 'N/A'}
   Mitigation: ${threat.mitigation}
   ASVS Requirement: ${threat.asvsRequirement}
   Test Case: ${threat.testDescription}
`).join('\n')}

User question: ${userMessage}`;
    
    setChatInput('');
    const newMessages: ChatMessage[] = [...chatMessages, { type: 'user' as const, text: userMessage }];
    setChatMessages(newMessages);
    
    // Save to component chat history
    const componentId = selectedComponent.data.label;
    setComponentChatHistories(prev => ({
      ...prev,
      [componentId]: newMessages
    }));
    
    setIsChatLoading(true);

    try {
      const response = await apiService.queryAI(assessment_id!, threatContext);
      console.log('Raw response:', response); // Debug logging
      console.log('Bot response:', response); // Debug logging

      if (!response || !response.Result) {
        throw new Error('Invalid response format from server');
      }

      const botResponse = typeof response.Result === 'string' 
        ? response.Result
        : typeof response.Result === 'object'
          ? JSON.stringify(response.Result, null, 2)
          : String(response.Result);

      const finalMessages: ChatMessage[] = [...newMessages, { type: 'bot' as const, text: botResponse }];
      setChatMessages(finalMessages);
      
      // Update component chat history
      setComponentChatHistories(prev => ({
        ...prev,
        [componentId]: finalMessages
      }));
    } catch (error) {
      console.error('Chat error:', error);
      const errorMessages: ChatMessage[] = [...newMessages, { 
        type: 'bot' as const, 
        text: 'Sorry, I encountered an error. Please try again.' 
      }];
      setChatMessages(errorMessages);
      
      // Update component chat history with error
      setComponentChatHistories(prev => ({
        ...prev,
        [componentId]: errorMessages
      }));
    } finally {
      setIsChatLoading(false);
    }
  };

  const handleThreatChatSubmit = async () => {
    if (!chatInput.trim() || !selectedNode) return;

    const userMessage = chatInput.trim();
    const normalize = (s: string) => (s || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
    
    // Get threat details from selectedNode
    const threatType = selectedNode.data.threatType;
    const scenario = selectedNode.data.fullScenario;
    const impact = selectedNode.data.impact;

    // Find DREAD score
    const dreadInfo = dreadData?.find((d: any) => {
      return normalize(d['Threat Type']) === normalize(threatType) && 
             normalize(d['Scenario']) === normalize(scenario);
    });

    const dreadScore = dreadInfo ? 
      (([
        dreadInfo['Damage Potential'],
        dreadInfo['Reproducibility'],
        dreadInfo['Exploitability'],
        dreadInfo['Affected Users'],
        dreadInfo['Discoverability']
      ].reduce((a, b) => a + b, 0) / 5)) : null;

    // Find mitigation
    const key = `${threatType}_${scenario}`.replace(/[\s\W]+/g, '_').toLowerCase();
    const mitigation = mitigationData?.[key];

    // Find ASVS test case
    const asvsTc = asvsTestCasesData?.find((t: any) =>
      normalize(t['Scenario']) === normalize(scenario) &&
      normalize(t['Threat Type']) === normalize(threatType)
    );

    // Find security test case
    const securityTc = securityTestCasesData?.find((t: any) =>
      normalize(t['Scenario']) === normalize(scenario) &&
      normalize(t['Threat Type']) === normalize(threatType)
    );

    const threatContext = `Threat Analysis:

Threat Type: ${threatType}
Scenario: ${scenario}
Impact: ${impact}
DREAD Score: ${dreadScore ? dreadScore.toFixed(1) : 'N/A'}
Mitigation: ${mitigation?.['Suggested Mitigation(s)'] || 'No mitigation available'}
ASVS Requirement: ${asvsTc?.asvs_requirement || securityTc?.asvs_requirement || 'No ASVS requirement available'}
Test Case: ${asvsTc?.test_cases?.[0]?.test_description || securityTc?.test_cases?.[0]?.test_description || 'No test case available'}

User question: ${userMessage}`;
    
    setChatInput('');
    const newMessages: ChatMessage[] = [...chatMessages, { type: 'user' as const, text: userMessage }];
    setChatMessages(newMessages);
    
    // Save to threat chat history
    const threatId = `${threatType}_${scenario}`;
    setThreatChatHistories(prev => ({
      ...prev,
      [threatId]: newMessages
    }));
    
    setIsChatLoading(true);

    try {
      const response = await apiService.queryAI(assessment_id!, threatContext);
      console.log('Raw response:', response); // Debug logging
      console.log('Bot response:', response); // Debug logging

      if (!response || !response.Result) {
        throw new Error('Invalid response format from server');
      }

      const botResponse = typeof response.Result === 'string' 
        ? response.Result
        : typeof response.Result === 'object'
          ? JSON.stringify(response.Result, null, 2)
          : String(response.Result);

      const finalMessages: ChatMessage[] = [...newMessages, { type: 'bot' as const, text: botResponse }];
      setChatMessages(finalMessages);
      
      // Update threat chat history
      setThreatChatHistories(prev => ({
        ...prev,
        [threatId]: finalMessages
      }));
    } catch (error) {
      console.error('Chat error:', error);
      const errorMessages: ChatMessage[] = [...newMessages, { 
        type: 'bot' as const, 
        text: 'Sorry, I encountered an error. Please try again.' 
      }];
      setChatMessages(errorMessages);
      
      // Update threat chat history with error
      setThreatChatHistories(prev => ({
        ...prev,
        [threatId]: errorMessages
      }));
    } finally {
      setIsChatLoading(false);
    }
  };

  return (
    // h-[calc(100vh/0.8)] compensates for the app-wide `html { zoom: 0.8 }` (see index.css):
    // a plain h-screen (100vh) would only fill ~80% of the viewport, leaving a dead band at the
    // bottom of this fixed-height flex container holding the diagram. Dividing by 0.8 renders it
    // at exactly one full viewport after the zoom.
    <div className="h-[calc(100vh/0.8)] flex flex-col dark:bg-transparent">
      <div className="px-6 py-5 border-b border-slate-200 dark:border-gray-700/60 bg-white dark:bg-gray-900/80">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#0052cc] to-blue-400 flex items-center justify-center shadow-sm">
                <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 10l-2 1m0 0l-2-1m2 1v2.5M20 7l-2 1m2-1l-2-1m2 1v2.5M14 4l-2-1-2 1M4 7l2-1M4 7l2 1M4 7v2.5M12 21l-2-1m2 1l2-1m-2 1v-2.5M6 18l-2-1v-2.5M18 18l2-1v-2.5" />
                </svg>
              </div>
              <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100">Interactive Threat Model</h1>
            </div>
            {assessmentDetails ? (
              <div className="flex items-center gap-2 flex-wrap">
                <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold bg-slate-100 text-slate-600 border border-slate-200 dark:bg-gray-800/60 dark:text-slate-400 dark:border-gray-700/60 uppercase tracking-wide">
                  {assessmentDetails.department}
                </span>
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{assessmentDetails.projectName}</span>
                <span className="text-xs text-slate-400 dark:text-slate-500">&middot; {new Date(assessmentDetails.timestamp).toLocaleDateString()}</span>
              </div>
            ) : (
              <p className="text-sm text-slate-500 dark:text-slate-400">{assessment_id}</p>
            )}
          </div>

          <div className="flex flex-col items-end gap-2 flex-shrink-0">
            <button
              onClick={() => navigate(`/view-threat-model/${assessment_id}`)}
              className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 text-slate-600 text-sm font-medium rounded-lg hover:border-[#0052cc]/40 hover:text-[#0052cc] hover:bg-blue-50/50 dark:bg-gray-800/60 dark:border-gray-700 dark:text-slate-300 dark:hover:border-blue-500/40 dark:hover:text-blue-400 dark:hover:bg-blue-900/20 transition-all duration-200 shadow-sm"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Basic Mode
            </button>
            <div className="flex items-center gap-4">
              {viewMode === 'architecture' && (
                <div className="flex flex-col items-end gap-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-slate-500 dark:text-slate-400">Trust Boundaries</span>
                    <button
                      onClick={() => setShowTrustBoundaries(prev => !prev)}
                      disabled={trustBoundaries.length === 0}
                      title={trustBoundaries.length === 0 ? 'Regenerate diagram to enable trust boundaries' : (showTrustBoundaries ? 'Hide trust boundaries' : 'Show trust boundaries')}
                      className={`relative inline-flex h-5 w-9 flex-shrink-0 items-center rounded-full transition-colors duration-200 focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed ${
                        showTrustBoundaries ? 'bg-indigo-500' : 'bg-slate-200 dark:bg-gray-700'
                      }`}
                    >
                      <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform duration-200 ${
                        showTrustBoundaries ? 'translate-x-4' : 'translate-x-0.5'
                      }`} />
                    </button>
                  </div>
                  {trustBoundaries.length === 0 && (
                    <span className="text-[10px] text-amber-500 dark:text-amber-400">Regenerate diagram to enable</span>
                  )}
                </div>
              )}
              <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-slate-500 dark:text-slate-400">View by</span>
              <div className="flex items-center gap-1 bg-slate-100 dark:bg-gray-800 p-1 rounded-lg">
              <button
                onClick={() => setViewMode('threats')}
                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-all ${
                  viewMode === 'threats'
                    ? 'bg-white dark:bg-gray-700 text-[#0052cc] dark:text-blue-400 shadow-sm'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'
                }`}
              >
                Threats
              </button>
              <button
                onClick={() => setViewMode('architecture')}
                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-all ${
                  viewMode === 'architecture'
                    ? 'bg-white dark:bg-gray-700 text-[#0052cc] dark:text-blue-400 shadow-sm'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'
                }`}
              >
                Architecture
              </button>
              </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Missing Diagram Alert and Regenerate Button */}
      {isDiagramMissing && viewMode === 'architecture' && (
        <div className="bg-amber-50 dark:bg-amber-900/20 border-l-4 border-amber-400 dark:border-amber-600 p-4 m-4">
          <div className="flex items-start">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-amber-400 dark:text-amber-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
                Data Flow Diagram is not generated yet or is missing data.
              </p>
              <p className="text-sm text-amber-700 dark:text-amber-400 mt-1">
                Please click the button below to generate the diagrams.
              </p>
              <button
                onClick={handleRegenerateDiagrams}
                disabled={isDiagramGenerating}
                className="mt-3 bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200 flex items-center"
              >
                {isDiagramGenerating ? (
                  <>
                    <svg className="animate-spin h-5 w-5 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Generating Diagrams...
                  </>
                ) : (
                  <>
                    <svg className="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    Regenerate Diagrams
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* View Content */}
      {viewMode === 'threats' ? (
        /* Categories and Threats */
      <div className="border-b border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center gap-4 mb-4">
          <h3 className="font-semibold text-lg dark:text-slate-200">
            {methodology === 'STRIDE' ? 'Threats by Category' : 'Business Risk Categories'}
          </h3>
          <div className="flex items-center space-x-2">
            <>
              <button
                key="ALL"
                onClick={() => setActiveCategory('ALL')}
                className={`px-6 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                  activeCategory === 'ALL'
                    ? 'bg-blue-500 text-white shadow-md'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200 dark:bg-gray-800 dark:text-slate-400 dark:hover:bg-gray-700'
                }`}
              >
                ALL
              </button>
              {(methodology === 'STRIDE' ? CATEGORIES : dynamicCategories).map(category => (
                <button
                  key={category}
                  onClick={() => setActiveCategory(category)}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                    activeCategory === category
                      ? 'bg-blue-500 text-white shadow-md'
                      : 'bg-gray-100 text-gray-600 hover:bg-gray-200 dark:bg-gray-800 dark:text-slate-400 dark:hover:bg-gray-700'
                  }`}
                >
                  <span className="w-6 h-6 flex items-center justify-center bg-white bg-opacity-20 rounded-full font-bold">
                    {category.charAt(0)}
                  </span>
                  <span>{methodology === 'STRIDE' ? category.split(' ')[0] : category}</span>
                </button>
              ))}
            </>
          </div>
        </div>
        <div className="overflow-x-auto">
          <div className="flex gap-3 pb-4" style={{ minWidth: 'min-content' }}>
            {threatModel?.result.raw_response.threat_model?.filter((threat: Threat) => {
              if (activeCategory === 'ALL') return true;
              if (methodology === 'STRIDE') {
                return threat['Threat Type'].startsWith(activeCategory.split(' ')[0].charAt(0));
              } else {
                // For PASTA, filter by Business Risk Type
                const pastaThreat = threat as PastaThreat;
                const businessRiskTypes = Array.isArray(pastaThreat['Business Risk Type']) 
                  ? pastaThreat['Business Risk Type'] 
                  : [pastaThreat['Business Risk Type']];
                return businessRiskTypes.includes(activeCategory);
              }
            })?.map((threat: any) => {
              // Find the original index of this threat in the full threat model
              const originalIndex = threatModel.result.raw_response.threat_model.findIndex(
                t => t['Threat Type'] === threat['Threat Type'] && t['Scenario'] === threat['Scenario']
              );
              return (
                <div
                  key={originalIndex}
                  className={`p-3 rounded-lg cursor-pointer transition-all duration-200 flex-shrink-0 w-64 hover:shadow-md ${
                    selectedNode?.id === `threat-${threat['Threat Type']}-${originalIndex}`
                      ? 'bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700/60 shadow-md'
                      : 'hover:bg-blue-50 dark:hover:bg-blue-900/10 hover:border-blue-200 dark:hover:border-blue-700/40 border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900/60'
                  }`}
                  onClick={() => {
                    const nodeId = `threat-${threat['Threat Type']}-${originalIndex}`;
                    const node = nodes.find(n => n.id === nodeId);
                    if (node) {
                      updateNodeSelection(node);
                    }
                  }}
                >
                  <p className="font-medium text-sm mb-2 text-slate-800 dark:text-slate-100">
                    {threat['Threat Type']}
                  </p>
                  <p className="text-sm text-gray-700 dark:text-slate-300 font-medium line-clamp-2">
                    {threat['Scenario'].substring(0, 100)}{threat['Scenario'].length > 100 ? '...' : ''}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      ) : (
        /* Architecture View */
        <div className="flex-1 flex flex-col">
          {/* Component Categories */}
          <div className="p-4">
            <div className="flex items-center gap-4 mb-2">
              <h3 className="font-semibold text-lg dark:text-slate-200">Components</h3>
              <div className="flex items-center space-x-2">
                <>
                  <button
                    key="ALL"
                    onClick={() => setSelectedComponentCategory('ALL')}
                    className={`px-6 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                      selectedComponentCategory === 'ALL'
                        ? 'bg-blue-500 text-white shadow-md'
                        : 'bg-gray-100 text-gray-600 hover:bg-gray-200 dark:bg-gray-800 dark:text-slate-400 dark:hover:bg-gray-700'
                    }`}
                  >
                    ALL
                  </button>
                  {componentCategories.map(category => (
                    <button
                      key={category}
                      onClick={() => setSelectedComponentCategory(category)}
                      className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                        selectedComponentCategory === category
                          ? 'bg-blue-500 text-white shadow-md'
                          : 'bg-gray-100 text-gray-600 hover:bg-gray-200 dark:bg-gray-800 dark:text-slate-400 dark:hover:bg-gray-700'
                      }`}
                    >
                      <span className="w-6 h-6 flex items-center justify-center bg-white bg-opacity-20 rounded-full font-bold">
                        {category.charAt(0)}
                      </span>
                      <span>{category}</span>
                    </button>
                  ))}
                </>
              </div>
            </div>
          </div>

          {/* Components List */}
          <div className="overflow-x-auto px-4">
            <div className="flex gap-3 pb-4" style={{ minWidth: 'min-content' }}>
              {architectureNodes.filter(node => 
                selectedComponentCategory === 'ALL' || 
                node.data.type === selectedComponentCategory
              ).map((node, index) => (
                <div
                  key={index}
                  className={`p-3 rounded-lg cursor-pointer transition-all duration-200 flex-shrink-0 w-64 hover:shadow-md ${
                    selectedComponent?.id === node.id
                      ? 'bg-blue-50 dark:bg-blue-900/40 border border-blue-200 dark:border-blue-600 shadow-md'
                      : 'bg-white dark:bg-gray-900/60 hover:bg-blue-50 dark:hover:bg-blue-900/10 hover:border-blue-200 dark:hover:border-blue-700/40 border border-gray-300 dark:border-gray-600'
                  }`}
                  onClick={() => {
                    setSelectedComponent(node);
                    if (architectureReactFlowInstance) {
                      const zoomLevel = 1.5;
                      const { x, y } = node.position;
                      const width = 200;
                      const height = 100;
                      const centerX = x + width / 2;
                      const centerY = y + height / 2;
                      architectureReactFlowInstance.setCenter(centerX, centerY, { zoom: zoomLevel, duration: 800 });
                    }
                  }}
                >
                  <p className="font-medium text-sm mb-2 text-slate-800 dark:text-slate-100">
                    {node.data.type}
                  </p>
                  <p className="text-sm text-gray-700 dark:text-slate-300 font-medium">
                    {node.data.label}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1 flex">
            {/* Left side - Architecture Diagram */}
            <div className="w-1/2 h-full border-r border-gray-300 dark:border-gray-600">
            <ReactFlow
              nodes={architectureDisplayNodes}
              edges={architectureEdges}
              onNodesChange={onArchitectureNodesChange}
              onEdgesChange={onArchitectureEdgesChange}
              onNodeClick={(event: React.MouseEvent, node: Node) => {
                setSelectedComponent(node);
                // Auto-zoom to the selected node
                if (architectureReactFlowInstance) {
                  const zoomLevel = 1.5;
                  const { x, y } = node.position;
                  const width = 200; // Default width of component node
                  const height = 100; // Default height of component node
                  const centerX = x + width / 2;
                  const centerY = y + height / 2;
                  architectureReactFlowInstance.setCenter(centerX, centerY, { zoom: zoomLevel, duration: 800 });
                }
              }}
              onInit={(instance: ReactFlowInstance) => setArchitectureReactFlowInstance(instance)}
              fitView
              nodeTypes={nodeTypes}
              className="bg-white dark:bg-gray-900"
            >
              <Controls />
              <MiniMap />
              <Background color="#94a3b8" gap={16} size={1} />
            </ReactFlow>
          </div>
          
          {/* Right side - Details Panel */}
          <div className="w-1/2 h-full flex flex-col">
            <div className="flex-1 overflow-y-auto bg-white dark:bg-gray-900/80">
              {selectedComponent ? (
                <div className="flex flex-col h-full">
                  <div className="p-6 bg-white dark:bg-gray-900/80 border-b dark:border-gray-700">
                    <div className="flex items-center justify-between mb-4">
                      <h2 className="text-2xl font-bold text-gray-900 dark:text-slate-200">{selectedComponent.data.label}</h2>
                      <span className="px-3 py-1 text-sm font-medium rounded-full bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300">
                        {selectedComponent.data.type}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-gray-600 dark:text-slate-400">Component DREAD Score:</span>
                      {(() => {
                        // Calculate average DREAD score for this component
                        const componentThreats = selectedComponent.data.relatedThreats || [];
                        const dreadScores = componentThreats
                          .map((threatScenario: string) => {
                            const threatEntry = threatModel?.result?.raw_response?.threat_model?.find(
                              (threat) => threat['Scenario'] === threatScenario
                            );
                            if (!threatEntry) return null;

                            const dreadInfo = dreadData?.find((d: any) => {
                              const normalizeString = (str: string) => str.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
                              return normalizeString(d['Threat Type']) === normalizeString(threatEntry['Threat Type']) && 
                                     normalizeString(d['Scenario']) === normalizeString(threatEntry['Scenario']);
                            });

                            return dreadInfo ? 
                              (([
                                dreadInfo['Damage Potential'],
                                dreadInfo['Reproducibility'],
                                dreadInfo['Exploitability'],
                                dreadInfo['Affected Users'],
                                dreadInfo['Discoverability']
                              ].reduce((a, b) => a + b, 0) / 5)) : null;
                          })
                          .filter((score: number | null): score is number => score !== null);

                        const averageScore = dreadScores.length > 0 
                          ? dreadScores.reduce((a: number, b: number) => a + b, 0) / dreadScores.length 
                          : null;

                        return averageScore !== null ? (
                          <span className={`px-3 py-1 font-bold rounded-full ${
                            averageScore >= 8 ? 'bg-red-50 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
                            averageScore >= 6 ? 'bg-yellow-50 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
                            'bg-green-50 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                          }`}>
                            {averageScore.toFixed(1)}
                          </span>
                        ) : (
                          <span className="px-3 py-1 font-bold rounded-full bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-slate-400">N/A</span>
                        );
                      })()}
                    </div>
                  </div>

                  {/* Tabs */}
                  <div className="border-b border-gray-200 dark:border-gray-700">
                    <nav className="flex gap-4 px-6">
                      {['Threats', 'DREAD', 'Mitigations', 'Security Test Cases', 'Chat'].map((tab) => (
                        <button
                          key={tab}
                          onClick={() => setActiveTab(tab as 'Threats' | 'DREAD' | 'Mitigations' | 'Security Test Cases' | 'Chat')}
                          className={`py-3 px-2 border-b-2 font-medium text-sm ${
                            activeTab === tab
                              ? 'border-blue-500 text-blue-600'
                              : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-300 hover:border-gray-300 dark:hover:border-gray-600'
                          }`}
                        >
                          {tab}
                        </button>
                      ))}
                    </nav>
                  </div>

                  {/* Tab Content */}
                  <div className="p-6">
                    <div className="w-full h-[500px] overflow-y-auto bg-white dark:bg-gray-900/80 rounded-lg p-6 shadow-sm">
                      {activeTab === 'Threats' && (
                        <div className="overflow-x-auto">
                          {!selectedComponent?.data?.relatedThreats?.length ? (
                            <div className="text-center text-gray-500 dark:text-slate-400 py-8">
                              No threats identified for this component
                            </div>
                          ) : (
                            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead className="bg-gray-50 dark:bg-gray-800/60">
                              <tr>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">
                                  Type
                                </th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">
                                  Threat Scenario
                                </th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">
                                  Impact
                                </th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">
                                  Confidence
                                </th>
                              </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-900/80 divide-y divide-gray-200 dark:divide-gray-700">
                              {selectedComponent?.data?.relatedThreats?.map((threatScenario: string, index: number) => {
                                const threatEntry = threatModel?.result?.raw_response?.threat_model?.find(
                                  (threat) => threat['Scenario'] === threatScenario
                                );

                                return threatEntry ? (
                                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-800/60">
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-slate-200">
                                      {threatEntry['Threat Type']}
                                    </td>
                                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-slate-400">
                                      {threatEntry['Scenario']}
                                    </td>
                                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-slate-400">
                                      {threatEntry['Potential Impact']}
                                    </td>
                                    <td className="px-6 py-4 text-sm">
                                      {(() => {
                                        const c = (threatEntry['Confidence'] as string) || 'Medium';
                                        const cls = c === 'High' ? 'bg-red-100 text-red-700' : c === 'Low' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700';
                                        return <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>{c}</span>;
                                      })()}
                                    </td>
                                  </tr>
                                ) : null;
                              })}
                            </tbody>
                          </table>
                          )}
                        </div>
                      )}

                      {activeTab === 'DREAD' && (
                        <div className="overflow-x-auto">
                          {!selectedComponent?.data?.relatedThreats?.length ? (
                            <div className="text-center text-gray-500 dark:text-slate-400 py-8">
                              No threats identified for this component
                            </div>
                          ) : (
                            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead className="bg-gray-50 dark:bg-gray-800/60">
                              <tr>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">
                                  Threat Type
                                </th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">
                                  Threat Scenario
                                </th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider">
                                  DREAD Score
                                </th>
                              </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-900/80 divide-y divide-gray-200 dark:divide-gray-700">
                              {selectedComponent?.data?.relatedThreats?.map((threatScenario: string, index: number) => {
                                const threatEntry = threatModel?.result?.raw_response?.threat_model?.find(
                                  (threat) => threat['Scenario'] === threatScenario
                                );

                                if (!threatEntry) return null;

                                // Find DREAD score for this threat
                                const dreadInfo = dreadData?.find((d: any) => {
                                  const normalizeString = (str: string) => str.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
                                  return normalizeString(d['Threat Type']) === normalizeString(threatEntry['Threat Type']) &&
                                         normalizeString(d['Scenario']) === normalizeString(threatEntry['Scenario']);
                                });

                                const dreadScore = dreadInfo ?
                                  (([
                                    dreadInfo['Damage Potential'],
                                    dreadInfo['Reproducibility'],
                                    dreadInfo['Exploitability'],
                                    dreadInfo['Affected Users'],
                                    dreadInfo['Discoverability']
                                  ].reduce((a, b) => a + b, 0) / 5)) : null;

                                return (
                                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-800/60">
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-slate-200">
                                      {threatEntry['Threat Type']}
                                    </td>
                                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-slate-400">
                                      {threatEntry['Scenario']}
                                    </td>
                                    <td className="px-6 py-4 text-center">
                                      {dreadScore !== null ? (
                                        <span className={`px-3 py-1 text-sm font-bold rounded-full ${
                                          dreadScore >= 8 ? 'bg-red-50 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
                                          dreadScore >= 6 ? 'bg-yellow-50 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
                                          'bg-green-50 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                                        }`}>
                                          {dreadScore.toFixed(1)}
                                        </span>
                                      ) : (
                                        <span className="text-gray-400 dark:text-slate-500 text-sm">N/A</span>
                                      )}
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                          )}
                        </div>
                      )}

                      {activeTab === 'Mitigations' && (
                        <div className="overflow-x-auto">
                          {!selectedComponent?.data?.relatedThreats?.length ? (
                            <div className="text-center text-gray-500 dark:text-slate-400 py-8">
                              No threats identified for this component
                            </div>
                          ) : (
                            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead className="bg-gray-50 dark:bg-gray-800/60">
                              <tr>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider w-1/8">
                                  Type
                                </th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider w-1/3">
                                  Threat Scenario
                                </th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider w-1/2">
                                  Mitigations
                                </th>
                              </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-900/80 divide-y divide-gray-200 dark:divide-gray-700">
                              {selectedComponent?.data?.relatedThreats?.map((threatScenario: string, index: number) => {
                                const threatEntry = threatModel?.result?.raw_response?.threat_model?.find(
                                  (threat) => threat['Scenario'] === threatScenario
                                );

                                if (!threatEntry) return null;

                                const key = `${threatEntry['Threat Type']}_${threatEntry['Scenario']}`.replace(/[\s\W]+/g, '_').toLowerCase();
                                const mitigation = mitigationData?.[key];

                                return (
                                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-800/60">
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-slate-200">
                                      {threatEntry['Threat Type']}
                                    </td>
                                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-slate-400">
                                      {threatEntry['Scenario']}
                                    </td>
                                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-slate-400">
                                      <div className="prose prose-blue dark:prose-invert max-w-none">
                                        <ul className="list-none">
                                          {mitigation?.['Suggested Mitigation(s)'] && typeof mitigation['Suggested Mitigation(s)'] === 'string'
                                            ? mitigation['Suggested Mitigation(s)']
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
                                            : <li>No mitigation details available</li>
                                          }
                                        </ul>
                                      </div>
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                          )}
                        </div>
                      )}

                      {activeTab === 'Security Test Cases' && (
                        <div className="overflow-x-auto">
                         {!selectedComponent?.data?.relatedThreats?.length ? (
                            <div className="text-center text-gray-500 dark:text-slate-400 py-8">
                              No threats identified for this component
                            </div>
                          ) : (
                          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead className="bg-gray-50 dark:bg-gray-800/60">
                              <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider w-1/6">
                                  Threat Type
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider w-1/3">
                                  Scenario
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider w-1/6">
                                  ASVS Clause
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider w-1/6">
                                  Security Test Case
                                </th>
                                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wider w-1/6">
                                  Validated
                                </th>
                              </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-900/80 divide-y divide-gray-200 dark:divide-gray-700">
                              {selectedComponent?.data?.relatedThreats?.map((threatScenario: string, index: number) => {
                                const threatEntry = threatModel?.result?.raw_response?.threat_model?.find(
                                  (threat) => threat['Scenario'] === threatScenario
                                );
                                
                                if (!threatEntry) return null;

                                const normalize = (s: string) => (s || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
                                const tc = asvsTestCasesData?.find((t: any) =>
                                  normalize(t['Scenario']) === normalize(threatEntry['Scenario']) &&
                                  normalize(t['Threat Type']) === normalize(threatEntry['Threat Type'])
                                );

                                // Find security test case for this threat
                                const securityTc = securityTestCasesData?.find((t: any) =>
                                  normalize(t['Scenario']) === normalize(threatEntry['Scenario']) &&
                                  normalize(t['Threat Type']) === normalize(threatEntry['Threat Type'])
                                );

                                console.log('ASVS lookup for threat:', {
                                  component: selectedComponent?.data?.label,
                                  threatType: threatEntry['Threat Type'],
                                  scenario: threatEntry['Scenario'],
                                  foundAsvsMatch: !!tc,
                                  foundSecurityMatch: !!securityTc
                                });

                                return (
                                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-800/60">
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-slate-200">{threatEntry['Threat Type']}</td>
                                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-slate-400">{threatEntry['Scenario']}</td>
                                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-slate-400">{tc?.asvs_requirement || securityTc?.asvs_requirement || '-'}</td>
                                    <td className="px-6 py-4 flex items-center">
                                      <span className="flex-1 text-sm text-gray-500 dark:text-slate-400">{tc?.test_cases?.[0]?.test_description || securityTc?.test_cases?.[0]?.test_description || '-'}</span>
                                      {(tc || securityTc) && (
                                        <button
                                          onClick={() => setSelectedTestCase(tc || securityTc)}
                                          className="ml-2 text-blue-600 hover:text-blue-800"
                                        >
                                          <svg
                                            xmlns="http://www.w3.org/2000/svg"
                                            className="h-5 w-5"
                                            fill="none"
                                            viewBox="0 0 24 24"
                                            stroke="currentColor"
                                          >
                                            <path
                                              strokeLinecap="round"
                                              strokeLinejoin="round"
                                              strokeWidth={2}
                                              d="M13 16h-1v-4h-1m1-4h.01M12 2a10 10 0 100 20 10 10 0 000-20z"
                                            />
                                          </svg>
                                        </button>
                                      )}
                                    </td>
                                    <td className="px-6 py-4 text-center">
                                      {(tc || securityTc) ? (
                                        <button
                                          onClick={() => handleValidationChange(tc || securityTc)}
                                          className={`px-3 py-1 rounded-full text-sm font-medium ${
                                            (tc?.validated || securityTc?.validated)
                                              ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                                              : 'bg-gray-100 text-gray-800 hover:bg-gray-200 dark:bg-gray-700 dark:text-slate-300 dark:hover:bg-gray-600'
                                          }`}
                                        >
                                          {(tc?.validated || securityTc?.validated) ? 'Validated' : 'Mark as Validated'}
                                        </button>
                                      ) : (
                                        <span className="text-gray-400 dark:text-slate-500 text-sm">No test data</span>
                                      )}
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                           
                          )}
                        </div>
                      )}

                      {activeTab === 'Chat' && (
                        <div className="flex flex-col h-full">
                          <div className="h-[400px] bg-gray-50 dark:bg-gray-800/60 rounded-lg p-4 overflow-y-auto">
                            {chatMessages.length === 0 ? (
                              <div className="text-center text-gray-500 dark:text-slate-400">
                                <p>Chat with Threat Bot about this threat.</p>
                                <p className="text-sm mt-2">Ask questions about mitigations, impact analysis, or security best practices.</p>
                              </div>
                            ) : (
                              <div className="space-y-4">
                                {chatMessages.map((msg: ChatMessage, i: number) => (
                                  <div
                                    key={i}
                                    className={`flex ${msg.type === 'user' ? 'justify-end' : 'justify-start'}`}
                                  >
                                    <div
                                      className={`max-w-[80%] rounded-lg px-4 py-2 ${
                                        msg.type === 'user'
                                          ? 'bg-blue-500 text-white'
                                          : 'bg-white dark:bg-gray-900/80 border border-gray-200 dark:border-gray-700 dark:text-slate-300'
                                      }`}
                                    >
                                      <p className="whitespace-pre-wrap">{msg.text}</p>
                                    </div>
                                  </div>
                                ))}
                                {isChatLoading && (
                                  <div className="flex justify-start">
                                    <div className="bg-white dark:bg-gray-900/80 border border-gray-200 dark:border-gray-700 rounded-lg px-4 py-2">
                                      <div className="flex gap-1">
                                        <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                                        <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                                        <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                                      </div>
                                    </div>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                          <div className="mt-4 flex gap-2">
                            <input
                              type="text"
                              value={chatInput}
                              onChange={(e) => setChatInput(e.target.value)}
                              onKeyDown={(e) => e.key === 'Enter' && handleChatSubmit()}
                              placeholder="Type your message..."
                              className="flex-1 rounded-lg border border-gray-300 dark:border-gray-600 px-4 py-2 dark:bg-gray-800 dark:text-slate-200 dark:placeholder-slate-500"
                              disabled={isChatLoading}
                            />
                            <button
                              onClick={handleChatSubmit}
                              disabled={isChatLoading || !chatInput.trim()}
                              className="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                              Send
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center text-gray-500 dark:text-slate-400 mt-10">
                  <p>Select a component to view its details</p>
                </div>
              )}

              {/* Test Case Details Modal */}
              {selectedTestCase && (
                <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center">
                  <div className="bg-white dark:bg-gray-900/80 rounded-lg shadow-lg w-96 p-4 relative">
                    <button
                      onClick={() => setSelectedTestCase(null)}
                      className="absolute top-2 right-2 text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200"
                    >
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        className="h-5 w-5"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M6 18L18 6M6 6l12 12"
                        />
                      </svg>
                    </button>
                    <h4 className="font-bold mb-2 text-slate-800 dark:text-slate-100">Test Case Details</h4>
                    <div className="text-sm space-y-2 text-slate-700 dark:text-slate-300">
                      <p>
                        <strong>Description:</strong> {selectedTestCase.test_cases[0]?.test_description}
                      </p>
                      <p>
                        <strong>Steps:</strong>
                      </p>
                      <ol className="list-decimal list-inside ml-4">
                        {selectedTestCase.test_cases[0]?.steps.map((step: string, i: number) => (
                          <li key={i}>{step.replace(/^\d+\.\s*/, '')}</li>
                        ))}
                      </ol>
                      <p>
                        <strong>Expected:</strong> {selectedTestCase.test_cases[0]?.expected_result}
                      </p>
                      {selectedTestCase.test_cases[0]?.prerequisites && (
                        <p>
                          <strong>Prerequisites:</strong> {selectedTestCase.test_cases[0]?.prerequisites}
                        </p>
                      )}
                      {selectedTestCase.test_cases[0]?.test_data && (
                        <p>
                          <strong>Test Data:</strong> {selectedTestCase.test_cases[0]?.test_data}
                        </p>
                      )}
                      {selectedTestCase.test_cases[0]?.validation_criteria && (
                        <p>
                          <strong>Validation Criteria:</strong>{' '}
                          {selectedTestCase.test_cases[0]?.validation_criteria}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
            </div>
          </div>
        </div>
      )}

      {viewMode === 'threats' && (
        <div className="flex-1 flex">
        {/* Left side - Flow Diagram */}
        <div className="w-1/2 h-full border-r border-gray-300 dark:border-gray-600">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            fitView
            nodeTypes={nodeTypes}
            onInit={(instance: ReactFlowInstance) => setReactFlowInstance(instance)}
            className="bg-white dark:bg-gray-900"
          >
            <Controls />
            <MiniMap />
            <Background color="#94a3b8" gap={16} size={1} />
          </ReactFlow>
        </div>

        {/* Right side - Details Panel */}
        <div className="w-1/2 h-full flex flex-col">
          <div className="flex-1 overflow-y-auto bg-white dark:bg-gray-900/80">
          {selectedNode ? (
            <div className="flex flex-col h-full">
              {/* Fixed Header with DREAD Score */}
              <div className="p-6 bg-white dark:bg-gray-900/80 border-b dark:border-gray-700">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-slate-200">Threat Details</h2>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-600 dark:text-slate-400">DREAD Score:</span>
                    <span className={`px-3 py-1 font-bold rounded-full ${
                      selectedNode.data.dreadScore >= 8 ? 'bg-red-50 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
                      selectedNode.data.dreadScore >= 6 ? 'bg-yellow-50 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
                      'bg-green-50 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                    }`}>
                      {selectedNode.data.dreadScore?.toFixed(1) || 'N/A'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Tabs */}
              <div className="border-b border-gray-200 dark:border-gray-700">
                <nav className="flex gap-4 px-6">
                  {['Threats', 'DREAD', 'Mitigations', 'Security Test Cases', 'Chat'].map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setActiveTab(tab as 'Threats' | 'DREAD' | 'Mitigations' | 'Security Test Cases' | 'Chat')}
                      className={`py-3 px-2 border-b-2 font-medium text-sm ${
                        activeTab === tab
                          ? 'border-blue-500 text-blue-600'
                          : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-300 hover:border-gray-300 dark:hover:border-gray-600'
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                </nav>
              </div>

              {/* Tab Content */}
              <div className="p-6">
                <div className="w-full h-[500px] overflow-y-auto bg-white dark:bg-gray-900/80 rounded-lg p-6 shadow-sm">
                {activeTab === 'Threats' && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-slate-400">Type</h3>
                      <p className="mt-2 text-gray-900 dark:text-slate-200">{selectedNode.data.label.split('\n')[0]}</p>
                    </div>
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-slate-400">Scenario</h3>
                      <p className="mt-2 text-gray-900 dark:text-slate-200">{selectedNode.data.description}</p>
                    </div>
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-slate-400">Potential Impact</h3>
                      <p className="mt-2 text-gray-900 dark:text-slate-200">{selectedNode.data.impact}</p>
                    </div>
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-slate-400">Confidence</h3>
                      <p className="mt-2">
                        {(() => {
                          const c = (selectedNode.data.confidence as string) || 'Medium';
                          const cls = c === 'High' ? 'bg-red-100 text-red-700' : c === 'Low' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700';
                          return <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>{c}</span>;
                        })()}
                      </p>
                    </div>
                  </div>
                )}

                {activeTab === 'DREAD' && selectedNode && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-slate-400">Type</h3>
                      <p className="mt-2 text-gray-900 dark:text-slate-200">{selectedNode.data.label.split('\n')[0]}</p>
                    </div>
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-slate-400">Scenario</h3>
                      <p className="mt-2 text-gray-900 dark:text-slate-200">{selectedNode.data.description}</p>
                    </div>
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-slate-400">DREAD Score</h3>
                      <div className="mt-2">
                        {selectedNode.data.dreadScore !== null ? (
                          <span className={`px-3 py-1 text-sm font-bold rounded-full ${
                            selectedNode.data.dreadScore >= 8 ? 'bg-red-50 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
                            selectedNode.data.dreadScore >= 6 ? 'bg-yellow-50 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
                            'bg-green-50 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                          }`}>
                            {selectedNode.data.dreadScore.toFixed(1)}
                          </span>
                        ) : (
                          <span className="text-gray-400 dark:text-slate-500 text-sm">N/A</span>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'Mitigations' && selectedNode && (
                  <div className="prose prose-blue dark:prose-invert max-w-none">
                    {(() => {
                      const threatType = selectedNode.data.threatType;
                      const scenario = selectedNode.data.fullScenario;
                      const key = `${threatType}_${scenario}`.replace(/[\s\W]+/g, '_').toLowerCase();
                      const mitigation = (mitigationData as any)?.[key];

                      return (
                        <ul className="list-none space-y-4">
                          {mitigation?.['Suggested Mitigation(s)'] && typeof mitigation['Suggested Mitigation(s)'] === 'string'
                            ? mitigation['Suggested Mitigation(s)']
                                .split('. ')
                                .map((item: string) => {
                                  let cleanedItem = item
                                    .trim()
                                    .replace(/^[\d]+[\.\s]*/, '')
                                    .replace(/\s\d+$/, '');
                                  if (/^\d+$/.test(cleanedItem.split(' ')[0] || '')) {
                                    cleanedItem = cleanedItem.replace(/^\d+\s*/, '');
                                  }
                                  return cleanedItem;
                                })
                                .filter((str: string) => Boolean(str))
                                .map((cleaned: string, i: number) => (
                                  <li key={i} className="flex gap-2 text-slate-700 dark:text-slate-300">
                                    <span className="text-blue-500 dark:text-blue-400 flex-shrink-0">•</span>
                                    <span>{cleaned}</span>
                                  </li>
                                ))
                            : <li className="text-gray-500 dark:text-slate-400">No mitigation details available</li>
                          }
                        </ul>
                      );
                    })()}
                  </div>
                )}

                {activeTab === 'Security Test Cases' && selectedNode && (
                  <div>
                    <ASVSTestCases
                      assessmentId={assessment_id!}
                      threatScenario={selectedNode.data.fullScenario}
                    />
                  </div>
                )}

                {activeTab === 'Chat' && (
                  <div className="flex flex-col h-full">
                    <div className="h-[400px] bg-gray-50 dark:bg-gray-800/60 rounded-lg p-4 overflow-y-auto">
                      {chatMessages.length === 0 ? (
                        <div className="text-center text-gray-500 dark:text-slate-400">
                          <p>Chat with Threat Bot about this threat.</p>
                          <p className="text-sm mt-2">Ask questions about mitigations, impact analysis, or security best practices.</p>
                        </div>
                      ) : (
                        <div className="space-y-4">
                          {chatMessages.map((msg: ChatMessage, i: number) => (
                            <div
                              key={i}
                              className={`flex ${msg.type === 'user' ? 'justify-end' : 'justify-start'}`}
                            >
                              <div
                                className={`max-w-[80%] rounded-lg px-4 py-2 ${
                                  msg.type === 'user'
                                    ? 'bg-blue-500 text-white'
                                    : 'bg-white dark:bg-gray-900/80 border border-gray-200 dark:border-gray-700 dark:text-slate-300'
                                }`}
                              >
                                <p className="whitespace-pre-wrap">{msg.text}</p>
                              </div>
                            </div>
                          ))}
                          {isChatLoading && (
                            <div className="flex justify-start">
                              <div className="bg-white dark:bg-gray-900/80 border border-gray-200 dark:border-gray-700 rounded-lg px-4 py-2">
                                <div className="flex gap-1">
                                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                    <div className="mt-4 flex gap-2">
                      <input
                        type="text"
                        value={chatInput}
                        onChange={(e) => setChatInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleThreatChatSubmit()}
                        placeholder="Type your message..."
                        className="flex-1 rounded-lg border border-gray-300 dark:border-gray-600 px-4 py-2 dark:bg-gray-800 dark:text-slate-200 dark:placeholder-slate-500"
                        disabled={isChatLoading}
                      />
                      <button
                        onClick={handleThreatChatSubmit}
                        disabled={isChatLoading || !chatInput.trim()}
                        className="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        Send
                      </button>
                    </div>
                  </div>
                )}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center text-gray-500 dark:text-slate-400 mt-10">
              <p>Select a component to view its details and associated threats</p>
            </div>
          )}
          </div>
        </div>
        </div>
      )}
    </div>
  );
};

export default InteractiveThreatModel;
