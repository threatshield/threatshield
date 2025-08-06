import json
import logging
import os
from rag.rag_handler import PromptManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AttackTreeHandler:
    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        self.client = openai_handler.client
        self.prompt_manager = PromptManager()

    def _get_methodology_from_details(self, assessment_id):
        """
        Get the methodology from details.json for the given assessment_id.
        Raises an error if details.json doesn't exist or doesn't contain the methodology.
        """
        details_path = os.path.join('storage', assessment_id, 'details.json')
        if not os.path.exists(details_path):
            error_msg = f"details.json not found for assessment {assessment_id}"
            logging.error(error_msg)
            raise ValueError(error_msg)
            
        try:
            with open(details_path, 'r') as f:
                details = json.load(f)
                methodology = details.get('threatModelingMethodology')
                if not methodology:
                    error_msg = f"No threat modeling methodology found in details.json for assessment {assessment_id}"
                    logging.error(error_msg)
                    raise ValueError(error_msg)
                return methodology
        except Exception as e:
            error_msg = f"Error reading methodology from details.json: {str(e)}"
            logging.error(error_msg)
            raise ValueError(error_msg)
    
    def create_attack_tree_prompt(self, threat_model_result, assessment_id=None):
        """
        Create prompt for generating attack tree using threat model data.
        """
        # Get methodology from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            try:
                methodology = self._get_methodology_from_details(assessment_id)
                logging.info(f"Using threat modeling methodology from details.json for attack tree: {methodology}")
            except ValueError as e:
                # Re-raise the error to be handled by the caller
                raise ValueError(f"Failed to get methodology: {str(e)}")
        else:
            # If no assessment_id is provided, this is likely a direct call not through the API
            # In this case, we need to throw an error as we can't determine the methodology
            error_msg = "Assessment ID is required to determine the threat modeling methodology"
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        # Get the attack tree prompt template
        prompt_data = self.prompt_manager.get_prompt("attack_tree")
        
        # Extract relevant information from threat model
        threats = threat_model_result.get('threat_model', [])
        
        # Group threats by type for better organization
        threat_types = {}
        for threat in threats:
            threat_type = threat.get('Threat Type', '')
            if threat_type not in threat_types:
                threat_types[threat_type] = []
            threat_types[threat_type].append(threat)
        
        # Format threats for attack tree analysis
        threat_descriptions = []
        for threat_type, type_threats in threat_types.items():
            threat_descriptions.append(f"## {threat_type} Threats:")
            for threat in type_threats:
                scenario = threat.get('Scenario', '')
                impact = threat.get('Potential Impact', '')
                threat_descriptions.append(f"- Scenario: {scenario}\n  Impact: {impact}")
        
        formatted_threats = "\n\n".join(threat_descriptions)
        
        prompt = f"""
{prompt_data.system_context} {prompt_data.task}

The JSON structure should follow this format:
{json.dumps(prompt_data.format.get("example", {}), indent=2)}

{prompt_data.instructions}

Below are the identified threats to consider:
{formatted_threats}

IMPORTANT: Your response must be ONLY valid JSON, with no additional text or explanation.
Ensure all JSON strings are properly escaped and the structure is valid.
Use commas between all properties and array elements.
"""
        return prompt

    def convert_tree_to_mermaid(self, tree_data):
        """
        Convert JSON tree structure to Mermaid diagram syntax with styled nodes based on type.
        Uses left-to-right layout for better visualization.
        """
        # Use LR (left-to-right) layout instead of TD (top-down) for better spacing
        mermaid_lines = ["graph LR"]
        
        # Add configuration for better layout
        # Note: Mermaid doesn't use commas in graph configuration
        mermaid_lines.append("    %% Configuration for better spacing and layout")
        mermaid_lines.append("    graph [rankdir=LR nodesep=100 ranksep=150]")
        
        # Add style definitions with spaces between properties to avoid rendering issues
        # Use different shapes for different node types
        # Note: Mermaid doesn't use commas in style definitions
        mermaid_lines.extend([
            "    %% Node styling",
            "    classDef goal fill:#ffd7d7 stroke:#ff9999 color:#cc0000 stroke-width:2px padding:15px margin:10px",
            "    classDef attack fill:#fff3d7 stroke:#ffd699 color:#cc7700 stroke-width:2px padding:10px margin:10px",
            "    classDef vulnerability fill:#d7e9ff stroke:#99c2ff color:#0052cc stroke-width:2px padding:8px margin:10px"
        ])
        
        # Track link count for styling
        link_count = 0
        link_styles = []
        
        def process_node(node, parent_id=None):
            nonlocal link_count
            node_id = node["id"]
            node_label = node["label"]
            node_type = node["type"]
            
            # Use different shapes based on node type
            if node_type == "goal":
                # Use stadium shape for goal nodes
                mermaid_lines.append(f'    {node_id}(["{node_label}"])')
            elif node_type == "attack":
                # Use hexagon shape for attack nodes
                mermaid_lines.append(f'    {node_id}{{{{{node_label}}}}}')
            else:
                # Use rounded rectangle for vulnerability nodes
                mermaid_lines.append(f'    {node_id}["{node_label}"]')
            
            # Apply style class based on node type
            mermaid_lines.append(f'    class {node_id} {node_type}')
            
            # Add connection to parent if exists with improved styling
            if parent_id:
                # Use curved lines with arrows for better visibility
                mermaid_lines.append(f'    {parent_id} -->|{node_type}| {node_id}')
                
                # Add link style for this connection (no commas in Mermaid style definitions)
                link_styles.append(f"    linkStyle {link_count} stroke:#333333 stroke-width:2px fill:none")
                link_count += 1
            
            # Process children
            if "children" in node:
                for child in node["children"]:
                    process_node(child, node_id)
        
        # Process the root node(s)
        for root_node in tree_data["nodes"]:
            process_node(root_node)
        
        # Add link styles
        mermaid_lines.extend(link_styles)
        
        # Join lines with newlines
        return "\n".join(mermaid_lines)

    def get_attack_tree(self, prompt):
        """
        Get attack tree from LLM with improved error handling and JSON parsing.
        """
        method = self.openai_handler.method
        logging.info(f"Generating attack tree using {method}")
        
        try:
            # Add explicit JSON formatting instructions to the system message
            system_message = """You are a Security Architect and expert. Create an attack tree structure in JSON format.
            IMPORTANT: Your response must be ONLY valid JSON, with no additional text or explanation.
            Ensure all JSON strings are properly escaped and the structure is valid.
            Always use commas between properties and array elements."""
            
            # Add stronger JSON instructions for Bedrock
            if method == 'BEDROCK':
                system_message = """You are a Security Architect and expert. Create an attack tree structure in JSON format.
                IMPORTANT: Your response must be ONLY valid JSON, with no additional text or explanation.
                Do not include markdown code blocks, explanations, or any text outside the JSON structure.
                Ensure all JSON strings are properly escaped and the structure is valid.
                Always use commas between properties and array elements."""

            # Prepare common parameters
            params = {
                "model": self.openai_handler.model,
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.5,  # Lower temperature for more consistent output
                "max_tokens": 8000
            }
            
            # Add provider-specific parameters
            if method == 'OPENAI':
                params["response_format"] = {"type": "json_object"}  # Enforce JSON response
                logging.info("Using OpenAI-specific parameters")
            elif method == 'BEDROCK':
                # Bedrock might not support response_format, so we don't add it
                logging.info("Using Bedrock-compatible parameters")
            
            # Make the API call
            logging.info(f"Sending request to {method} with model {self.openai_handler.model}")
            response = self.client.chat.completions.create(**params)
            
            response_content = response.choices[0].message.content.strip()
            
            # Additional JSON validation and cleaning
            try:
                # Try to parse the JSON response
                # First, try to fix common JSON formatting issues
                fixed_content = response_content
                
                try:
                    # Try parsing as-is first
                    tree_data = json.loads(fixed_content)
                    
                    # Ensure total_paths exists, calculate if not provided
                    if 'total_paths' not in tree_data:
                        # Calculate total paths by counting unique paths from root to leaf nodes
                        def count_paths(node):
                            if not node.get('children'):
                                return 1
                            total = 0
                            for child in node.get('children', []):
                                total += count_paths(child)
                            return total
                        
                        total_paths = 0
                        for root_node in tree_data.get('nodes', []):
                            total_paths += count_paths(root_node)
                        tree_data['total_paths'] = total_paths
                except json.JSONDecodeError:
                    # If parsing fails, try fixing the JSON
                    logging.warning("Initial JSON parsing failed, attempting fixes")
                    
                    # Fix missing commas between properties
                    import re
                    
                    # Fix missing commas between properties at the same level
                    fixed_content = re.sub(r'"\s*\n\s*"', '",\n"', fixed_content)
                    fixed_content = re.sub(r'}\s*\n\s*{', '},\n{', fixed_content)
                    
                    # Fix missing commas between object properties
                    fixed_content = re.sub(r'"([^"]+)"\s*:\s*("[^"]+"|\{[^}]+\}|\[[^\]]+\]|\w+)\s*\n\s*"', 
                                         r'"\1": \2,\n"', fixed_content)
                    
                    # Fix missing commas in arrays
                    fixed_content = re.sub(r'\}\s*\n\s*\{', '}, {', fixed_content)
                    fixed_content = re.sub(r'\]\s*\n\s*\[', '], [', fixed_content)
                    
                    # Fix missing commas between properties in nested objects
                    fixed_content = re.sub(r'(\s*"[^"]+"\s*:\s*(?:"[^"]*"|{[^}]*}|\[[^\]]*\]|\w+))\s*\n\s*(?=")', r'\1,\n', fixed_content)
                    
                    # More aggressive fix - replace all newlines between properties with commas
                    fixed_content = re.sub(r'"([^"]+)"\s*:\s*([^,\n]+)\s*\n\s*"', r'"\1": \2,\n"', fixed_content)
                    
                    # Last resort - manually construct valid JSON
                    if '"id":' in fixed_content and '"type":' in fixed_content:
                        try:
                            # Try to extract all properties and rebuild the JSON
                            id_matches = re.findall(r'"id"\s*:\s*"([^"]+)"', fixed_content)
                            type_matches = re.findall(r'"type"\s*:\s*"([^"]+)"', fixed_content)
                            label_matches = re.findall(r'"label"\s*:\s*"([^"]+)"', fixed_content)
                            
                            # If we have enough data, construct a minimal valid tree
                            if len(id_matches) > 0 and len(type_matches) > 0 and len(label_matches) > 0:
                                logging.warning("Constructing minimal valid tree from extracted properties")
                                
                                # Create a root node
                                root_node = {
                                    "id": "root",
                                    "type": "goal",
                                    "label": "Security Threats",
                                    "children": []
                                }
                                
                                # Add attack nodes for each threat type
                                threat_types = set()
                                for i, type_val in enumerate(type_matches):
                                    if type_val == "attack" and i < len(label_matches):
                                        threat_type = label_matches[i].split()[0] if len(label_matches[i].split()) > 0 else "Unknown"
                                        if threat_type not in threat_types:
                                            threat_types.add(threat_type)
                                            attack_node = {
                                                "id": f"attack{len(threat_types)}",
                                                "type": "attack",
                                                "label": label_matches[i],
                                                "children": []
                                            }
                                            root_node["children"].append(attack_node)
                                
                                tree_data = {"nodes": [root_node]}
                                return {
                                    "attack_tree": tree_data,
                                    "markdown": self.convert_tree_to_mermaid(tree_data)
                                }
                        except Exception as e:
                            logging.error(f"Failed to construct minimal valid tree: {str(e)}")
                    
                    try:
                        tree_data = json.loads(fixed_content)
                    except json.JSONDecodeError as e:
                        logging.error(f"JSON parsing still failed after fixes: {str(e)}")
                        logging.error(f"Fixed content: {fixed_content[:200]}...")
                        
                        # Create a default tree structure
                        tree_data = {
                            "nodes": [
                                {
                                    "id": "root",
                                    "type": "goal",
                                    "label": "Security Threats",
                                    "children": [
                                        {
                                            "id": "attack1",
                                            "type": "attack",
                                            "label": "Spoofing Threats",
                                            "children": [
                                                {
                                                    "id": "vuln1",
                                                    "type": "vulnerability",
                                                    "label": "Authentication vulnerabilities"
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                
                # Ensure the basic structure exists
                if "nodes" not in tree_data:
                    tree_data = {"nodes": []}
                
                # Validate and fix the tree structure
                if not self.validate_tree_structure(tree_data):
                    logging.warning("Invalid tree structure received, attempting to fix...")
                    tree_data = self.fix_tree_structure(tree_data)
                
                # Convert to Mermaid diagram
                mermaid_diagram = self.convert_tree_to_mermaid(tree_data)
                
                return {
                    "attack_tree": tree_data,
                    "markdown": mermaid_diagram,
                    "total_paths": tree_data.get('total_paths', 0)
                }
                
            except json.JSONDecodeError as json_err:
                logging.error(f"JSON parsing error: {str(json_err)}")
                logging.error(f"Response content: {response_content[:200]}...")
                raise ValueError(f"Failed to parse OpenAI response as JSON: {str(json_err)}")
            
        except Exception as e:
            logging.error(f"Error generating attack tree: {str(e)}")
            # Return a properly formatted error response with more detail
            error_message = str(e)
            error_tree = {
                "nodes": [
                    {
                        "id": "error",
                        "type": "goal",
                        "label": f"Error generating attack tree: {error_message}"
                    }
                ]
            }
            error_mermaid = f"graph TD\n    error[\"{error_message}\"]"
            return {
                "attack_tree": error_tree,
                "markdown": error_mermaid
            }

    def fix_tree_structure(self, tree_data):
        """
        Attempt to fix invalid tree structures by ensuring proper node hierarchy.
        """
        fixed_nodes = []
        
        # Create a root node if none exists
        root_exists = any(node.get("type") == "goal" for node in tree_data.get("nodes", []))
        if not root_exists:
            fixed_nodes.append({
                "id": "root",
                "type": "goal",
                "label": "Security Threats",
                "children": []
            })
        
        # Process existing nodes
        for node in tree_data.get("nodes", []):
            if "id" not in node:
                node["id"] = f"node_{len(fixed_nodes)}"
            if "type" not in node:
                node["type"] = "attack"  # Default to attack type
            if "label" not in node:
                node["label"] = "Unnamed Node"
            fixed_nodes.append(node)
        
        return {"nodes": fixed_nodes}

    def validate_tree_structure(self, tree_data):
        """
        Validate the tree structure to ensure it meets the frontend requirements.
        """
        try:
            # Check if the tree has a nodes array
            if not isinstance(tree_data, dict) or "nodes" not in tree_data:
                logging.error("Tree data missing 'nodes' array")
                return False
                
            # Check if there's at least one root node
            if not tree_data["nodes"] or not isinstance(tree_data["nodes"], list):
                logging.error("Tree data has empty or invalid 'nodes' array")
                return False
                
            # Validate each node in the tree
            for node in self._get_all_nodes(tree_data["nodes"]):
                # Check required fields
                if not all(key in node for key in ["id", "type", "label"]):
                    logging.error(f"Node missing required fields: {node}")
                    return False
                    
                # Validate node type
                if node["type"] not in ["goal", "attack", "vulnerability"]:
                    logging.error(f"Invalid node type: {node['type']}")
                    return False
                    
            return True
            
        except Exception as e:
            logging.error(f"Error validating tree structure: {str(e)}")
            return False
            
    def _get_all_nodes(self, nodes):
        """
        Helper method to get all nodes in the tree recursively.
        """
        all_nodes = []
        
        def collect_nodes(node_list):
            for node in node_list:
                all_nodes.append(node)
                if "children" in node and node["children"]:
                    collect_nodes(node["children"])
                    
        collect_nodes(nodes)
        return all_nodes

    def generate_attack_tree(self, threat_model_result, assessment_id=None):
        """
        Generate attack tree based on threat model results.
        """
        logging.info("Generating attack tree")
        
        # Create the prompt using threat model results
        prompt = self.create_attack_tree_prompt(threat_model_result, assessment_id)
        
        # Get the attack tree data
        result = self.get_attack_tree(prompt)
        
        # Check if result is a string (error message) or a dictionary
        if isinstance(result, str):
            return {
                "markdown": f"mermaid\n{result}\n"
            }
        
        return result
