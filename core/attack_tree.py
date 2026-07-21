import json
import logging
import os

_STORAGE_DIR = os.environ.get('STORAGE_PATH', 'storage')
import re
import time
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
        details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
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
        
        # Get the appropriate attack tree prompt template based on methodology
        prompt_key = "pasta_attack_tree" if methodology == "PASTA" else "attack_tree"
        prompt_data = self.prompt_manager.get_prompt(prompt_key)
        
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

    def _build_system_message(self):
        """Build the system message for attack tree generation."""
        base = (
            "You are a Security Architect and expert. Create an attack tree structure in JSON format. "
            "IMPORTANT: Your response must be ONLY valid JSON, with no additional text or explanation. "
            "Ensure all JSON strings are properly escaped and the structure is valid. "
            "Always use commas between properties and array elements."
        )
        if self.openai_handler.method == 'BEDROCK':
            base += (
                " Do not include markdown code blocks, explanations, "
                "or any text outside the JSON structure."
            )
        return base

    def _repair_json(self, text):
        """
        Repair common LLM JSON formatting issues.
        Returns the repaired string (may still be invalid if severely malformed).
        """
        # Strip markdown code fences
        text = text.replace("```json", "").replace("```", "").strip()

        # Find the opening brace
        json_start = text.find('{')
        if json_start < 0:
            return text
        text = text[json_start:]

        # Truncate to the last balanced closing brace (handles truncated responses)
        depth = 0
        end_pos = -1
        for i, ch in enumerate(text):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end_pos = i + 1
                    break
        if end_pos > 0:
            text = text[:end_pos]

        # Remove trailing commas before ] or }
        text = re.sub(r',(\s*[}\]])', r'\1', text)
        # Fix missing commas between adjacent string values / objects
        text = re.sub(r'"\s*\n(\s*")', r'",\n\1', text)
        text = re.sub(r'}\s*\n(\s*\{)', r'},\n\1', text)

        return text

    def _parse_tree_response(self, response_content):
        """
        Try to parse the LLM response as a valid attack tree dict.
        Returns tree_data dict on success, raises json.JSONDecodeError on failure.
        """
        repaired = self._repair_json(response_content)
        tree_data = json.loads(repaired)  # raises JSONDecodeError if still broken

        # Ensure total_paths exists
        if 'total_paths' not in tree_data:
            def count_paths(node):
                if not node.get('children'):
                    return 1
                return sum(count_paths(c) for c in node['children'])

            tree_data['total_paths'] = sum(
                count_paths(n) for n in tree_data.get('nodes', [])
            )
        return tree_data

    @staticmethod
    def _default_children():
        return [{
            "id": "attack1",
            "type": "attack",
            "label": "Spoofing Threats",
            "children": [{"id": "vuln1", "type": "vulnerability", "label": "Authentication vulnerabilities"}]
        }]

    @staticmethod
    def _extract_attack_nodes(type_matches, label_matches):
        """Return deduplicated attack nodes extracted from regex matches."""
        seen = set()
        nodes = []
        for i, type_val in enumerate(type_matches):
            if type_val != "attack" or i >= len(label_matches):
                continue
            label = label_matches[i]
            key = (label.split()[0] if label.split() else "Unknown")
            if key not in seen:
                seen.add(key)
                nodes.append({"id": f"attack{len(seen)}", "type": "attack",
                               "label": label, "children": []})
        return nodes

    def _build_fallback_tree(self, response_content):
        """
        Build a minimal tree by extracting node data from a malformed response.
        Falls back to a hardcoded default if extraction yields nothing.
        """
        type_matches = re.findall(r'"type"\s*:\s*"([^"]+)"', response_content)
        label_matches = re.findall(r'"label"\s*:\s*"([^"]+)"', response_content)

        children = self._extract_attack_nodes(type_matches, label_matches)
        if children:
            logging.warning("Constructing minimal tree from extracted properties")
        else:
            logging.warning("No nodes extracted, using hardcoded fallback tree")
            children = self._default_children()

        root_node = {"id": "root", "type": "goal", "label": "Security Threats", "children": children}
        return {"nodes": [root_node]}

    def _finalize_tree(self, tree_data):
        """Validate, fix and convert a parsed tree to the final result dict."""
        if "nodes" not in tree_data:
            tree_data["nodes"] = []
        if not self.validate_tree_structure(tree_data):
            logging.warning("Tree structure invalid after parse, fixing…")
            tree_data = self.fix_tree_structure(tree_data)
        return {
            "attack_tree": tree_data,
            "markdown": self.convert_tree_to_mermaid(tree_data),
            "total_paths": tree_data.get('total_paths', 0)
        }

    def _call_llm(self, params):
        """Make one LLM call and return the stripped response text."""
        response = self.client.chat.completions.create(**params)
        if hasattr(response, 'usage') and response.usage:
            prev = getattr(self, '_last_usage', (0, 0)) or (0, 0)
            self._last_usage = (prev[0] + response.usage.prompt_tokens, prev[1] + response.usage.completion_tokens)
        return response.choices[0].message.content.strip()

    def get_attack_tree(self, prompt):
        """
        Get attack tree from LLM with retry logic, JSON repair, and graceful fallback.
        """
        method = self.openai_handler.method
        logging.info(f"Generating attack tree using {method}")

        params = {
            "model": self.openai_handler.large_output_model,
            "messages": [
                {"role": "system", "content": self._build_system_message()},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 16000
        }
        if method == 'OPENAI':
            params["response_format"] = {"type": "json_object"}

        response_content = None
        last_error = None
        for attempt in range(1, 4):
            try:
                logging.info(f"Attack tree attempt {attempt}/3")
                response_content = self._call_llm(params)
                return self._finalize_tree(self._parse_tree_response(response_content))
            except (json.JSONDecodeError, Exception) as e:
                last_error = e
                logging.warning(f"Attempt {attempt} failed: {e}. "
                                 f"Snippet: {(response_content or '')[:200]}")
                if attempt < 3:
                    time.sleep(2 ** attempt)

        logging.error(f"All 3 attack tree attempts failed. Last error: {last_error}")
        tree_data = self._build_fallback_tree(response_content or "")
        return self._finalize_tree(tree_data)

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
        if assessment_id and getattr(self, '_last_usage', None):
            try:
                from utils.storage import accumulate_pipeline_cost
                accumulate_pipeline_cost(assessment_id, 'attack_tree', self._last_usage[0], self._last_usage[1], self.openai_handler.model)
            except Exception:
                pass
        
        # Check if result is a string (error message) or a dictionary
        if isinstance(result, str):
            return {
                "markdown": f"mermaid\n{result}\n"
            }

        return result
