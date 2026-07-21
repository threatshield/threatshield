import json
import logging
import os

_STORAGE_DIR = os.environ.get('STORAGE_PATH', 'storage')
import re
import time
import datetime
import concurrent.futures
from rag.rag_handler import PromptManager
from utils.storage import StorageHandler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DiagramGenerator:
    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        self.client = openai_handler.client
        self.prompt_manager = PromptManager()
        self.storage_handler = StorageHandler()

    def create_diagram_prompt(self, threat_model_result, diagram_type):
        """
        Create prompt for generating diagrams using threat model data.
        """
        prompt_data = self.prompt_manager.get_prompt(diagram_type)
        
        # Extract threats from threat model result
        threats = threat_model_result.get('threat_model', [])
        
        # Group threats by type for better organization
        threat_types = {}
        for threat in threats:
            threat_type = threat.get('Threat Type', '')
            if threat_type not in threat_types:
                threat_types[threat_type] = []
            threat_types[threat_type].append(threat)
        
        # Format threats for diagram generation
        threat_descriptions = []
        canonical_scenarios = []
        for threat_type, type_threats in threat_types.items():
            for threat in type_threats:
                scenario = threat.get('Scenario', '')
                threat_descriptions.append(f"- Scenario: {scenario}")
                if scenario:
                    canonical_scenarios.append(scenario)

        formatted_threats = "\n\n".join(threat_descriptions)

        # Explicit scenario list for verbatim mapping constraint
        scenario_json = json.dumps(canonical_scenarios, indent=2)
        mapping_constraint = (
            "\n\nMAPPING CONSTRAINT:\n"
            "The 'mapping' object keys MUST be copied VERBATIM from this exact list — "
            "do not paraphrase, shorten, or rephrase any scenario string:\n"
            f"{scenario_json}\n"
            "Every scenario in this list must appear as a key in 'mapping'. "
            "Use the exact string, including punctuation and capitalisation."
        )

        prompt = f"""
{prompt_data.system_context}

{prompt_data.task}

{prompt_data.format}

{prompt_data.instructions}
{mapping_constraint}

Below are the identified threats to consider:
{formatted_threats}

Please generate a diagram that clearly shows the potential attack points based on these threats.
"""
        return prompt

    def get_dfd_basic_system_message(self):
        """Get system message for basic Data Flow Diagram generation (intro, diagram, description)."""
        return """You are a security architect specializing in creating detailed system flow diagrams.
        Your response must be structured in JSON format with three sections:
        1. intro: A brief introduction explaining what the diagram represents
        2. diagram: The mermaid diagram code (without ```mermaid markers)
        3. description: A detailed explanation of the diagram, including attack points and security implications
        
        Example response format:
        {
            "intro": "This diagram illustrates the data flow...",
            "diagram": "graph TD\\n    A[Client] -->|Request| B[API Gateway]...",
            "description": "The diagram shows potential attack points..."
        }
        """

    def get_dfd_details_system_message(self):
        """Get system message for detailed Data Flow Diagram generation (reactflow, components, mapping)."""
        return """You are a security architect specializing in creating detailed system flow diagrams.
        Your response must be structured in JSON format with four sections, consider the diagram as your input for the same:
        1. reactflow: React Flow JSON as a plain JSON object (NOT a string) with keys "nodes" and "edges".
           Each node must have: "id" (string), "type" (one of: Client, API Gateway, Microservice, Database,
           Infrastructure, External / Third-Party System), "data" (object with "label"), "position" (object with x, y).
           Each edge must have: "id", "source", "target", "label".
           Mapping of type should be precise and only to one component per node.
        2. components: Array of all the node labels identified in the reactflow of the DFD.
        3. mapping: Create a mapping between the threats identified in the threat model and the components listed above in DFD. Output should be a JSON object where each key is a threat scenario string and its value is an array of one or more components affected by that threat. The user prompt includes a MAPPING CONSTRAINT section with the exact scenario strings — copy each key VERBATIM from that list. Do not paraphrase, summarise, or rephrase any scenario. Every scenario in the constraint list must be present as a key. Ensure every scenario maps to at least one component.
        4. trust_boundaries: Array of trust boundary zone objects. Each object has:
           - "name": descriptive zone name (e.g. "External / Internet Zone", "DMZ / Perimeter",
             "Internal Application Zone", "Data Zone", "Third-Party Zone")
           - "components": array of component labels (from the "components" list) in this zone.
           Every component must appear in exactly one boundary.

        Example response format:
        {
            "reactflow": {
                "nodes": [{"id": "client", "type": "Client", "data": {"label": "Web Browser / Mobile Client"}, "position": {"x": 0, "y": 0}}],
                "edges": [{"id": "e-client-cdn", "source": "client", "target": "cdn", "label": "HTTPS"}]
            },
            "components": ["User Client", "Auth Service", "Payment Gateway"],
            "mapping": {"threat content (Exactly same as the scenario parameter provided in threats)": ["Component1", "Component2"]},
            "trust_boundaries": [
                {"name": "External / Internet Zone", "components": ["Web Browser / Mobile Client"]},
                {"name": "Internal Application Zone", "components": ["Auth Service"]},
                {"name": "Data Zone", "components": ["Payment Gateway"]}
            ]
        }
        """

    def get_mermaid_system_message(self):
        """Get system message for Mermaid Flow Diagram generation."""
        return """You are a security architect specializing in creating detailed system flow diagrams.
        Your response must be structured in JSON format with three sections:
        1. intro: A brief introduction explaining what the diagram represents
        2. diagram: The mermaid diagram code (without ```mermaid markers)
        3. description: A detailed explanation of the diagram, including attack points and security implications
        
        Example response format:
        {
            "intro": "This diagram illustrates the system flow...",
            "diagram": "graph TD\\n    A[Client] -->|Request| B[API Gateway]...",
            "description": "The diagram shows potential attack points..."
        }
        """

    def clean_json_response(self, text):
        """
        Clean the response text to handle potential JSON formatting issues.
        """
        # Remove any markdown code block indicators
        text = text.replace("```json", "").replace("```", "")
        
        # Trim whitespace
        text = text.strip()
        
        # If the text starts with a non-JSON character, try to find the start of the JSON
        if text and text[0] not in ['{', '[']:
            json_start = text.find('{')
            if json_start >= 0:
                text = text[json_start:]
        
        # If the text ends with a non-JSON character, try to find the end of the JSON
        if text and text[-1] not in ['}', ']']:
            json_end = text.rfind('}')
            if json_end >= 0:
                text = text[:json_end+1]
        
        # Remove any trailing commas before closing brackets
        text = text.replace(",}", "}")
        text = text.replace(",]", "]")
        
        # Remove any comments
        text = re.sub(r'//[^\n]*\n', '\n', text)
        
        logging.debug(f"Cleaned JSON text: {text[:100]}..." if len(text) > 100 else f"Cleaned JSON text: {text}")
        return text

    def _store_error_response(self, assessment_id, raw_response, error, diagram_type):
        """Persist the raw LLM response and error to a JSON file for debugging."""
        if not (assessment_id and raw_response):
            return
        try:
            error_file_path = os.path.join(_STORAGE_DIR, assessment_id, f'{diagram_type}_error.json')
            os.makedirs(os.path.dirname(error_file_path), exist_ok=True)
            with open(error_file_path, 'w') as f:
                json.dump({
                    "error": str(error),
                    "raw_response": raw_response,
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
                }, f, indent=2)
            logging.info(f"Stored error response in {error_file_path}")
        except Exception as store_error:
            logging.error(f"Failed to store error response: {store_error}")

    def _llm_call_with_retry(self, params):
        """Make an LLM API call with up to 3 attempts and exponential back-off."""
        for attempt in range(1, 4):
            try:
                response = self.client.chat.completions.create(**params)
                if hasattr(response, 'usage') and response.usage:
                    prev = getattr(self, '_last_usage', (0, 0)) or (0, 0)
                    self._last_usage = (prev[0] + response.usage.prompt_tokens, prev[1] + response.usage.completion_tokens)
                return response
            except Exception as e:
                if attempt == 3:
                    raise
                logging.warning(f"Attempt {attempt} failed: {e}. Retrying…")
                time.sleep(2 ** attempt)

    def get_diagram_part(self, prompt, system_message, max_tokens=None, assessment_id=None, diagram_type="data_flow"):
        """
        Get a part of the diagram from LLM with structured response format.
        """
        method = self.openai_handler.method
        logging.info(f"Generating diagram part using {method}")
        if max_tokens is None:
            max_tokens = self.openai_handler.max_output_tokens

        params = {
            "model": self.openai_handler.model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.5,
            "max_tokens": max_tokens,
            # Real DFD generation calls take ~210s on the proxy (observed 200-330s), so a 60s
            # timeout caused every attempt + all retries to time out, storing an empty DFD.
            # 600s matches the default the other (working) analysis modules rely on.
            "timeout": 600
        }
        if method == 'OPENAI':
            params["response_format"] = {"type": "json_object"}

        raw_response = None
        try:
            response = self._llm_call_with_retry(params)
            finish_reason = response.choices[0].finish_reason
            if finish_reason == "length":
                logging.warning(
                    f"[DIAGRAM] Response truncated by token limit (finish_reason=length). "
                    f"Output may be incomplete. model={self.openai_handler.model}, max_tokens={params['max_tokens']}"
                )
            raw_response = response.choices[0].message.content
            return json.loads(self.clean_json_response(raw_response))
        except Exception as e:
            logging.error(f"Error generating diagram part: {e}")
            self._store_error_response(assessment_id, raw_response, e, diagram_type)
            return {}

    def get_diagram(self, prompt, diagram_type="data_flow_diagram", assessment_id=None):
        """
        Get diagram from LLM with structured response format.
        """
        method = self.openai_handler.method
        logging.info(f"Generating diagram using {method}")
        
        try:
            if diagram_type == "data_flow_diagram":
                # First request: Get basic diagram info
                basic_system_message = self.get_dfd_basic_system_message()
                basic_content = self.get_diagram_part(prompt, basic_system_message, assessment_id=assessment_id, diagram_type="data_flow_basic")

                # Second request: Get detailed diagram info
                details_system_message = self.get_dfd_details_system_message()
                # Include the basic diagram when getting details
                details_prompt = f"{prompt}\n\nUse this diagram as input:\n{basic_content.get('diagram', '')}"
                details_content = self.get_diagram_part(details_prompt, details_system_message, assessment_id=assessment_id, diagram_type="data_flow_details")
                
                # Create complete prompts that were actually used
                complete_prompt = f"{basic_system_message}\n\n{prompt}\n\n---\n\n{details_system_message}\n\n{details_prompt}"
                
                # Combine the results
                return {
                    "intro": basic_content.get("intro", ""),
                    "diagram": basic_content.get("diagram", ""),
                    "description": basic_content.get("description", ""),
                    "reactflow": details_content.get("reactflow", ""),
                    "components": details_content.get("components", ""),
                    "mapping": details_content.get("mapping", ""),
                    "trust_boundaries": details_content.get("trust_boundaries", []),
                    "complete_prompt": complete_prompt  # Add the complete prompt
                }
            else:
                # For mermaid diagrams, use the original system message
                system_message = self.get_mermaid_system_message()
                content = self.get_diagram_part(prompt, system_message, assessment_id=assessment_id, diagram_type="mermaid_flow")
                
                # Create complete prompt that was actually used
                complete_prompt = f"{system_message}\n\n{prompt}"
                
                return {
                    "intro": content.get("intro", ""),
                    "diagram": content.get("diagram", ""),
                    "description": content.get("description", ""),
                    "complete_prompt": complete_prompt  # Add the complete prompt
                }
        except json.JSONDecodeError as je:
            logging.error(f"Failed to parse JSON response: {str(je)}")
            # Return error response based on diagram type
            if diagram_type == "data_flow_diagram":
                return {
                    "intro": "Error parsing diagram response",
                    "diagram": "",
                    "reactflow": "",
                    "components": "",
                    "mapping": "",
                    "description": f"Failed to parse response: {str(je)}",
                    "complete_prompt": prompt  # Fallback to original prompt
                }
            else:
                return {
                    "intro": "Error parsing diagram response",
                    "diagram": "",
                    "description": f"Failed to parse response: {str(je)}",
                    "complete_prompt": prompt  # Fallback to original prompt
                }
        except Exception as e:
            error_msg = f"Error generating diagram: {str(e)}"
            logging.error(error_msg)
            return {
                "intro": "Error generating diagram",
                "diagram": "",
                "description": error_msg
            }

    def generate_diagrams(self, threat_model_result, assessment_id,
                          generate_data_flow=True, generate_mermaid=False):
        """
        Generate diagrams and store them in additionalinfo.json.

        Args:
            generate_data_flow: Whether to generate the data flow diagram (default: True).
            generate_mermaid: Whether to generate the mermaid flow diagram (default: False).
        """
        if not generate_data_flow and not generate_mermaid:
            logging.info("No diagrams requested; skipping diagram generation.")
            return

        logging.info(f"Generating diagrams (data_flow={generate_data_flow}, mermaid={generate_mermaid})")

        data_flow_prompt = self.create_diagram_prompt(threat_model_result, "data_flow_diagram") if generate_data_flow else None
        mermaid_flow_prompt = self.create_diagram_prompt(threat_model_result, "mermaid_functional_flow") if generate_mermaid else None

        data_flow = {}
        mermaid_flow = {}

        # ── Stage 1: generate diagram content via the LLM ────────────────────────────
        # On any failure we log and fall through with empty dicts (do NOT abort), so that
        # Stage 2 still persists the diagram fields. This lets the UI distinguish an empty
        # (failed) diagram from one that is still generating.
        try:
            futures = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                if generate_data_flow:
                    futures["data_flow"] = executor.submit(
                        self.get_diagram, data_flow_prompt, "data_flow_diagram", assessment_id
                    )
                if generate_mermaid:
                    futures["mermaid"] = executor.submit(
                        self.get_diagram, mermaid_flow_prompt, "mermaid_functional_flow", assessment_id
                    )
                if "data_flow" in futures:
                    data_flow = futures["data_flow"].result()
                if "mermaid" in futures:
                    mermaid_flow = futures["mermaid"].result()
        except Exception as e:
            logging.error(f"Error generating diagram content (persisting empty diagrams): {str(e)}")

        # ── Stage 2: always persist the diagram fields into additionalinfo.json ───────
        # Populated or empty, preserving other keys. A missing/corrupt existing file is
        # tolerated by starting fresh instead of raising, so this write can never leave
        # the data_flow_diagrams key completely absent.
        additional_info_path = os.path.join(_STORAGE_DIR, assessment_id, 'additionalinfo.json')

        enhanced_info = None
        if os.path.exists(additional_info_path):
            try:
                with open(additional_info_path, 'r') as f:
                    enhanced_info = json.load(f)
            except Exception as e:
                logging.warning(f"Existing additionalinfo.json missing or corrupt; starting fresh: {e}")
        if not isinstance(enhanced_info, dict):
            enhanced_info = {
                "confluenceDoc": None,
                "slackThread": None,
                "meetingTranscript": None,
                "functional_flows": None,
                "third_party_integrations": None
            }

        # Update only the requested diagram fields (preserving field names/shape)
        if generate_data_flow:
            enhanced_info["data_flow_diagrams"] = {
                "intro": data_flow.get("intro", ""),
                "diagram": data_flow.get("diagram", ""),
                "reactflow": data_flow.get("reactflow", ""),
                "components": data_flow.get("components", ""),
                "mapping": data_flow.get("mapping", ""),
                "description": data_flow.get("description", ""),
                "trust_boundaries": data_flow.get("trust_boundaries", []),
            }
        if generate_mermaid:
            enhanced_info["mermaid_flow_diagrams"] = {
                "intro": mermaid_flow.get("intro", ""),
                "diagram": mermaid_flow.get("diagram", ""),
                "description": mermaid_flow.get("description", "")
            }

        os.makedirs(os.path.dirname(additional_info_path), exist_ok=True)
        with open(additional_info_path, 'w') as f:
            json.dump(enhanced_info, f, indent=2)

        logging.info(f"Successfully updated additionalinfo.json for assessment {assessment_id}")

        # ── Stage 3: best-effort side effects (must never fail the diagram write above) ─
        # Store the prompts used for diagram generation while preserving existing prompts.
        try:
            prompts_data = self.storage_handler.get_prompts(assessment_id) or {"prompts": {}}

            if generate_data_flow:
                prompts_data["prompts"]["data_flow_diagram"] = {
                    "prompt": data_flow.get("complete_prompt", data_flow_prompt),
                    "diagram_type": "data_flow_diagram"
                }
            if generate_mermaid:
                prompts_data["prompts"]["mermaid_flow_diagram"] = {
                    "prompt": mermaid_flow.get("complete_prompt", mermaid_flow_prompt),
                    "diagram_type": "mermaid_functional_flow"
                }

            self.storage_handler.save_prompts(assessment_id, prompts_data["prompts"])
        except Exception as e:
            logging.warning(f"Failed to save diagram prompts (non-fatal): {e}")

        # Accumulate pipeline cost as a best-effort side effect.
        if getattr(self, '_last_usage', None):
            try:
                from utils.storage import accumulate_pipeline_cost
                accumulate_pipeline_cost(assessment_id, 'diagram', self._last_usage[0], self._last_usage[1], self.openai_handler.model)
            except Exception:
                pass
