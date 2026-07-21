import json
import logging
import os

_STORAGE_DIR = os.environ.get('STORAGE_PATH', 'storage')
from llm.openai_module import OpenAIHandler
from rag.rag_handler import PromptManager
from core.threat_filter import ThreatFilterEngine
from utils.config import get_threat_filter_config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ThreatModelingHandler:
    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        self.client = openai_handler.client
        self.last_generated_prompt = None  # Store the last generated prompt
        self.prompt_manager = PromptManager()

    def create_threat_model_prompt(self, app_type, authentication, internet_facing, sensitive_data, app_input, secbugs="", custom_prompt="", org_context="", assessment_id=None, security_context=None, mcp_context=""):
        """
        Create a prompt for generating a threat model using the selected methodology.
        """
        # Ensure custom_prompt is a string
        if custom_prompt is None:
            custom_prompt = ""
        
        # Log the custom prompt for debugging
        logging.info(f"Custom prompt received in create_threat_model_prompt: '{custom_prompt[:100]}...'")
        
        # Get methodology from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            try:
                methodology = self._get_methodology_from_details(assessment_id)
                logging.info(f"Using threat modeling methodology from details.json: {methodology}")
            except ValueError as e:
                # Re-raise the error to be handled by the caller
                raise ValueError(f"Failed to get methodology: {str(e)}")
        else:
            # If no assessment_id is provided, this is likely a direct call not through the API
            # In this case, we need to throw an error as we can't determine the methodology
            error_msg = "Assessment ID is required to determine the threat modeling methodology"
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        # Get the appropriate threat model prompt template based on methodology
        prompt_key = "pasta_threat_model" if methodology == "PASTA" else "threat_model"
        prompt_data = self.prompt_manager.get_prompt(prompt_key)
        
        # Add stronger JSON formatting instructions for Bedrock
        json_instructions = ""
        if self.openai_handler.method == 'BEDROCK':
            json_instructions = """
IMPORTANT: You MUST respond with valid, properly formatted JSON that follows the exact structure shown in the example below.
Your entire response must be parseable as JSON. Do not include any explanatory text outside the JSON structure.
The JSON must include the keys "threat_model" and "improvement_suggestions" exactly as shown.
"""
        
        # Format security context from Stage 2 RAG into labelled sections
        _label_map = {
            "authentication":          "Authentication & Identity",
            "data_flows":              "Data Flows & Trust Boundaries",
            "sensitive_data":          "Sensitive Data & Storage",
            "access_control":          "Access Control & Privileges",
            "input_handling":          "Input Handling & Validation",
            "external_integrations":   "External Integrations",
            "audit_logging":           "Logging & Audit",
            "secrets_config":          "Configuration & Secrets",
            "spoofing_context":        "Spoofing Surface",
            "tampering_context":       "Tampering Surface",
            "repudiation_context":     "Repudiation Surface",
            "info_disclosure_context": "Information Disclosure Surface",
            "dos_context":             "Denial of Service Surface",
            "privilege_context":       "Privilege Escalation Surface",
            "app_decomposition":       "Application Decomposition",
            "threat_analysis":         "Threat Analysis Context",
            "vulnerability_analysis":  "Vulnerability Context",
        }
        security_section = ""
        if security_context:
            parts = []
            for key, ctx in security_context.items():
                label = _label_map.get(key, key.replace('_', ' ').title())
                parts.append(f"[{label}]\n{ctx}")
            security_section = "\n\n".join(parts)

        # Build methodology-specific self-review checklist for CoT
        if methodology == 'PASTA':
            self_review_checklist = """SELF-REVIEW CHECKLIST — Reason through this internally before generating the final JSON:
□ All relevant PASTA stages are represented (decomposition, threat analysis, vulnerability analysis, attack modeling, risk/impact)
□ Business risk types cover financial, reputational, operational, and compliance dimensions
□ All external APIs, payment flows, and third-party integrations have associated threats
□ Trust boundary violations between microservices/services are captured
□ Threat actors (internal, external, supply chain) are represented across scenarios
□ Threats from the security context above that are not yet covered are included
□ No threat flags gateway-injected headers as attacker-controllable
□ Every threat scenario names a concrete entry point and specific sensitive asset
□ No near-duplicate scenarios across different PASTA stages

After this internal review, output a comprehensive threat model addressing any identified gaps.
Your response must be ONLY the JSON object — no text outside the JSON structure."""
        else:
            self_review_checklist = """SELF-REVIEW CHECKLIST — Reason through this internally before generating the final JSON:
□ All 6 STRIDE categories are represented (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
□ Authentication flows include token theft, session hijacking, and credential stuffing scenarios
□ Every external integration and third-party API has at least one associated threat
□ Data-in-transit and data-at-rest threats are both present
□ Input validation and injection threats (SQL, command, deserialization) are covered
□ Privilege escalation paths identified in the security context above are addressed
□ Threats specific to the application type and sensitive data handled are included
□ No threat flags gateway-injected headers (x-user-id, x-device-id, x-tenant-id, x-request-id) as attacker-controllable
□ No threat assumes the attacker bypasses CDN/WAF-layer rate limiting
□ Every threat names a specific entry point, not just a generic category
□ Every threat references specific sensitive data from this domain (fintech: UPI, KYC, CIBIL, loan data)
□ No two threats describe the same attack path with only surface wording differences

After this internal review, output a comprehensive threat model addressing any identified gaps.
Your response must be ONLY the JSON object — no text outside the JSON structure."""

        mcp_section = ("MCP SECURITY INTELLIGENCE:\n" + mcp_context) if mcp_context else ""

        # Build false-positive filter and quality blocks from admin config
        _filter_cfg = get_threat_filter_config()
        _filter_engine = ThreatFilterEngine(self.openai_handler, _filter_cfg)
        self._filter_cfg = _filter_cfg
        self._filter_engine = _filter_engine
        infra_block = _filter_engine.build_infra_context_block() if _filter_cfg.get('enabled', True) else ""
        fp_filter_block = _filter_engine.build_fp_filter_block() if _filter_cfg.get('enabled', True) else ""
        quality_block = _filter_engine.build_quality_requirements_block() if _filter_cfg.get('enabled', True) else ""

        # Store the prompt being generated
        self.last_generated_prompt = f"""
{json_instructions}
{prompt_data.system_context} {prompt_data.task}

ORGANIZATION SECURITY CONTEXT:
{org_context}

{prompt_data.instructions}

APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
CODE SUMMARY, README CONTENT, AND APPLICATION DESCRIPTION:
{app_input}
Existing and reported security vulnerabilities: {secbugs}, only use the KEY like SECBUG-1 for refrencing the security issues, and only reference the SECBUGs in the provided list, make sure to consider the status of the secbug, if the secbug is in Done status it means it is closed, hence give more priority to the ones which are in to do or in progress state. Also, consider the priority of the secbug which is nothing but the severity defined by security engineers, make sure it is not a sample data.

SECURITY-FOCUSED CONTEXT (targeted document analysis by domain):
{security_section}

{infra_block}

{fp_filter_block}

{quality_block}

{mcp_section}

ADDITIONAL CONTEXT AND REQUIREMENTS:
{custom_prompt}

{self_review_checklist}

Example of expected JSON response format:
{json.dumps(prompt_data.format.get("example", {}), indent=2)}
"""
        return self.last_generated_prompt

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
            # Look for the first occurrence of '{'
            json_start = text.find('{')
            if json_start >= 0:
                text = text[json_start:]
        
        # If the text ends with a non-JSON character, try to find the end of the JSON
        if text and text[-1] not in ['}', ']']:
            # Look for the last occurrence of '}'
            json_end = text.rfind('}')
            if json_end >= 0:
                text = text[:json_end+1]
        
        # Remove any trailing commas before closing brackets (common JSON parsing error)
        text = text.replace(",}", "}")
        text = text.replace(",]", "]")
        
        # Remove any comments (which are not valid JSON)
        import re
        text = re.sub(r'//.*?\n', '\n', text)  # Remove single-line comments

        # Strip raw control characters that are invalid in JSON strings (keep \t, \n, \r)
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)

        logging.debug(f"Cleaned JSON text: {text[:100]}..." if len(text) > 100 else f"Cleaned JSON text: {text}")
        return text
        
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
    
    def json_to_markdown(self, threat_model, improvement_suggestions, assessment_id=None):
        """
        Convert JSON threat model to Markdown for display.
        """
        markdown_output = "\n\n"
        
        # Determine which methodology was used based on details.json
        is_pasta = False
        if assessment_id:
            methodology = self._get_methodology_from_details(assessment_id)
            is_pasta = methodology == 'PASTA'
        else:
            # Fallback to the old method if assessment_id is not provided
            if threat_model and ("Business Risk Type" in threat_model[0] or "Business Impact" in threat_model[0]):
                is_pasta = True
        
        # Start the markdown table with appropriate headers based on methodology
        if is_pasta:
            # Check if it's the new PASTA format with Business Risk Type and PASTA Stage
            if threat_model and "Business Risk Type" in threat_model[0] and "PASTA Stage" in threat_model[0]:
                markdown_output += "| Threat Type | Scenario | Business Risk Type | PASTA Stage | Potential Impact |\n"
                markdown_output += "|----------------|----------|-------------------|-------------|------------------|\n"
                
                # Fill the table rows with the new PASTA threat model data
                for threat in threat_model:
                    # Handle Business Risk Type which can be an array
                    business_risk_types = threat.get('Business Risk Type', '')
                    if isinstance(business_risk_types, list):
                        business_risk_str = ", ".join(business_risk_types)
                    else:
                        business_risk_str = str(business_risk_types)

                    markdown_output += f"| {threat.get('Threat Type', '')} | {threat.get('Scenario', '')} | {business_risk_str} | {threat.get('PASTA Stage', '')} | {threat.get('Potential Impact', '')} |\n"
            else:
                # STRIDE format with Business Impact and Attack Vector
                markdown_output += "| Threat Type | Scenario | Business Impact | Attack Vector |\n"
                markdown_output += "|-------------|----------|-----------------|---------------|\n"

                # Fill the table rows with the STRIDE threat model data
                for threat in threat_model:
                    markdown_output += f"| {threat.get('Threat Type', '')} | {threat.get('Scenario', '')} | {threat.get('Business Impact', '')} | {threat.get('Attack Vector', '')} |\n"
        else:
            # STRIDE format
            markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
            markdown_output += "|-------------|----------|------------------|\n"

            # Fill the table rows with the STRIDE threat model data
            for threat in threat_model:
                markdown_output += f"| {threat.get('Threat Type', '')} | {threat.get('Scenario', '')} | {threat.get('Potential Impact', '')} |\n"
        
        markdown_output += "\n\n## Improvement Suggestions\n\n"
        for suggestion in improvement_suggestions:
            markdown_output += f"- {suggestion}\n"
        
        return markdown_output

    def get_threat_model(self, prompt):
        """
        Get threat model from the LLM response.
        """
        method = self.openai_handler.method
        logging.info(f"Generating threat model using {method}")

        try:
            # Prepare system message based on provider
            system_message = "You are a helpful assistant designed to output JSON."
            if method == 'BEDROCK':
                system_message = "You are a helpful assistant designed to output JSON. Your response must be valid, parseable JSON with no additional text, markdown formatting, or explanations outside the JSON structure."

            # Prepare common parameters
            params = {
                "model": self.openai_handler.model,
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 16000
            }

            # Add provider-specific parameters
            if method == 'OPENAI':
                params["response_format"] = {"type": "json_object"}
                logging.info("Using OpenAI-specific parameters")
            elif method == 'BEDROCK':
                # Bedrock might not support response_format, so we don't add it
                logging.info("Using Bedrock-compatible parameters")

            # Make the API call — log full request signature to aid prod debugging
            prompt_chars = len(prompt)
            logging.info(
                f"[THREAT_MODEL] Sending request — method={method}, model={self.openai_handler.model}, "
                f"max_tokens={params['max_tokens']}, prompt_chars={prompt_chars} (~{prompt_chars // 4} tokens est)"
            )
            response = self.openai_handler.client.chat.completions.create(**params)
            if hasattr(response, 'usage') and response.usage:
                self._last_usage = (response.usage.prompt_tokens, response.usage.completion_tokens)
            else:
                self._last_usage = None
            
            # Log the raw response for debugging
            logging.debug(f"Raw response from {method}: {response}")
            
            # Extract and parse the response content
            finish_reason = response.choices[0].finish_reason
            if finish_reason == "length":
                logging.warning("Threat model response was truncated by token limit — output may be incomplete (only first STRIDE categories). Consider reducing app_input size.")
            response_text = response.choices[0].message.content
            logging.info(f"Response content length: {len(response_text)}")
            logging.debug(f"Response content preview: {response_text[:200]}...")
            
            # Clean the response text to handle potential formatting issues
            cleaned_text = self.clean_json_response(response_text)
            
            # Try to parse the JSON response
            try:
                try:
                    response_content = json.loads(cleaned_text, strict=False)
                    logging.info("Successfully parsed JSON response")
                except json.JSONDecodeError as je:
                    logging.warning(f"json.loads failed ({je}), attempting json_repair fallback")
                    from json_repair import repair_json
                    response_content = json.loads(repair_json(cleaned_text))
                    logging.info("Successfully parsed JSON response via json_repair")

                # Validate the response structure
                if "threat_model" not in response_content or "improvement_suggestions" not in response_content:
                    logging.warning("Response missing required fields, attempting to fix structure")
                    # Try to fix the structure if possible
                    if not response_content.get("threat_model"):
                        response_content["threat_model"] = []
                    if not response_content.get("improvement_suggestions"):
                        response_content["improvement_suggestions"] = []

                return response_content

            except Exception as je:
                logging.error(f"Failed to parse JSON response even after repair: {str(je)}")
                logging.error(f"Response was: {response_text}")
                raise
            
        except Exception as e:
            error_type = type(e).__name__
            status_code = getattr(e, 'status_code', None)
            error_body = getattr(e, 'body', None)
            error_detail = str(e)
            logging.error(f"[THREAT_MODEL] {error_type} from {method}: {error_detail}")
            if status_code:
                logging.error(f"[THREAT_MODEL] HTTP status: {status_code}")
            if error_body:
                logging.error(f"[THREAT_MODEL] Error body: {error_body}")
            logging.error(
                f"[THREAT_MODEL] Request params at failure — model={self.openai_handler.model}, "
                f"max_tokens={self.openai_handler.max_output_tokens}, prompt_chars={len(prompt)}"
            )
            error_msg = f"{error_type}: {error_detail}"
            if status_code:
                error_msg = f"HTTP {status_code} — {error_detail}"
            return {
                "threat_model": [
                    {
                        "Threat Type": "Error",
                        "Scenario": f"Failed to generate threat model with {method}: {error_msg}",
                        "Potential Impact": "Unable to assess security threats"
                    }
                ],
                "improvement_suggestions": [
                    "Try again with a more detailed application description",
                    "Check API key and connection",
                    f"Verify {method} configuration and model compatibility"
                ]
            }

    def generate_threat_model(self, app_type, authentication, internet_facing, sensitive_data, app_input, secbugs="", custom_prompt="", org_context="", assessment_id=None, security_context=None, mcp_context=""):
        """
        Generate a threat model based on the provided inputs.
        """
        logging.info("Generating threat model")
        logging.info(f"Custom prompt received in generate_threat_model: '{custom_prompt[:100]}...'")

        # Create the prompt
        prompt = self.create_threat_model_prompt(
            app_type,
            authentication,
            internet_facing,
            sensitive_data,
            app_input,
            secbugs,
            custom_prompt,
            org_context,
            assessment_id,
            security_context,
            mcp_context,
        )
        
        # Get the threat model
        response = self.get_threat_model(prompt)
        if assessment_id and getattr(self, '_last_usage', None):
            try:
                from utils.storage import accumulate_pipeline_cost
                accumulate_pipeline_cost(assessment_id, 'threat_model', self._last_usage[0], self._last_usage[1], self.openai_handler.model)
            except Exception:
                pass

        # Critic pass: filter FPs, deduplicate, improve quality
        critic_result = None
        _filter_cfg = getattr(self, '_filter_cfg', {})
        _filter_engine = getattr(self, '_filter_engine', None)
        if (
            _filter_engine is not None
            and _filter_cfg.get('enabled', True)
            and _filter_cfg.get('criticPassEnabled', True)
            and response.get('threat_model')
        ):
            try:
                methodology = None
                if assessment_id:
                    try:
                        methodology = self._get_methodology_from_details(assessment_id)
                    except Exception:
                        methodology = 'STRIDE'
                critic_result = _filter_engine.run_critic_pass(
                    response['threat_model'], methodology=methodology or 'STRIDE'
                )
                response['threat_model'] = critic_result['filtered_threats']
            except Exception as e:
                logging.warning(f"[CRITIC] Critic pass error (non-fatal): {e}")
        
        # Normalize Confidence field — backfill missing/invalid values to 'Medium'
        _valid_confidence = {'High', 'Medium', 'Low'}
        for t in response.get('threat_model', []):
            if isinstance(t, dict) and t.get('Confidence') not in _valid_confidence:
                t['Confidence'] = 'Medium'

        # Extract the threat model and improvement suggestions
        threat_model = response.get("threat_model", [])
        improvement_suggestions = response.get("improvement_suggestions", [])

        # Convert to markdown, passing the assessment_id
        markdown = self.json_to_markdown(threat_model, improvement_suggestions, assessment_id)

        # raw_response must reflect the post-critic filtered list so that any downstream
        # consumer (DREAD, mitigations, attack tree) always operates on the same canonical
        # threat set, regardless of whether they read from the return value or from storage.
        return {
            "raw_response": {
                "threat_model": threat_model,
                "improvement_suggestions": improvement_suggestions,
            },
            "threat_model": threat_model,
            "improvement_suggestions": improvement_suggestions,
            "markdown": markdown,
            "critic_pass": critic_result,
        }
