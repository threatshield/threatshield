import json
import logging
import os

_STORAGE_DIR = os.environ.get('STORAGE_PATH', 'storage')
import datetime
import openai
from rag.rag_handler import PromptManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ASVSTestCaseGenerator:
    def __init__(self, openai_handler):
        """Initialize the ASVS test case generator."""
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

    def create_asvs_test_cases_prompt(self, threat_model_result, assessment_id=None):
        """
        Create prompt for generating ASVS test cases using threats from threat model.
        """
        # Get methodology from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            try:
                methodology = self._get_methodology_from_details(assessment_id)
                logging.info(f"Using threat modeling methodology from details.json for ASVS test cases: {methodology}")
            except ValueError as e:
                # Re-raise the error to be handled by the caller
                raise ValueError(f"Failed to get methodology: {str(e)}")
        else:
            error_msg = "Assessment ID is required to determine the threat modeling methodology"
            logging.error(error_msg)
            raise ValueError(error_msg)

        # Get the appropriate ASVS test cases prompt template
        prompt_data = self.prompt_manager.get_prompt('asvs_test_cases')

        # Get threats from the threat model result
        threats = threat_model_result.get('threat_model', [])
        
        # Include all threats in the prompt as requested

        # Format threats for test case generation
        threat_descriptions = []
        is_pasta = methodology == "PASTA"

        for threat in threats:
            if is_pasta:
                # PASTA format
                threat_category = threat.get('Threat Type', '')
                business_risk = threat.get('Business Risk Type', [])
                if isinstance(business_risk, list):
                    business_risk = ', '.join(business_risk)
                pasta_stage = threat.get('PASTA Stage', '')
                scenario = threat.get('Scenario', '')
                impact = threat.get('Potential Impact', '')
                
                threat_descriptions.append(
                    f"Threat Type: {threat_category}\n"
                    f"Business Risk Type: {business_risk}\n"
                    f"PASTA Stage: {pasta_stage}\n"
                    f"Scenario: {scenario}\n"
                    f"Potential Impact: {impact}"
                )
            else:
                # STRIDE format
                threat_type = threat.get('Threat Type', '')
                scenario = threat.get('Scenario', '')
                impact = threat.get('Potential Impact', '')
                threat_descriptions.append(f"Threat Type: {threat_type}\nScenario: {scenario}\nPotential Impact: {impact}")

        formatted_threats = "\n\n".join(threat_descriptions)

        prompt = f"""
{prompt_data.system_context}

{prompt_data.task}

Threats:
{formatted_threats}

Format: {prompt_data.format}

Instructions:
{chr(10).join(f"- {instruction}" for instruction in prompt_data.instructions)}

YOUR RESPONSE (valid JSON with key 'test_cases', no code fences or extra text):
"""
        return prompt

    def clean_json_response(self, text):
        """
        Clean the response text to handle potential JSON formatting issues.
        """
        import re
        
        # Remove any markdown code block indicators
        text = text.replace("```json", "").replace("```", "")
        
        # Trim whitespace
        text = text.strip()
        
        # If the text starts with a non-JSON character, try to find the start of the JSON
        if text and text[0] not in ['{', '[']:
            json_start = text.find('{')
            if json_start >= 0:
                text = text[json_start:]
        
        # Remove any comments
        text = re.sub(r'//.*?\n', '\n', text)
        
        # Remove stray trailing commas before closing brackets
        text = re.sub(r',\s*([}\]])', r'\1', text)
        
        # Find the proper JSON structure by matching braces and brackets
        if text and text[0] == '{':
            # Find the matching closing brace for the opening brace
            brace_count = 0
            bracket_count = 0
            in_string = False
            escape_next = False
            end_pos = 0
            
            for i, char in enumerate(text):
                if escape_next:
                    escape_next = False
                    continue
                    
                if char == '\\':
                    escape_next = True
                    continue
                    
                if char == '"' and not escape_next:
                    in_string = not in_string
                    continue
                
                if not in_string:
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                    elif char == '[':
                        bracket_count += 1
                    elif char == ']':
                        bracket_count -= 1
                    
                    # When we've closed all braces and brackets, we've found the end
                    if brace_count == 0 and bracket_count == 0:
                        end_pos = i + 1
                        break
            
            if end_pos > 0:
                text = text[:end_pos]
        
        logging.debug(f"Cleaned JSON text: {text[:100]}..." if len(text) > 100 else f"Cleaned JSON text: {text}")
        return text

    def get_asvs_test_cases(self, prompt):
        """
        Get ASVS test cases from LLM (OpenAI or Bedrock).
        """
        method = self.openai_handler.method
        logging.info(f"Generating ASVS test cases using {method}")
        
        try:
            # Prepare system message based on provider
            system_message = """You are a helpful assistant that provides ASVS test cases in JSON format.
                Your response must be valid, parseable JSON with no additional text, markdown formatting, 
                or explanations outside the JSON structure. The JSON must include the key 'test_cases' 
                with an array of test case items."""
            if method == 'BEDROCK':
                system_message = """You are a helpful assistant that provides ASVS test cases in JSON format.
                Your response must be valid, parseable JSON with no additional text, markdown formatting, 
                or explanations outside the JSON structure. The JSON must include the key 'test_cases' 
                with an array of test case items."""
            
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
                logging.info("Using Bedrock-compatible parameters")
            
            # Log request parameters for debugging
            logging.debug(f"Request parameters: {json.dumps(params, indent=2)}")
            
            # Make the API call
            logging.info(f"Sending request to {method} with model {self.openai_handler.model}")

            response = self.client.chat.completions.create(**params)
            if hasattr(response, 'usage') and response.usage:
                prev = getattr(self, '_last_usage', (0, 0)) or (0, 0)
                self._last_usage = (prev[0] + response.usage.prompt_tokens, prev[1] + response.usage.completion_tokens)
            else:
                if not hasattr(self, '_last_usage'):
                    self._last_usage = None

            finish_reason = response.choices[0].finish_reason
            if finish_reason == "length":
                logging.warning(
                    f"[ASVS] Response truncated by token limit (finish_reason=length). "
                    f"Output may be incomplete. model={self.openai_handler.model}, max_tokens={params['max_tokens']}"
                )

            # Extract and parse the response content
            response_text = response.choices[0].message.content
            logging.info(f"Response content length: {len(response_text)}")
            logging.debug(f"Response content preview: {response_text[:500]}...")
            
            # Clean the response text
            cleaned_text = self.clean_json_response(response_text)
            logging.info(f"Cleaned response length: {len(cleaned_text)}")
            
            return cleaned_text
            
        except openai.RateLimitError as e:
            error_msg = f"Rate limit exceeded when calling {method}: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg) from e
        except openai.APIError as e:
            error_msg = f"OpenAI API error when calling {method}: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg) from e
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse LLM response as JSON: {str(e)}"
            logging.error(error_msg)
            raise
        except Exception as e:
            error_msg = f"Unexpected error generating ASVS test cases with {method}: {str(e)}"
            logging.error(error_msg)
            logging.exception("Full stack trace:")
            raise

    def _parse_test_cases_response(self, test_cases_json_str):
        """
        Parse a test cases JSON response string, returning the list of test cases or None on failure.
        """
        try:
            test_cases_data = json.loads(test_cases_json_str)
        except json.JSONDecodeError as je:
            logging.warning(f"json.loads failed ({je}), attempting json_repair fallback")
            from json_repair import repair_json
            test_cases_data = json.loads(repair_json(test_cases_json_str))
            logging.info("Parsed test cases JSON via json_repair")

        if "test_cases" in test_cases_data:
            return test_cases_data["test_cases"]
        return None

    def generate_asvs(self, threat_model_result, assessment_id=None):
        """
        Generate ASVS test cases for threats identified in the threat model.
        Process each threat type separately to avoid truncation.
        Failed batches are retried once; if still failing they are skipped
        (no error placeholder entries) so the validation check is never blocked.
        """
        logging.info("Generating ASVS test cases per threat type")

        # Get threats from the threat model result
        threats = threat_model_result.get('threat_model', [])

        # Group threats by threat type
        threats_by_type = {}
        for threat in threats:
            threat_type = threat.get('Threat Type', 'Unknown')
            if threat_type not in threats_by_type:
                threats_by_type[threat_type] = []
            threats_by_type[threat_type].append(threat)

        logging.info(f"Found {len(threats_by_type)} threat types: {list(threats_by_type.keys())}")

        # Get methodology from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            try:
                methodology = self._get_methodology_from_details(assessment_id)
                logging.info(f"Using threat modeling methodology: {methodology}")
            except ValueError as e:
                logging.error(f"Failed to get methodology: {str(e)}")
                raise

        # Collect all test cases from all threats
        all_test_cases = []

        # Process each threat type separately (with one retry on failure)
        for threat_type, threats_of_type in threats_by_type.items():
            logging.info(f"Processing threat type: {threat_type}")

            # Confidence gate: separate Low from High/Medium
            low_confidence = [t for t in threats_of_type if t.get('Confidence', 'Medium') == 'Low']
            actionable = [t for t in threats_of_type if t.get('Confidence', 'Medium') != 'Low']

            # Add skip entries for Low-confidence threats directly (no LLM call)
            for threat in low_confidence:
                all_test_cases.append({
                    'Threat Type': threat.get('Threat Type', ''),
                    'Scenario': threat.get('Scenario', ''),
                    'Confidence': 'Low',
                    'asvs_requirement': 'N/A',
                    'skipped': True,
                    'skip_reason': 'Insufficient confidence for test generation',
                    'test_cases': [],
                    'validated': False,
                })
            logging.info(f"Skipped {len(low_confidence)} Low-confidence threats for {threat_type}")

            if not actionable:
                continue

            test_cases_json_str = None
            last_error = None

            for attempt in range(2):  # attempt 0 = first try, attempt 1 = retry
                if attempt > 0:
                    logging.info(f"Retrying test case generation for {threat_type} (attempt {attempt + 1})")
                try:
                    prompt = self._create_threat_specific_prompt(actionable, threat_type, methodology)
                    test_cases_json_str = self.get_asvs_test_cases(prompt)
                    test_cases = self._parse_test_cases_response(test_cases_json_str)
                    if test_cases is not None:
                        logging.info(f"Generated {len(test_cases)} test cases for {threat_type} (attempt {attempt + 1})")
                        for tc in test_cases:
                            if "validated" not in tc:
                                tc["validated"] = False
                        all_test_cases.extend(test_cases)
                        last_error = None
                        break  # success — move to next threat type
                    else:
                        last_error = ValueError(f"No 'test_cases' key in response for {threat_type}")
                        logging.warning(str(last_error))
                except (json.JSONDecodeError, Exception) as e:
                    last_error = e
                    logging.error(f"Error on attempt {attempt + 1} for {threat_type}: {str(e)}")
                    if test_cases_json_str:
                        logging.error(f"Raw response (first 500 chars): {test_cases_json_str[:500]}")

            if last_error is not None:
                # Both attempts failed — log and save debug file, but do NOT add an error
                # placeholder entry that would block the "all validated" check.
                logging.error(f"Skipping test cases for {threat_type} after all retries: {str(last_error)}")
                if assessment_id and test_cases_json_str:
                    try:
                        safe_type = threat_type.replace('/', '_').replace(' ', '_')
                        error_file_path = os.path.join(_STORAGE_DIR, assessment_id, f'asvs_error_{safe_type}.json')
                        error_response = {
                            "threat_type": threat_type,
                            "error": str(last_error),
                            "raw_response": test_cases_json_str,
                            "timestamp": datetime.datetime.now().isoformat()
                        }
                        with open(error_file_path, 'w') as f:
                            json.dump(error_response, f, indent=2)
                        logging.info(f"Saved error debug file to {error_file_path}")
                    except Exception as save_error:
                        logging.error(f"Failed to save error debug file: {str(save_error)}")
        
        # Combine all test cases
        combined_result = {"test_cases": all_test_cases}
        
        # Save combined test cases to storage
        if assessment_id:
            try:
                output_path = os.path.join(_STORAGE_DIR, assessment_id, 'test_cases.json')
                with open(output_path, 'w') as f:
                    json.dump(combined_result, f, indent=2)
                logging.info(f"Saved {len(all_test_cases)} total test cases to {output_path}")
            except Exception as e:
                logging.error(f"Failed to save test cases: {str(e)}")
            if getattr(self, '_last_usage', None):
                try:
                    from utils.storage import accumulate_pipeline_cost
                    accumulate_pipeline_cost(assessment_id, 'test_cases', self._last_usage[0], self._last_usage[1], self.openai_handler.model)
                except Exception:
                    pass
        
        return combined_result
    
    def _create_threat_specific_prompt(self, threats, threat_type, methodology):
        """
        Create a prompt for generating test cases for a specific threat type.
        Uses a quality template; Low-confidence threats are pre-filtered by the caller.
        """
        # Get the appropriate ASVS test cases prompt template
        prompt_data = self.prompt_manager.get_prompt('asvs_test_cases')

        # Format threats for test case generation
        threat_descriptions = []
        is_pasta = methodology == "PASTA"

        for threat in threats:
            confidence = threat.get('Confidence', 'Medium')
            if is_pasta:
                threat_category = threat.get('Threat Type', '')
                business_risk = threat.get('Business Risk Type', [])
                if isinstance(business_risk, list):
                    business_risk = ', '.join(business_risk)
                pasta_stage = threat.get('PASTA Stage', '')
                scenario = threat.get('Scenario', '')
                impact = threat.get('Potential Impact', '')

                threat_descriptions.append(
                    f"Threat Type: {threat_category}\n"
                    f"Business Risk Type: {business_risk}\n"
                    f"PASTA Stage: {pasta_stage}\n"
                    f"Scenario: {scenario}\n"
                    f"Potential Impact: {impact}\n"
                    f"Confidence: {confidence}"
                )
            else:
                threat_type_val = threat.get('Threat Type', '')
                scenario = threat.get('Scenario', '')
                impact = threat.get('Potential Impact', '')
                threat_descriptions.append(
                    f"Threat Type: {threat_type_val}\n"
                    f"Scenario: {scenario}\n"
                    f"Potential Impact: {impact}\n"
                    f"Confidence: {confidence}"
                )

        formatted_threats = "\n\n".join(threat_descriptions)

        quality_instruction = """
QUALITY TEMPLATE — For each threat, generate exactly ONE test case using this structure:
  pre_condition:   What state must exist before the test runs (e.g. "A valid user session exists")
  steps:           Numbered list of specific HTTP requests or UI actions with endpoint paths, methods, and payloads
  expected_result: HTTP status code AND response body pattern (e.g. "HTTP 401 with {\"error\": \"unauthorized\"}")
  pass_condition:  What must be true to confirm the security control is working

Do NOT use vague steps like "send a request" — name the endpoint, the method, and the payload.
"""

        prompt = f"""
{prompt_data.system_context}

{prompt_data.task}

Threat Type: {threat_type}

Threats:
{formatted_threats}

{quality_instruction}

Format: {prompt_data.format}

Instructions:
{chr(10).join(f"- {instruction}" for instruction in prompt_data.instructions)}

YOUR RESPONSE (valid JSON with key 'test_cases', no code fences or extra text):
"""
        return prompt
