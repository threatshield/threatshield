import json
import logging
import os

_STORAGE_DIR = os.environ.get('STORAGE_PATH', 'storage')
import datetime
from rag.rag_handler import PromptManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MitigationHandler:
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
    
    def create_mitigations_prompt(self, threat_model_result, assessment_id=None):
        """
        Create prompt for generating mitigations using threats from threat model, attack tree, and DREAD assessment.
        """
        # Get methodology from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            try:
                methodology = self._get_methodology_from_details(assessment_id)
                logging.info(f"Using threat modeling methodology from details.json for mitigations: {methodology}")
            except ValueError as e:
                # Re-raise the error to be handled by the caller
                raise ValueError(f"Failed to get methodology: {str(e)}")
        else:
            # If no assessment_id is provided, this is likely a direct call not through the API
            # In this case, we need to throw an error as we can't determine the methodology
            error_msg = "Assessment ID is required to determine the threat modeling methodology"
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        # Get the appropriate mitigations prompt template based on methodology
        prompt_key = "pasta_mitigations" if methodology == "PASTA" else "mitigations"
        prompt_data = self.prompt_manager.get_prompt(prompt_key)
        
        threats = threat_model_result.get('threat_model', [])
        
        # Format threats for mitigation analysis
        threat_descriptions = []
        
        # Determine if we're using PASTA methodology
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
{prompt_data.system_context} {prompt_data.task}

{prompt_data.format}

Below is the list of identified threats:
{formatted_threats}

{prompt_data.instructions}

YOUR RESPONSE (do not wrap in a code block):
"""
        return prompt

    def clean_json_response(self, text):
        """
        Clean the response text to handle potential JSON formatting issues.
        """
        # Remove any markdown code block indicators
        text = text.replace("```json", "").replace("```", "")
        
        # Trim whitespace
        text = text.strip()

        # Strip control characters that break JSON parsing
        import re
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)

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
        text = re.sub(r'//.*?\n', '\n', text)  # Remove single-line comments
        
        logging.debug(f"Cleaned JSON text: {text[:100]}..." if len(text) > 100 else f"Cleaned JSON text: {text}")
        return text

    def get_mitigations(self, prompt):
        """
        Get mitigations from LLM (OpenAI or Bedrock).
        """
        method = self.openai_handler.method
        logging.info(f"Generating mitigations using {method}")
        
        try:
            # Prepare system message based on provider
            system_message = "You are a helpful assistant that provides threat mitigation strategies in JSON format."
            if method == 'BEDROCK':
                system_message = """You are a helpful assistant that provides threat mitigation strategies in JSON format.
                Your response must be valid, parseable JSON with no additional text, markdown formatting, 
                or explanations outside the JSON structure. The JSON must include the key 'mitigations' 
                with an array of mitigation items."""
            
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
            
            # Make the API call
            logging.info(f"Sending request to {method} with model {self.openai_handler.model}")
            response = self.client.chat.completions.create(**params)
            if hasattr(response, 'usage') and response.usage:
                self._last_usage = (response.usage.prompt_tokens, response.usage.completion_tokens)
            else:
                self._last_usage = None

            finish_reason = response.choices[0].finish_reason
            if finish_reason == "length":
                logging.warning(
                    f"[MITIGATION] Response truncated by token limit (finish_reason=length). "
                    f"Output may be incomplete. model={self.openai_handler.model}, max_tokens={params['max_tokens']}"
                )

            # Extract and parse the response content
            response_text = response.choices[0].message.content
            logging.info(f"Response content length: {len(response_text)}")
            logging.debug(f"Response content preview: {response_text[:200]}...")
            
            # Clean the response text to handle potential formatting issues
            cleaned_text = self.clean_json_response(response_text)
            
            return cleaned_text
            
        except Exception as e:
            logging.error(f"Error generating mitigations with {method}: {str(e)}")
            return """{"mitigations": [{"Threat Type": "Error", "Scenario": "Failed to generate mitigations", "Suggested Mitigation(s)": "Please try again"}]}"""

    def generate_mitigations(self, prompt, assessment_id=None):
        """
        Generate mitigations for threats identified in the threat model, considering attack tree and DREAD data.
        """
        logging.info("Generating mitigations")
        
        # Determine which methodology to use from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            methodology = self._get_methodology_from_details(assessment_id)
            logging.info(f"Using threat modeling methodology from details.json for mitigations processing: {methodology}")
        # Get the mitigations
        mitigations_json_str = self.get_mitigations(prompt)
        if assessment_id and getattr(self, '_last_usage', None):
            try:
                from utils.storage import accumulate_pipeline_cost
                accumulate_pipeline_cost(assessment_id, 'mitigation', self._last_usage[0], self._last_usage[1], self.openai_handler.model)
            except Exception:
                pass
        
        try:
            # Parse the JSON response
            try:
                mitigations_data = json.loads(mitigations_json_str)
            except json.JSONDecodeError as je:
                logging.warning(f"json.loads failed ({je}), attempting json_repair fallback")
                from json_repair import repair_json
                mitigations_data = json.loads(repair_json(mitigations_json_str))
                logging.info("Successfully parsed mitigations JSON via json_repair")
            
            # Normalize key name: LLM sometimes outputs "Suggested_Mitigation(s)" (underscore)
            # instead of the expected "Suggested Mitigation(s)" (space)
            if "mitigations" in mitigations_data and isinstance(mitigations_data["mitigations"], list):
                for item in mitigations_data["mitigations"]:
                    if "Suggested_Mitigation(s)" in item and "Suggested Mitigation(s)" not in item:
                        item["Suggested Mitigation(s)"] = item.pop("Suggested_Mitigation(s)")

            # Validate the response structure
            if "mitigations" not in mitigations_data:
                logging.warning("Response missing 'mitigations' field, attempting to fix structure")
                # Try to fix the structure if possible
                if isinstance(mitigations_data, dict):
                    # Check if there's a key that might contain mitigations
                    for key in mitigations_data:
                        if isinstance(mitigations_data[key], list) and len(mitigations_data[key]) > 0:
                            logging.info(f"Found potential mitigations in key '{key}'")
                            mitigations_data = {"mitigations": mitigations_data[key]}
                            break
                    else:
                        # If no suitable key found, create an empty mitigations array
                        mitigations_data = {"mitigations": []}
                else:
                    # If not a dict, create a default structure
                    mitigations_data = {"mitigations": []}
            
            # Process PASTA methodology specific fields
            if "mitigations" in mitigations_data and isinstance(mitigations_data["mitigations"], list):
                # Determine if we're using PASTA methodology
                is_pasta = False
                
                # First, check if methodology is available from details.json
                if methodology:
                    is_pasta = methodology == "PASTA"
                    logging.info(f"Using methodology from details.json to determine if PASTA: {is_pasta}")
                # If methodology is not available, fall back to checking the structure
                elif mitigations_data["mitigations"] and len(mitigations_data["mitigations"]) > 0:
                    first_mitigation = mitigations_data["mitigations"][0]
                    is_pasta = "PASTA Stage" in first_mitigation or "Business Risk Type" in first_mitigation
                    logging.info(f"Methodology not available, determined PASTA from structure: {is_pasta}")
                
                if is_pasta:
                    logging.info("PASTA methodology detected, ensuring field consistency")
                    for mitigation in mitigations_data["mitigations"]:
                        # 1. Ensure Business Risk Type is always an array
                        if "Business Risk Type" in mitigation:
                            # Convert string to array if it's not already an array
                            if not isinstance(mitigation["Business Risk Type"], list):
                                mitigation["Business Risk Type"] = [mitigation["Business Risk Type"]]
                                logging.info(f"Converted Business Risk Type to array: {mitigation['Business Risk Type']}")
                        else:
                            # If missing, add a default value
                            mitigation["Business Risk Type"] = ["Operational"]
                            logging.info("Added default Business Risk Type: ['Operational']")
                        
                       
            # Return only the raw JSON data
            return {
                "raw_response": mitigations_data
            }
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing mitigations JSON: {str(e)}")
            logging.error(f"Raw JSON string: {mitigations_json_str[:500]}...")
            
            # Save error response for debugging with proper JSON encoding
            if assessment_id:
                try:
                    error_file_path = os.path.join(_STORAGE_DIR, assessment_id, 'mitigation_error.json')
                    # Wrap the raw response in a JSON object with proper escaping
                    error_response = {
                        "error": str(e),
                        "raw_response": mitigations_json_str,
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                    with open(error_file_path, 'w') as f:
                        json.dump(error_response, f, indent=2)
                    logging.info(f"Saved error response to {error_file_path}")
                except Exception as save_error:
                    logging.error(f"Failed to save error response: {str(save_error)}")
            
            # Return a fallback response
            return {
                "raw_response": {
                    "mitigations": [
                        {
                            "Threat Type": "Error",
                            "Scenario": "Failed to parse mitigations JSON",
                            "Suggested Mitigation(s)": "Please try again"
                        }
                    ]
                }
            }
