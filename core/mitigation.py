import json
import logging
import os
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
    
    def create_mitigations_prompt(self, threat_model_result, attack_tree_data=None, dread_data=None, assessment_id=None):
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
        
        # Get the mitigations prompt template
        prompt_data = self.prompt_manager.get_prompt("mitigations")
        
        threats = threat_model_result.get('threat_model', [])
        
        # Format threats for mitigation analysis
        threat_descriptions = []
        
        for threat in threats:
            threat_type = threat.get('Threat Type', '')
            scenario = threat.get('Scenario', '')
            impact = threat.get('Potential Impact', '')
            threat_descriptions.append(f"Threat Type: {threat_type}\nScenario: {scenario}\nPotential Impact: {impact}")
        
        formatted_threats = "\n\n".join(threat_descriptions)
        
        # Add attack tree data if available
        attack_tree_context = ""
        if attack_tree_data and 'attack_tree' in attack_tree_data:
            attack_tree = attack_tree_data['attack_tree']
            attack_tree_context = f"\n\nAttack Tree Analysis:\n{json.dumps(attack_tree, indent=2)}"
            
        # Add DREAD assessment data if available
        dread_context = ""
        if dread_data and 'raw_response' in dread_data:
            dread_assessment = dread_data['raw_response']
            dread_context = f"\n\nDREAD Risk Assessment:\n{json.dumps(dread_assessment, indent=2)}"
        
        prompt = f"""
{prompt_data.system_context} {prompt_data.task}

{prompt_data.format}

Below is the list of identified threats:
{formatted_threats}

{attack_tree_context}

{dread_context}

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
                "max_tokens": 8000
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

    def generate_mitigations(self, threat_model_result, attack_tree_data, dread_data, assessment_id=None):
        """
        Generate mitigations for threats identified in the threat model, considering attack tree and DREAD data.
        """
        logging.info("Generating mitigations")
        
        # Determine which methodology to use from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            methodology = self._get_methodology_from_details(assessment_id)
            logging.info(f"Using threat modeling methodology from details.json for mitigations processing: {methodology}")
        
        # Create the prompt using all available data
        prompt = self.create_mitigations_prompt(threat_model_result, attack_tree_data, dread_data, assessment_id)
        
        # Get the mitigations
        mitigations_json_str = self.get_mitigations(prompt)
        
        try:
            # Parse the JSON response
            mitigations_data = json.loads(mitigations_json_str)
            
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
            
            # Return only the raw JSON data
            return {
                "raw_response": mitigations_data
            }
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing mitigations JSON: {str(e)}")
            logging.error(f"Raw JSON string: {mitigations_json_str[:500]}...")
            # Return a fallback response
            return {
                "raw_response": {
                    "mitigations": [
                        {
                            "Threat Type": "Error",
                            "Scenario": "Failed to parse mitigations JSON",
                            "Mitigations": "Please try again"
                        }
                    ]
                }
            }
