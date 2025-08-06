import json
import logging
import os
from rag.rag_handler import PromptManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DreadHandler:
    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        self.client = openai_handler.client
        self.prompt_manager = PromptManager()

    def create_dread_assessment_prompt(self, threat_model_result, attack_tree_data, assessment_id=None):
        """
        Create a prompt for generating a DREAD assessment using threats from threat model and attack tree.
        """
        # Get methodology from details.json if assessment_id is provided
        methodology = None
        if assessment_id:
            try:
                methodology = self._get_methodology_from_details(assessment_id)
                logging.info(f"Using threat modeling methodology from details.json for DREAD assessment: {methodology}")
            except ValueError as e:
                # Re-raise the error to be handled by the caller
                raise ValueError(f"Failed to get methodology: {str(e)}")
        else:
            # If no assessment_id is provided, this is likely a direct call not through the API
            # In this case, we need to throw an error as we can't determine the methodology
            error_msg = "Assessment ID is required to determine the threat modeling methodology"
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        # Get the DREAD assessment prompt template
        prompt_data = self.prompt_manager.get_prompt("dread_assessment")
        
        threats = threat_model_result.get('threat_model', [])
        
        # Format threats for DREAD assessment
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
        
        # Add stronger JSON formatting instructions for Bedrock
        json_instructions = ""
        if self.openai_handler.method == 'BEDROCK':
            json_instructions = """
IMPORTANT: You MUST respond with valid, properly formatted JSON that follows the exact structure shown below.
Your entire response must be parseable as JSON. Do not include any explanatory text outside the JSON structure.
The JSON must include the key "Risk Assessment" with an array of threat assessments exactly as shown.
"""
        
        prompt = f"""
{json_instructions}
{prompt_data.system_context}
{prompt_data.task}

Below is the list of identified threats:

{formatted_threats}

{attack_tree_context}

{prompt_data.instructions}

Example of expected JSON response format:
{json.dumps(prompt_data.format.get("example", {}), indent=2)}

Ensure the JSON response is correctly formatted and does not contain any additional text.
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

    def get_dread_assessment(self, prompt):
        """
        Get DREAD assessment from the LLM response.
        """
        method = self.openai_handler.method
        logging.info(f"Generating DREAD assessment using {method}")
        
        try:
            # Prepare system message based on provider
            system_message = "You are a helpful assistant designed to output JSON."
            if method == 'BEDROCK':
                system_message = """You are a helpful assistant designed to output JSON. 
                Your response must be valid, parseable JSON with no additional text, markdown formatting, 
                or explanations outside the JSON structure. The JSON must include the key 'Risk Assessment' 
                with an array of threat assessments."""
            
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
            
            # Try to parse the JSON response
            try:
                response_content = json.loads(cleaned_text)
                logging.info("Successfully parsed JSON response")
                
                # Validate the response structure
                if "Risk Assessment" not in response_content:
                    logging.warning("Response missing 'Risk Assessment' field, attempting to fix structure")
                    # Try to fix the structure if possible
                    if not response_content.get("Risk Assessment"):
                        response_content["Risk Assessment"] = []
                
                return response_content
                
            except json.JSONDecodeError as je:
                logging.error(f"Failed to parse JSON response: {str(je)}")
                logging.error(f"Response was: {response_text}")
                raise
            
        except Exception as e:
            logging.error(f"Error generating DREAD assessment with {method}: {str(e)}")
            return {
                "Risk Assessment": [
                    {
                        "Threat Type": "Error",
                        "Scenario": f"Failed to generate DREAD assessment with {method}: {str(e)}",
                        "Damage Potential": 0,
                        "Reproducibility": 0,
                        "Exploitability": 0,
                        "Affected Users": 0,
                        "Discoverability": 0
                    }
                ]
            }

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
    
    def json_to_markdown(self, dread_assessment, assessment_id=None):
        """
        Convert JSON DREAD assessment to Markdown for display.
        """
        markdown_output = "\n\n## DREAD Risk Assessment\n\n"
        
        markdown_output += "| Threat Type | Scenario | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |\n"
        markdown_output += "|-------------|----------|------------------|-----------------|----------------|----------------|-----------------|-------------|\n"
        
        try:
            threats = dread_assessment.get("Risk Assessment", [])
            for threat in threats:
                if isinstance(threat, dict):
                    damage_potential = threat.get('Damage Potential', 0)
                    reproducibility = threat.get('Reproducibility', 0)
                    exploitability = threat.get('Exploitability', 0)
                    affected_users = threat.get('Affected Users', 0)
                    discoverability = threat.get('Discoverability', 0)
                    
                    # Calculate the Risk Score
                    risk_score = (damage_potential + reproducibility + exploitability + affected_users + discoverability) / 5
                    
                    markdown_output += f"| {threat.get('Threat Type', 'N/A')} | {threat.get('Scenario', 'N/A')} | {damage_potential} | {reproducibility} | {exploitability} | {affected_users} | {discoverability} | {risk_score:.2f} |\n"
        except Exception as e:
            logging.error(f"Error converting DREAD assessment to markdown: {str(e)}")
            markdown_output += f"| Error | Failed to format DREAD assessment: {str(e)} | - | - | - | - | - | - |\n"
        
        return markdown_output

    def generate_dread_assessment(self, threat_model_result, attack_tree_data=None, assessment_id=None):
        """
        Generate a DREAD assessment based on threat model results and attack tree data.
        """
        logging.info("Generating DREAD assessment")
        
        # Create the prompt using threat model results and attack tree data
        prompt = self.create_dread_assessment_prompt(threat_model_result, attack_tree_data, assessment_id)
        
        # Get the DREAD assessment
        assessment = self.get_dread_assessment(prompt)
        
        # Convert to markdown, passing the assessment_id
        # markdown = self.json_to_markdown(assessment, assessment_id)
        
        return {
            "raw_response": assessment
        }
