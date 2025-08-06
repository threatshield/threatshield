import json
import logging
import os
from llm.openai_module import OpenAIHandler
from rag.rag_handler import PromptManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ThreatModelingHandler:
    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        self.client = openai_handler.client
        self.last_generated_prompt = None  # Store the last generated prompt
        self.prompt_manager = PromptManager()

    def create_threat_model_prompt(self, app_type, authentication, internet_facing, sensitive_data, app_input, custom_prompt="", org_context="", assessment_id=None):
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
        
        # Get the threat model prompt template
        prompt_data = self.prompt_manager.get_prompt("threat_model")
        
        # Add stronger JSON formatting instructions for Bedrock
        json_instructions = ""
        if self.openai_handler.method == 'BEDROCK':
            json_instructions = """
IMPORTANT: You MUST respond with valid, properly formatted JSON that follows the exact structure shown in the example below.
Your entire response must be parseable as JSON. Do not include any explanatory text outside the JSON structure.
The JSON must include the keys "threat_model" and "improvement_suggestions" exactly as shown.
"""
        
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

ADDITIONAL CONTEXT AND REQUIREMENTS:
{custom_prompt}

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
        
        logging.debug(f"Cleaned JSON text: {text[:100]}..." if len(text) > 100 else f"Cleaned JSON text: {text}")
        return text
        
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
    
    def json_to_markdown(self, threat_model, improvement_suggestions, assessment_id=None):
        """
        Convert JSON threat model to Markdown for display.
        """
        markdown_output = "\n\n"
        
        # STRIDE format
        markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
        markdown_output += "|-------------|----------|------------------|\n"
        
        # Fill the table rows with the STRIDE threat model data
        for threat in threat_model:
            markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"
        
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
            # Prepare system message with strict JSON formatting instructions
            system_message = """You are a security expert generating threat models in JSON format.
Your response MUST be a valid JSON object with exactly these fields:
1. "threat_model": An array of threat objects, each containing:
   - "Threat Type": The STRIDE category (e.g., "Spoofing", "Tampering", etc.)
   - "Scenario": A clear description of the threat
   - "Potential Impact": The consequences if exploited
2. "improvement_suggestions": An array of strings with mitigation recommendations

Example of valid response format:
{
  "threat_model": [
    {
      "Threat Type": "Information Disclosure",
      "Scenario": "Sensitive data exposure through unencrypted API responses",
      "Potential Impact": "Unauthorized access to user data leading to privacy violations"
    }
  ],
  "improvement_suggestions": [
    "Implement TLS encryption for all API communications",
    "Add response data encryption for sensitive fields"
  ]
}"""

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
                logging.info("Using Bedrock-compatible parameters")
            
            # Make the API call
            logging.info(f"Sending request to {method} with model {self.openai_handler.model}")
            response = self.client.chat.completions.create(**params)
            
            # Extract and parse the response content
            response_text = response.choices[0].message.content
            logging.info(f"Response content length: {len(response_text)}")
            logging.debug(f"Response content preview: {response_text[:200]}...")
            
            # Clean the response text
            cleaned_text = self.clean_json_response(response_text)
            
            try:
                # Parse the JSON response
                response_content = json.loads(cleaned_text)
                logging.info("Successfully parsed JSON response")
                
                # Validate and normalize the response structure
                normalized_response = self._normalize_threat_model_response(response_content)
                logging.info("Successfully normalized threat model response")
                
                return normalized_response
                
            except json.JSONDecodeError as je:
                logging.error(f"Failed to parse JSON response: {str(je)}")
                logging.error(f"Response was: {response_text}")
                raise ValueError(f"Invalid JSON response from {method}: {str(je)}")
            
        except Exception as e:
            logging.error(f"Error generating threat model with {method}: {str(e)}")
            return {
                "threat_model": [
                    {
                        "Threat Type": "Error",
                        "Scenario": f"Failed to generate threat model with {method}: {str(e)}",
                        "Potential Impact": "Unable to assess security threats"
                    }
                ],
                "improvement_suggestions": [
                    "Try again with a more detailed application description",
                    "Check API key and connection",
                    f"Verify {method} configuration and model compatibility"
                ]
            }
            
    def _normalize_threat_model_response(self, response_content):
        """
        Validate and normalize the threat model response structure.
        Ensures all required fields are present and properly formatted.
        """
        normalized = {
            "threat_model": [],
            "improvement_suggestions": []
        }
        
        # Handle threat model array
        threats = response_content.get("threat_model", [])
        if not isinstance(threats, list):
            logging.warning("threat_model is not an array, attempting to normalize")
            threats = [threats] if threats else []
            
        for threat in threats:
            if not isinstance(threat, dict):
                logging.warning(f"Skipping invalid threat entry: {threat}")
                continue
                
            # Normalize threat entry
            normalized_threat = {
                "Threat Type": threat.get("Threat Type", "Unknown"),
                "Scenario": threat.get("Scenario", "No scenario provided"),
                "Potential Impact": threat.get("Potential Impact", "Impact not specified")
            }
            
            # Check for alternative field names
            if "type" in threat and not normalized_threat["Threat Type"]:
                normalized_threat["Threat Type"] = threat["type"]
            if "description" in threat and not normalized_threat["Scenario"]:
                normalized_threat["Scenario"] = threat["description"]
            if "impact" in threat and not normalized_threat["Potential Impact"]:
                normalized_threat["Potential Impact"] = threat["impact"]
                
            normalized["threat_model"].append(normalized_threat)
            
        # Handle improvement suggestions
        suggestions = response_content.get("improvement_suggestions", [])
        if not isinstance(suggestions, list):
            logging.warning("improvement_suggestions is not an array, attempting to normalize")
            suggestions = [suggestions] if suggestions else []
            
        normalized["improvement_suggestions"] = [
            str(suggestion) for suggestion in suggestions if suggestion
        ]
        
        if not normalized["threat_model"]:
            logging.warning("No valid threats found in response")
            normalized["threat_model"].append({
                "Threat Type": "Warning",
                "Scenario": "No valid threats were identified in the model generation response",
                "Potential Impact": "Incomplete security assessment"
            })
            
        return normalized

    def generate_threat_model(self, app_type, authentication, internet_facing, sensitive_data, app_input, custom_prompt="", org_context="", assessment_id=None):
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
            custom_prompt,
            org_context,
            assessment_id
        )
        
        # Get the threat model
        response = self.get_threat_model(prompt)
        
        # Extract the threat model and improvement suggestions
        threat_model = response.get("threat_model", [])
        improvement_suggestions = response.get("improvement_suggestions", [])
        
        # Convert to markdown, passing the assessment_id
        markdown = self.json_to_markdown(threat_model, improvement_suggestions, assessment_id)
        
        return {
            "raw_response": response,
            "threat_model": threat_model,
            "improvement_suggestions": improvement_suggestions,
            "markdown": markdown
        }
