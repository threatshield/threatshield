from openai import OpenAI
from utils.config import get_openai_api_key, get_llm_method, get_bedrock_config
import logging

class OpenAIHandler:
    def __init__(self, model=None):
        self.method = get_llm_method()
        
        if self.method == 'OPENAI':
            self.api_key = get_openai_api_key()
            if not self.api_key:
                logging.error("OpenAI API key not found")
                raise ValueError("OpenAI API key not found")
            self.model = model or "gpt-4o"
        elif self.method == 'BEDROCK':
            bedrock_config = get_bedrock_config()
            self.api_key = bedrock_config['api_key']
            if not self.api_key:
                logging.error("Bedrock API key not found")
                raise ValueError("Bedrock API key not found")
            self.base_url = bedrock_config['base_url']
            if not self.base_url:
                logging.error("Bedrock base URL not found")
                raise ValueError("Bedrock base URL not found")
            self.model = model or bedrock_config['model']
        else:
            logging.error(f"Unsupported LLM method: {self.method}")
            raise ValueError(f"Unsupported LLM method: {self.method}")
            
        self._client = self.initialize_openai_client()
        
    @property
    def client(self):
        """Return the OpenAI client instance."""
        return self._client
        
    def initialize_openai_client(self):
        try:
            logging.info(f"Initializing client for {self.method} method")
            
            if self.method == 'OPENAI':
                client = OpenAI(api_key=self.api_key)
                # Test connection with a simple request
                logging.info("Testing OpenAI connection...")
                try:
                    models = client.models.list()
                    logging.info(f"OpenAI connection successful. Available models: {len(models.data)}")
                except Exception as e:
                    logging.warning(f"Could not list OpenAI models: {str(e)}")
                    logging.warning("Continuing with initialization, but API calls may fail")
                return client
                
            elif self.method == 'BEDROCK':
                logging.info(f"Connecting to Bedrock at {self.base_url}")
                # Use default_headers instead of api_key to bypass OpenAI's API key validation
                client = OpenAI(
                    base_url=self.base_url,
                    default_headers={"Authorization": f"Bearer {self.api_key}"}
                )
                
                # Test connection with a simple request
                logging.info("Testing Bedrock connection...")
                try:
                    # Try to list models or make a simple request to verify connection
                    models = client.models.list()
                    logging.info(f"Bedrock connection successful. Available models: {len(models.data)}")
                except Exception as e:
                    logging.error(f"Failed to verify Bedrock connection: {str(e)}")
                    logging.error(f"Error details: {str(e)}")
                    logging.error("Continuing with initialization, but API calls may fail")
                    
                return client
        except Exception as e:
            error_msg = f"Failed to initialize {self.method} client: {str(e)}"
            logging.error(error_msg)
            raise ConnectionError(error_msg)

    def send_prompt(self, prompt):
        try:
            logging.info(f"Sending prompt to {self.method} using model {self.model}")
            
            # Log request details for debugging
            logging.debug(f"Request details - Model: {self.model}, Method: {self.method}")
            logging.debug(f"Prompt content: {prompt[:100]}..." if len(prompt) > 100 else f"Prompt content: {prompt}")
            
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=150
                )
                
                logging.info(f"Successfully received response from {self.method}")
                return response.choices[0].message.content.strip()
                
            except Exception as e:
                # Add more detailed error logging for API-specific errors
                if self.method == 'BEDROCK':
                    logging.error(f"Bedrock API error: {str(e)}")
                    logging.error("Check if your Bedrock API supports the OpenAI chat completions format")
                    logging.error(f"Model being used: {self.model}")
                else:
                    logging.error(f"OpenAI API error: {str(e)}")
                
                raise
            
        except Exception as e:
            error_msg = f"Error sending prompt to {self.method}: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)

    def create_chat_template(self, template_name):
        try:
            logging.info(f"Creating chat template '{template_name}' using {self.method}")
            # Create and return a chat template based on the template name
            # This is a placeholder for actual chat template creation
            result = f"Chat template for {template_name} created"
            logging.info(f"Successfully created chat template '{template_name}'")
            return result
        except Exception as e:
            error_msg = f"Error creating chat template '{template_name}': {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)
            
    def get_completion(self, prompt, max_tokens=1000):
        """Get completion from the LLM."""
        try:
            logging.info(f"Getting completion from {self.method} using model {self.model}")
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens
            )
            
            logging.info(f"Successfully received completion from {self.method}")
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            error_msg = f"Error getting completion from {self.method}: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)
