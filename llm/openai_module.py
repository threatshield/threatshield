from openai import OpenAI
from utils.config import get_openai_api_key, get_llm_method, get_bedrock_config
import logging

# Approximate pricing per 1M tokens (input / output) in USD
_MODEL_PRICING = {
    'claude-opus-4-7':   (15.0,  75.0),
    'claude-opus-4-6':   (15.0,  75.0),
    'claude-sonnet-4-6': (3.0,   15.0),
    'claude-haiku-4-5':  (0.8,   4.0),
    'gpt-4o':            (5.0,   15.0),
    'gpt-4o-mini':       (0.15,  0.6),
    'gpt-4-turbo':       (10.0,  30.0),
}

class OpenAIHandler:
    def __init__(self, model=None):
        # Always read fresh from settings.json (via config helpers) so no restart needed.
        self.method = get_llm_method()
        self._client = None
        self.configured = False

        if self.method == 'OPENAI':
            self.api_key = get_openai_api_key()
            self.model = model or "gpt-4o"
            self.large_output_model = self.model
            if not self.api_key:
                logging.warning("OpenAI API key not set — LLM calls will fail until configured")
                return
        elif self.method == 'BEDROCK':
            bedrock_config = get_bedrock_config()
            self.api_key = bedrock_config['api_key']
            self.base_url = bedrock_config.get('base_url', '')
            self.model = model or bedrock_config.get('model', '')
            self.large_output_model = bedrock_config.get('large_output_model') or self.model
            if not self.api_key:
                logging.warning("Bedrock API key not set — LLM calls will fail until configured")
                return
            if not self.base_url:
                logging.warning("Bedrock base URL not set — LLM calls will fail until configured")
                return
            if not self.model:
                logging.warning("Bedrock model not set — LLM calls will fail until configured")
                return
        else:
            logging.error(f"Unsupported LLM method: {self.method}")
            return

        try:
            self._client = self.initialize_openai_client()
            self.configured = True
        except Exception as e:
            logging.error(f"Failed to initialize {self.method} client: {e}")

    @property
    def client(self):
        return self._client

    @property
    def max_output_tokens(self):
        model = (self.model or "").lower()
        if "opus" in model:
            return 16000
        if "sonnet" in model:
            return 16000
        return 8192

    def _require_configured(self):
        if not self.configured or self._client is None:
            raise RuntimeError(
                "LLM is not configured. An admin must set the model, endpoint, and API key."
            )

    def initialize_openai_client(self):
        logging.info(f"Initializing client for {self.method} method")

        if self.method == 'OPENAI':
            client = OpenAI(api_key=self.api_key)
            try:
                models = client.models.list()
                logging.info(f"OpenAI connection successful. Available models: {len(models.data)}")
            except Exception as e:
                logging.warning(f"Could not list OpenAI models: {str(e)}")
            return client

        elif self.method == 'BEDROCK':
            logging.info(f"Connecting to Bedrock at {self.base_url}")
            client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )
            try:
                models = client.models.list()
                logging.info(f"Bedrock connection successful. Available models: {len(models.data)}")
            except Exception as e:
                logging.warning(f"Could not verify Bedrock connection: {str(e)}")
            return client

        raise ValueError(f"Unsupported method: {self.method}")

    def send_prompt(self, prompt):
        self._require_configured()
        try:
            logging.info(f"Sending prompt to {self.method} using model {self.model}")
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=150
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            error_msg = f"Error sending prompt to {self.method}: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)

    def create_chat_template(self, template_name):
        logging.info(f"Creating chat template '{template_name}' using {self.method}")
        return f"Chat template for {template_name} created"

    @staticmethod
    def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
        """Return estimated USD cost for a single API call."""
        model_key = (model or '').lower()
        for key, (inp_price, out_price) in _MODEL_PRICING.items():
            if key in model_key:
                return round((input_tokens * inp_price + output_tokens * out_price) / 1_000_000, 6)
        # Fallback: use Sonnet pricing
        return round((input_tokens * 3.0 + output_tokens * 15.0) / 1_000_000, 6)

    def get_completion(self, prompt, max_tokens=1000):
        self._require_configured()
        try:
            logging.info(f"Getting completion from {self.method} using model {self.model}")
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            error_msg = f"Error getting completion from {self.method}: {str(e)}"
            logging.error(error_msg)
            raise RuntimeError(error_msg)

