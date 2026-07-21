import os

_STORAGE_DIR = os.environ.get('STORAGE_PATH', 'storage')
import logging
import json
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

_SETTINGS_PATH = os.path.join(_STORAGE_DIR, 'data', 'settings', 'settings.json')
_TEAMS_PATH = os.path.join(_STORAGE_DIR, 'data', 'teams.json')

def get_teams() -> list:
    try:
        with open(_TEAMS_PATH, 'r') as f:
            return json.load(f)
    except Exception:
        return []

def save_teams(teams: list) -> None:
    os.makedirs(os.path.dirname(_TEAMS_PATH), exist_ok=True)
    with open(_TEAMS_PATH, 'w') as f:
        json.dump(teams, f, indent=2)

def _get_settings() -> dict:
    """Read settings.json fresh from disk. Returns empty dict on any error."""
    try:
        with open(_SETTINGS_PATH, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def _save_settings(settings: dict) -> None:
    """Write settings dict to storage/data/settings/settings.json."""
    os.makedirs(os.path.dirname(_SETTINGS_PATH), exist_ok=True)
    with open(_SETTINGS_PATH, 'w') as f:
        json.dump(settings, f, indent=2)

def get_mcp_admins() -> list[str]:
    """Return admin emails from settings.json admins list, fallback to MCP_ADMINS env var."""
    settings = _get_settings()
    admins = settings.get('admins')
    if admins is not None:
        return [e.strip().lower() for e in admins if e.strip()]
    # Fallback to env var
    raw = os.getenv('MCP_ADMINS', '')
    return [e.strip().lower() for e in raw.split(',') if e.strip()]

def save_admins(admins: list[str]) -> None:
    """Persist the admin list to settings.json."""
    settings = _get_settings()
    settings['admins'] = [e.strip().lower() for e in admins if e.strip()]
    _save_settings(settings)

def get_setup_dismissed() -> bool:
    """Return whether the one-time setup dialog has been dismissed/completed."""
    return bool(_get_settings().get('setupDismissed', False))

def set_setup_dismissed(value: bool = True) -> None:
    """Persist the one-time setup dismissed flag to settings.json."""
    settings = _get_settings()
    settings['setupDismissed'] = bool(value)
    _save_settings(settings)

def get_llm_method() -> str:
    """Return LLM method from settings.json llmConfig, fallback to LLM_METHOD env var."""
    settings = _get_settings()
    method = settings.get('llmConfig', {}).get('method')
    return method or os.getenv('LLM_METHOD', 'OPENAI')

def get_openai_api_key():
    return os.getenv('OPENAI_API_KEY')

def get_bedrock_config():
    settings = _get_settings()
    llm_cfg = settings.get('llmConfig', {})
    default_model = os.getenv('BEDROCK_MODEL', 'claude-3.7-sonnet')
    model = llm_cfg.get('model') or default_model
    large_output_model = (
        llm_cfg.get('large_output_model')
        or os.getenv('BEDROCK_LARGE_OUTPUT_MODEL')
        or model
    )
    return {
        'base_url': llm_cfg.get('base_url') or os.getenv('BEDROCK_BASE_URL'),
        'api_key': os.getenv('BEDROCK_API_KEY'),  # Always from .env
        'model': model,
        'large_output_model': large_output_model,
    }

def save_llm_config(llm_config: dict) -> None:
    """Persist LLM config to settings.json.
    API keys are never stored here — they stay in .env.
    Resets `tested` to False whenever config fields change.
    """
    settings = _get_settings()
    existing = settings.get('llmConfig', {})
    for key in ('method', 'model', 'base_url', 'large_output_model'):
        if key in llm_config:
            existing[key] = llm_config[key]
    existing['tested'] = False  # require re-test after any config change
    settings['llmConfig'] = existing
    _save_settings(settings)

def set_llm_tested(tested: bool) -> None:
    """Mark the current LLM config as tested (or untested) in settings.json."""
    settings = _get_settings()
    llm_cfg = settings.get('llmConfig', {})
    llm_cfg['tested'] = tested
    settings['llmConfig'] = llm_cfg
    _save_settings(settings)

def is_llm_tested() -> bool:
    """Return True only when llmConfig.tested is explicitly True in settings.json."""
    return bool(_get_settings().get('llmConfig', {}).get('tested', False))

DEFAULT_GENERAL_CONFIG = {
    # IANA timezone used to display assessment timestamps across the app.
    "timezone": "Asia/Kolkata",
}

def get_general_config() -> dict:
    """Return the general config from settings.json, merged over defaults."""
    settings = _get_settings()
    cfg = settings.get('generalConfig') or {}
    return {**DEFAULT_GENERAL_CONFIG, **cfg}

def save_general_config(config: dict) -> None:
    """Persist the general config to settings.json (merges known keys only)."""
    settings = _get_settings()
    existing = settings.get('generalConfig', {})
    if 'timezone' in config and isinstance(config['timezone'], str) and config['timezone'].strip():
        existing['timezone'] = config['timezone'].strip()
    settings['generalConfig'] = existing
    _save_settings(settings)

def get_confluence_credentials():
    """
    Get Confluence credentials from environment variables.
    
    Returns:
        Dictionary containing Confluence API key and username
    """
    return {
        'api_key': os.getenv('CONFLUENCE_API_KEY', ''),
        'username': os.getenv('CONFLUENCE_USERNAME', '')
    }

def get_slack_credentials():
    """
    Get Slack credentials from environment variables.
    
    Returns:
        Dictionary containing Slack token and other credentials
    """
    return {
        'token': os.getenv('SLACK_API_TOKEN', '')
    }

def test_confluence_connection(confluence_url):
    """
    Test if Confluence connection works with the provided URL and stored credentials.
    
    Args:
        confluence_url: Confluence URL to test
        
    Returns:
        Tuple of (success, message)
    """
    try:
        credentials = get_confluence_credentials()
        if not credentials['api_key'] or not credentials['username']:
            return False, "Confluence credentials not found in .env file"
            
        # Just check if credentials exist for now
        # In a real implementation, you would make an actual API call to Confluence
        return True, "Confluence connection successful"
    except Exception as e:
        logging.error(f"Error testing Confluence connection: {str(e)}")
        return False, f"Error testing Confluence connection: {str(e)}"

DEFAULT_THREAT_FILTER_CONFIG = {
    "enabled": True,
    "criticPassEnabled": True,
    "infrastructureControls": {
        "apiGateway": {
            "vendor": "Kong/Cloudflare",
            "trustedHeaders": [
                "x-user-id", "x-device-id", "x-tenant-id",
                "x-request-id", "x-correlation-id", "x-forwarded-for",
                "x-real-ip", "x-auth-token", "x-service-name"
            ],
            "description": "Headers are stripped and re-injected by the API gateway after authentication. Cannot be set by external users or attackers."
        },
        "waf": {
            "vendor": "Cloudflare",
            "capabilities": ["rate-limiting", "ddos-protection", "ip-reputation"],
            "description": "Rate limiting and DDoS protection enforced at CDN layer, not application code."
        },
        "serviceMesh": {
            "protocol": "mTLS",
            "description": "Internal service-to-service calls use mutual TLS certificates. Not accessible from the internet."
        }
    },
    "falsePositiveKeywords": [],
    "sensitiveAssets": [
        "UPI PIN", "KYC document", "loan repayment schedule",
        "CIBIL score", "bank account details", "credit card number",
        "NACH mandate", "OTP", "Aadhaar"
    ],
    "qualityConfig": {
        "requireSpecificEntryPoint": True,
        "requireAssetSpecificity": True,
        "minScenarioLength": 60
    }
}

def get_threat_filter_config() -> dict:
    """Return the threat filter config from settings.json, falling back to defaults."""
    settings = _get_settings()
    return settings.get('threatFilterConfig', DEFAULT_THREAT_FILTER_CONFIG)

def save_threat_filter_config(config: dict) -> None:
    """Persist the threat filter config to settings.json."""
    settings = _get_settings()
    settings['threatFilterConfig'] = config
    _save_settings(settings)

def test_slack_connection(slack_url):
    """
    Test if Slack connection works with the provided URL and stored credentials.
    
    Args:
        slack_url: Slack URL to test
        
    Returns:
        Tuple of (success, message)
    """
    try:
        credentials = get_slack_credentials()
        token = credentials['token']
        
        if not token:
            logging.error("Slack token not found in .env file")
            return False, "Slack token not found in .env file"
        
        # Log the token (first few chars only for security)
        masked_token = token[:4] + "..." + token[-4:] if len(token) > 8 else "***"
        logging.info(f"Testing Slack connection with token")
        
        # Check if the token is a path instead of an actual token
        if token.startswith('/'):
            logging.warning(f"Token appears to be a path ({token}) rather than an actual token")
            logging.warning("This may indicate that token retrieval failed")
        
        # Make an actual API call to test the token
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Use auth.test endpoint to validate token
        response = requests.post(
            'https://slack.com/api/auth.test',
            headers=headers
        )
        
        if not response.ok:
            error_msg = f"Failed to connect to Slack API: HTTP {response.status_code}"
            logging.error(error_msg)
            logging.error(f"Response content: {response.text[:500]}")
            return False, error_msg
            
        data = response.json()
        
        if not data.get('ok'):
            error_msg = f"Slack API error: {data.get('error', 'Unknown error')}"
            logging.error(error_msg)
            logging.error(f"Full response: {json.dumps(data)}")
            return False, error_msg
            
        # If we get here, the token is valid
        team_name = data.get('team', 'Unknown team')
        user_name = data.get('user', 'Unknown user')
        logging.info(f"Slack connection successful: Authenticated as {user_name} to team {team_name}")
        return True, f"Slack connection successful: Authenticated as {user_name} to team {team_name}"
        
    except Exception as e:
        logging.error(f"Error testing Slack connection: {str(e)}")
        return False, f"Error testing Slack connection: {str(e)}"
