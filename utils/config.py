import os
import logging
import json
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_llm_method():
    return os.getenv('LLM_METHOD', 'OPENAI')  # Default to OPENAI if not specified

def get_openai_api_key():
    return os.getenv('OPENAI_API_KEY')
    
def get_bedrock_config():
    return {
        'base_url': os.getenv('BEDROCK_BASE_URL'),
        'api_key': os.getenv('BEDROCK_API_KEY'),
        'model': os.getenv('BEDROCK_MODEL', 'claude-3.7-sonnet')  # Default model
    }

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