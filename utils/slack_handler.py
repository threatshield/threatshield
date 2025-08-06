import logging
import re
import json
from urllib.parse import urlparse, parse_qs
import requests
from utils.config import get_slack_credentials

def extract_channel_thread_from_url(slack_url):
    """
    Extract channel ID and thread timestamp from Slack URL.
    
    Args:
        slack_url: Slack thread URL
        
    Returns:
        Tuple of (channel_id, thread_ts) or (None, None) if not found
    """
    try:
        # Parse the URL
        parsed_url = urlparse(slack_url)
        
        # Common Slack URL patterns
        # Pattern: /archives/C01234567/p1234567890123456
        path_parts = parsed_url.path.strip('/').split('/')
        
        if len(path_parts) >= 3 and path_parts[0] == 'archives':
            channel_id = path_parts[1]
            
            # Thread timestamp is in the format p1234567890123456
            # We need to convert it to 1234567890.123456
            thread_ts_match = re.match(r'p(\d{10})(\d{6})', path_parts[2])
            if thread_ts_match:
                seconds = thread_ts_match.group(1)
                microseconds = thread_ts_match.group(2)
                thread_ts = f"{seconds}.{microseconds}"
                return channel_id, thread_ts
        
        logging.warning(f"Could not extract channel and thread from URL: {slack_url}")
        return None, None
        
    except Exception as e:
        logging.error(f"Error extracting channel and thread from URL: {str(e)}")
        return None, None

def load_slack_thread(slack_url):
    """
    Load messages from a Slack thread.
    
    Args:
        slack_url: Slack thread URL
        
    Returns:
        Dictionary containing thread content and metadata
    """
    try:
        # Get credentials from environment variables
        credentials = get_slack_credentials()
        token = credentials['token']
        
        # Validate credentials
        if not token:
            error_msg = "Slack token not found. Please check your .env file."
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        # Extract channel ID and thread timestamp from URL
        channel_id, thread_ts = extract_channel_thread_from_url(slack_url)
        if not channel_id or not thread_ts:
            error_msg = "Could not extract channel ID and thread timestamp from URL. Please check the URL format."
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        logging.info(f"Loading messages from Slack thread: {channel_id}/{thread_ts}")
        
        # Call Slack API to get thread messages
        try:
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Log the token (first few chars only for security)
            if token:
                masked_token = token[:4] + "..." + token[-4:] if len(token) > 8 else "***"
                logging.info(f"Using Slack token: {masked_token}")
            else:
                logging.warning("Slack token is empty")
                
            # Log request details
            logging.info(f"Making Slack API request to conversations.replies for channel: {channel_id}, thread: {thread_ts}")
            
            # Get thread messages
            response = requests.get(
                'https://slack.com/api/conversations.replies',
                headers=headers,
                params={
                    'channel': channel_id,
                    'ts': thread_ts,
                    'limit': 100  # Adjust as needed
                }
            )
            
            # Log response status
            logging.info(f"Slack API response status: {response.status_code}")
            
            if not response.ok:
                error_msg = f"Failed to connect to Slack API: HTTP {response.status_code}"
                logging.error(error_msg)
                logging.error(f"Response content: {response.text[:500]}")  # Log first 500 chars of response
                raise ValueError(error_msg)
                
            data = response.json()
            
            # Log response data (excluding sensitive info)
            logging.info(f"Slack API response: ok={data.get('ok')}, error={data.get('error', 'None')}")
            if 'messages' in data:
                logging.info(f"Retrieved {len(data['messages'])} messages from thread")
            
            if not data.get('ok'):
                error_msg = f"Slack API error: {data.get('error', 'Unknown error')}"
                logging.error(error_msg)
                logging.error(f"Full response: {json.dumps(data)}")
                raise ValueError(error_msg)
                
            messages = data.get('messages', [])
            
            if not messages:
                error_msg = "No messages found in the specified Slack thread"
                logging.warning(error_msg)
                raise ValueError(error_msg)
            
            # Get channel info for metadata
            channel_response = requests.get(
                'https://slack.com/api/conversations.info',
                headers=headers,
                params={'channel': channel_id}
            )
            
            channel_data = channel_response.json()
            channel_name = "Unknown Channel"
            
            if channel_data.get('ok') and channel_data.get('channel'):
                channel_name = channel_data['channel'].get('name', "Unknown Channel")
            
            # Format messages into a readable string
            formatted_content = ""
            for msg in messages:
                user = msg.get('user', 'Unknown User')
                text = msg.get('text', '')
                ts = msg.get('ts', '')
                
                # Try to get user info
                user_response = requests.get(
                    'https://slack.com/api/users.info',
                    headers=headers,
                    params={'user': user}
                )
                
                user_data = user_response.json()
                if user_data.get('ok') and user_data.get('user'):
                    user_name = user_data['user'].get('real_name', user)
                else:
                    user_name = user
                
                formatted_content += f"{user_name}: {text}\n\n"
            
            result = {
                "url": slack_url,
                "content": formatted_content.strip(),
                "channel": channel_name,
                "message_count": len(messages)
            }
            
            logging.info(f"Successfully loaded {len(messages)} messages from Slack thread")
            return result
            
        except requests.RequestException as e:
            error_msg = f"Failed to connect to Slack API: {str(e)}"
            logging.error(error_msg)
            raise ValueError(error_msg)
        
    except ValueError as e:
        # Re-raise ValueError for specific error messages
        raise
    except Exception as e:
        error_msg = f"Error loading Slack thread: {str(e)}"
        logging.error(error_msg)
        raise ValueError(error_msg)