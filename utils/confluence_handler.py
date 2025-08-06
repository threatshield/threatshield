import logging
import re
import base64
import requests
import json
from urllib.parse import urlparse, parse_qs
from langchain_community.document_loaders.confluence import ConfluenceLoader
from langchain.schema import Document
from utils.document_handler import process_pdf_file
from utils.config import get_confluence_credentials

def extract_page_info_from_url(confluence_url):
    """
    Extract page ID and space key from Confluence URL.
    
    Args:
        confluence_url: Confluence URL
        
    Returns:
        Tuple of (page_id, space_key) or (None, None) if not found
    """
    try:
        # Parse the URL
        parsed_url = urlparse(confluence_url)
        
        # Try to extract from path
        path_parts = parsed_url.path.strip('/').split('/')
        
        page_id = None
        space_key = None
        
        # Pattern for wiki URLs: /wiki/spaces/SPACEKEY/pages/PAGEID/...
        if len(path_parts) >= 5 and path_parts[0].lower() == 'wiki' and path_parts[1].lower() == 'spaces' and 'pages' in path_parts:
            space_key = path_parts[2]
            # The page ID is usually right after 'pages'
            pages_index = path_parts.index('pages')
            if pages_index + 1 < len(path_parts):
                page_id = path_parts[pages_index + 1]
                logging.info(f"Extracted page ID: {page_id} and space key: {space_key} from URL")
                return page_id, space_key
        
        # Try other common Confluence URL patterns for space key
        # Pattern 1: /display/SPACEKEY/
        if len(path_parts) >= 2 and path_parts[0].lower() == 'display':
            space_key = path_parts[1]
            
        # Pattern 2: /spaces/SPACEKEY/
        elif len(path_parts) >= 2 and path_parts[0].lower() == 'spaces':
            space_key = path_parts[1]
            
        # Try to extract from query parameters
        if not space_key:
            query_params = parse_qs(parsed_url.query)
            if 'spaceKey' in query_params:
                space_key = query_params['spaceKey'][0]
                
        # Try to find space key in the URL using regex
        if not space_key:
            space_key_match = re.search(r'[?&]key=([^&]+)', confluence_url)
            if space_key_match:
                space_key = space_key_match.group(1)
        
        if not page_id:
            logging.warning(f"Could not extract page ID from URL: {confluence_url}")
        if not space_key:
            logging.warning(f"Could not extract space key from URL: {confluence_url}")
            
        return page_id, space_key
        
    except Exception as e:
        logging.error(f"Error extracting info from URL: {str(e)}")
        return None, None

def extract_space_key_from_url(confluence_url):
    """
    Extract space key from Confluence URL.
    
    Args:
        confluence_url: Confluence URL
        
    Returns:
        Space key extracted from URL or None if not found
    """
    try:
        # Parse the URL
        parsed_url = urlparse(confluence_url)
        
        # Try to extract from path
        path_parts = parsed_url.path.strip('/').split('/')
        
        # Common Confluence URL patterns
        # Pattern 1: /display/SPACEKEY/
        if len(path_parts) >= 2 and path_parts[0].lower() == 'display':
            return path_parts[1]
            
        # Pattern 2: /spaces/SPACEKEY/
        if len(path_parts) >= 2 and path_parts[0].lower() == 'spaces':
            return path_parts[1]
            
        # Pattern 3: /wiki/spaces/SPACEKEY/pages/...
        if len(path_parts) >= 4 and path_parts[0].lower() == 'wiki' and path_parts[1].lower() == 'spaces' and 'pages' in path_parts:
            return path_parts[2]
            
        # Try to extract from query parameters
        query_params = parse_qs(parsed_url.query)
        if 'spaceKey' in query_params:
            return query_params['spaceKey'][0]
            
        # Try to find space key in the URL using regex
        space_key_match = re.search(r'[?&]key=([^&]+)', confluence_url)
        if space_key_match:
            return space_key_match.group(1)
            
        logging.warning(f"Could not extract space key from URL: {confluence_url}")
        return None
        
    except Exception as e:
        logging.error(f"Error extracting space key from URL: {str(e)}")
        return None

def load_confluence_documents(confluence_url):
    try:
        # Get credentials from environment variables
        credentials = get_confluence_credentials()
        api_key = credentials['api_key']
        username = credentials['username']
        
        # Validate credentials
        if not api_key or not username:
            error_msg = "Confluence credentials not found. Please check your .env file."
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        # Extract page ID and space key from URL
        page_id, space_key = extract_page_info_from_url(confluence_url)
        
        logging.info(f"Using Confluence URL: {confluence_url}")
        if page_id:
            logging.info(f"Targeting specific page ID: {page_id}")
        if space_key:
            logging.info(f"Using space key: {space_key}")
        
        # Extract the base domain for API calls
        parsed_url = urlparse(confluence_url)
        
        # Get the scheme (http/https) and netloc (domain)
        base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # For Atlassian Confluence Cloud URLs
        if 'atlassian.net' in base_domain:
            # The API endpoints are relative to the domain
            base_url = base_domain
            if not base_url.endswith('/'):
                base_url += '/'
            logging.info(f"Using Atlassian Cloud base URL: {base_url}")
        else:
            # For self-hosted Confluence, might need to include /wiki in the base URL
            # This is a simplification and might need adjustment for specific setups
            base_url = confluence_url
            if '/wiki' in base_url:
                base_url = base_url.split('/wiki')[0]
            if not base_url.endswith('/'):
                base_url += '/'
            logging.info(f"Using self-hosted Confluence base URL: {base_url}")
            
        # Create auth header using Basic Authentication
        auth_str = f"{username}:{api_key}"
        auth_bytes = auth_str.encode('ascii')
        base64_auth = base64.b64encode(auth_bytes).decode('ascii')
        headers = {
            'Authorization': f'Basic {base64_auth}',
            'Content-Type': 'application/json'
        }
        
        try:
            # Step 1: Get list of pages without expand parameter
            logging.info(f"Fetching page list from space: {space_key}")
            
            documents = []
            
            # If we have a specific page ID, fetch just that page
            if page_id:
                logging.info(f"Fetching specific page with ID: {page_id}")
                
                # Make direct API call to get the page with content
                content_url = f"{base_url}wiki/rest/api/content/{page_id}?expand=body.storage,version"
                content_response = requests.get(content_url, headers=headers)
                
                if not content_response.ok:
                    error_msg = f"Failed to fetch page with ID {page_id}: HTTP {content_response.status_code} - {content_response.text}"
                    logging.error(error_msg)
                    raise ValueError(error_msg)
                    
                page_data = content_response.json()
                page_title = page_data.get('title', 'Untitled')
                
                # Extract the content
                if 'body' in page_data and 'storage' in page_data['body']:
                    content = page_data['body']['storage']['value']
                    
                    # Create a document object
                    doc = Document(
                        page_content=content,
                        metadata={
                            'title': page_title,
                            'id': page_id,
                            'url': confluence_url,
                            'source': 'confluence'
                        }
                    )
                    documents.append(doc)
                    logging.info(f"Loaded document: {page_title}")
                else:
                    error_msg = f"Could not extract content from page with ID {page_id}"
                    logging.warning(error_msg)
                    raise ValueError(error_msg)
                    
            # If we don't have a page ID but have a space key, fetch all pages in the space
            elif space_key:
                logging.info(f"No specific page ID found. Fetching all pages from space: {space_key}")
                
                # Make direct API call to get pages
                pages_url = f"{base_url}wiki/rest/api/content"
                params = {
                    'spaceKey': space_key,
                    'limit': 1500,
                    'expand': 'version'  # Just get minimal info, not content
                }
                
                response = requests.get(pages_url, headers=headers, params=params)
                
                if not response.ok:
                    error_msg = f"Failed to fetch pages: HTTP {response.status_code} - {response.text}"
                    logging.error(error_msg)
                    raise ValueError(error_msg)
                    
                pages_data = response.json()
                
                if 'results' not in pages_data or not pages_data['results']:
                    error_msg = "No pages found in the specified Confluence space"
                    logging.warning(error_msg)
                    raise ValueError(error_msg)
                    
                pages = pages_data['results']
                logging.info(f"Found {len(pages)} pages in space {space_key}")
                
                # Fetch content for each page individually
                for page in pages:
                    page_id = page['id']
                    page_title = page.get('title', 'Untitled')
                    
                    try:
                        # Get the content
                        content_url = f"{base_url}wiki/rest/api/content/{page_id}?expand=body.storage"
                        content_response = requests.get(content_url, headers=headers)
                        
                        if not content_response.ok:
                            logging.warning(f"Failed to fetch content for page {page_title}: HTTP {content_response.status_code}")
                            continue
                            
                        content_data = content_response.json()
                        
                        # Extract the content
                        if 'body' in content_data and 'storage' in content_data['body']:
                            content = content_data['body']['storage']['value']
                            
                            # Create a document object
                            doc = Document(
                                page_content=content,
                                metadata={
                                    'title': page_title,
                                    'id': page_id,
                                    'url': f"{base_url}wiki/spaces/{space_key}/pages/{page_id}",
                                    'source': 'confluence'
                                }
                            )
                            documents.append(doc)
                            logging.info(f"Loaded document: {page_title}")
                        else:
                            logging.warning(f"Could not extract content from page {page_title}")
                            
                    except Exception as e:
                        # If we can't get content for a specific page, log and continue
                        logging.warning(f"Failed to process page {page_title}: {str(e)}")
                        continue
            else:
                error_msg = "Could not extract page ID or space key from URL. Please check the URL format."
                logging.error(error_msg)
                raise ValueError(error_msg)
            
            if not documents:
                error_msg = "Could not extract content from any pages in the space"
                logging.warning(error_msg)
                raise ValueError(error_msg)
                
            logging.info(f"Successfully loaded {len(documents)} documents from Confluence")
            return documents
            
        except Exception as e:
            error_msg = f"Failed to connect to Confluence: {str(e)}"
            logging.error(error_msg)
            raise ValueError(error_msg)
        
    except ValueError as e:
        # Re-raise ValueError for specific error messages
        raise
    except Exception as e:
        error_msg = f"Error loading Confluence documents: {str(e)}"
        logging.error(error_msg)
        raise ValueError(error_msg)

def decide_document_source(confluence_url, api_key=None, username=None, space_key=None, file_paths=None):
    try:
        print(f"[DEBUG] decide_document_source received file_paths: {file_paths}")
        logging.info(f"decide_document_source received file_paths: {file_paths}")
        
        if confluence_url:
            documents = load_confluence_documents(confluence_url)
        elif file_paths:
            # Handle single file path or list of file paths
            if isinstance(file_paths, list):
                print(f"[DEBUG] Processing multiple PDF files: {len(file_paths)} files")
                logging.info(f"Processing multiple PDF files: {len(file_paths)} files")
                documents = []
                for file_path in file_paths:
                    print(f"[DEBUG] Processing PDF file: {file_path}")
                    file_documents = process_pdf_file(file_path)
                    print(f"[DEBUG] Extracted {len(file_documents)} documents from {file_path}")
                    documents.extend(file_documents)
                print(f"[DEBUG] Total documents extracted from all PDFs: {len(documents)}")
            else:
                print(f"[DEBUG] Processing single PDF file: {file_paths}")
                documents = process_pdf_file(file_paths)
                print(f"[DEBUG] Extracted {len(documents)} documents from single PDF")
        else:
            logging.error("No valid document source provided")
            raise ValueError("No document source provided (neither Confluence credentials nor PDF file)")
            
        if not documents:
            logging.error("No documents were loaded from any source")
            raise ValueError("No documents were loaded from the provided source")
            
        logging.info(f"Successfully loaded {len(documents)} documents")
        return documents
        
    except Exception as e:
        logging.error(f"Error in decide_document_source: {str(e)}")
        raise