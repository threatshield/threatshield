import os
import json
import logging
from typing import Optional, Dict
from google.oauth2.service_account import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GoogleDocsHandler:
    """Handles Google Docs PRD fetching using service account"""
    
    def __init__(self):
        self.service = None
        self._authenticate()
    
    def _authenticate(self) -> bool:
        """Authenticate using service account credentials from .env"""
        try:
            # Get Google service account key from environment
            google_key_json = os.getenv('GOOGLE_SERVICE_ACCOUNT_JSON')
            
            if not google_key_json:
                logger.warning("GOOGLE_SERVICE_ACCOUNT_JSON not configured in .env")
                return False
            
            # Parse the service account key
            try:
                if google_key_json.startswith('{'):
                    # If it's a JSON string, parse it directly
                    service_account_info = json.loads(google_key_json)
                else:
                    # If it's a file path, read from file
                    with open(google_key_json, 'r') as f:
                        service_account_info = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError) as e:
                logger.error(f"Error loading service account key: {str(e)}")
                return False
            
            # Create credentials
            credentials = Credentials.from_service_account_info(
                service_account_info,
                scopes=['https://www.googleapis.com/auth/documents.readonly']
            )
            
            # Build the Docs API client
            self.service = build('docs', 'v1', credentials=credentials)
            logger.info("Successfully authenticated with Google Docs API")
            return True
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False
    
    def extract_document_id(self, url: str) -> Optional[str]:
        """Extract document ID from Google Docs URL"""
        try:
            # Handle various Google Docs URL formats
            if '/document/d/' in url:
                # https://docs.google.com/document/d/{id}/edit
                doc_id = url.split('/document/d/')[1].split('/')[0]
                return doc_id
            elif '/d/' in url:
                # Shortened format
                doc_id = url.split('/d/')[1].split('/')[0]
                return doc_id
            else:
                logger.error(f"Invalid Google Docs URL format: {url}")
                return None
                
        except Exception as e:
            logger.error(f"Error extracting document ID: {str(e)}")
            return None
    
    def fetch_document_content(self, doc_url: str) -> Optional[Dict]:
        """Fetch content from Google Docs"""
        try:
            if not self.service:
                logger.error("Not authenticated with Google Docs API")
                return None
            
            # Extract document ID from URL
            doc_id = self.extract_document_id(doc_url)
            if not doc_id:
                return None
            
            # Fetch the document
            document = self.service.documents().get(documentId=doc_id).execute()
            
            # Extract text content
            content = self._extract_text_from_document(document)
            
            return {
                "title": document.get('title', 'Untitled'),
                "content": content,
                "doc_id": doc_id,
                "url": doc_url,
                "source": "google_docs"
            }
            
        except HttpError as e:
            logger.error(f"Google Docs API error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error fetching Google Docs content: {str(e)}")
            return None
    
    def _extract_text_from_document(self, document: Dict) -> str:
        """Extract plain text from Google Docs document structure"""
        try:
            content = []
            
            if 'body' not in document:
                return ""
            
            for element in document['body'].get('content', []):
                if 'paragraph' in element:
                    text = self._extract_paragraph_text(element['paragraph'])
                    if text:
                        content.append(text)
                elif 'table' in element:
                    text = self._extract_table_text(element['table'])
                    if text:
                        content.append(text)
            
            return '\n\n'.join(content)
            
        except Exception as e:
            logger.error(f"Error extracting text: {str(e)}")
            return ""
    
    def _extract_paragraph_text(self, paragraph: Dict) -> str:
        """Extract text from a paragraph element"""
        try:
            text_parts = []
            
            for element in paragraph.get('elements', []):
                if 'textRun' in element:
                    text_parts.append(element['textRun']['content'])
            
            return ''.join(text_parts).strip()
            
        except Exception as e:
            logger.error(f"Error extracting paragraph: {str(e)}")
            return ""
    
    def _extract_table_text(self, table: Dict) -> str:
        """Extract text from a table element"""
        try:
            rows = []
            
            for row in table.get('tableRows', []):
                cells = []
                for cell in row.get('tableCells', []):
                    cell_content = []
                    for element in cell.get('content', []):
                        if 'paragraph' in element:
                            text = self._extract_paragraph_text(element['paragraph'])
                            if text:
                                cell_content.append(text)
                    cells.append(' | '.join(cell_content))
                rows.append(' || '.join(cells))
            
            return '\n'.join(rows)
            
        except Exception as e:
            logger.error(f"Error extracting table: {str(e)}")
            return ""
    
    def is_configured(self) -> bool:
        """Check if Google Docs is properly configured"""
        return self.service is not None


def fetch_prd_content(prd_url: str) -> Optional[Dict]:
    """
    Fetch PRD content from various sources
    
    Supports:
    - Google Docs
    - Confluence
    - Direct URLs
    """
    try:
        # Check if it's a Google Docs URL
        if 'docs.google.com' in prd_url:
            handler = GoogleDocsHandler()
            if not handler.is_configured():
                logger.warning("Google Docs not configured, but URL points to Google Docs")
                return None
            return handler.fetch_document_content(prd_url)
        
        # Check if it's a Confluence URL (including Atlassian Cloud: atlassian.net)
        elif 'atlassian.net' in prd_url.lower() or 'confluence' in prd_url.lower():
            from utils.confluence_handler import load_confluence_documents
            try:
                docs = load_confluence_documents(prd_url)
                if docs:
                    content = '\n\n'.join([doc.page_content for doc in docs])
                    return {
                        "title": "Confluence Document",
                        "content": content,
                        "url": prd_url,
                        "source": "confluence"
                    }
            except Exception as e:
                logger.error(f"Error fetching Confluence document: {str(e)}")
                return None
        
        else:
            logger.warning(f"Unsupported PRD URL format: {prd_url}")
            return None
            
    except Exception as e:
        logger.error(f"Error fetching PRD content: {str(e)}")
        return None