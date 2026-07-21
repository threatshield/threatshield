import os
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QueueHandler:
    """Handles queue operations for threat modeling"""
    
    def __init__(self, queue_base_dir='queue'):
        self.queue_base_dir = queue_base_dir
        os.makedirs(queue_base_dir, exist_ok=True)
    
    def add_to_queue(self, secreview_id: str, initiated_by: str, prd_url: str, 
                     service_name: str, slack_thread: str, additional_data: Dict = None) -> Dict:
        """
        Add an item to the queue
        
        Args:
            secreview_id: Unique secreview identifier
            initiated_by: User who initiated the request
            prd_url: URL to PRD (Google Docs, Confluence, etc.)
            service_name: Name of the service
            slack_thread: Slack thread URL for discussion
            additional_data: Any additional metadata
        
        Returns:
            Queue item data with assessment_id
        """
        try:
            # Create secreview folder
            secreview_dir = os.path.join(self.queue_base_dir, secreview_id)
            os.makedirs(secreview_dir, exist_ok=True)
            
            # Generate unique assessment ID
            assessment_id = str(uuid.uuid4())
            
            # Create queue item
            queue_item = {
                "id": str(uuid.uuid4()),
                "secreview_id": secreview_id,
                "assessment_id": assessment_id,
                "initiated_by": initiated_by,
                "prd_url": prd_url,
                "service_name": service_name,
                "slack_thread": slack_thread,
                "created_at": datetime.utcnow().isoformat(),
                "status": "pending",  # pending, processing, completed, failed
                "additional_data": additional_data or {},
                "threat_model_status": None,
                "error_message": None
            }
            
            # Save queue item
            queue_file = os.path.join(secreview_dir, 'queue_item.json')
            with open(queue_file, 'w') as f:
                json.dump(queue_item, f, indent=2)
            
            logger.info(f"Added to queue: {secreview_id} with assessment_id: {assessment_id}")
            
            return queue_item
            
        except Exception as e:
            logger.error(f"Error adding to queue: {str(e)}")
            raise
    
    def get_queue_items(self) -> List[Dict]:
        """Get all queue items"""
        try:
            queue_items = []
            
            if not os.path.exists(self.queue_base_dir):
                return queue_items
            
            # Iterate through all secreview folders
            for secreview_id in os.listdir(self.queue_base_dir):
                secreview_path = os.path.join(self.queue_base_dir, secreview_id)
                
                if not os.path.isdir(secreview_path):
                    continue
                
                queue_file = os.path.join(secreview_path, 'queue_item.json')
                if os.path.exists(queue_file):
                    with open(queue_file, 'r') as f:
                        queue_item = json.load(f)
                        queue_items.append(queue_item)
            
            # Sort by creation date (newest first)
            queue_items.sort(key=lambda x: x['created_at'], reverse=True)
            
            return queue_items
            
        except Exception as e:
            logger.error(f"Error retrieving queue items: {str(e)}")
            raise
    
    def get_queue_item(self, secreview_id: str) -> Optional[Dict]:
        """Get specific queue item by secreview_id"""
        try:
            queue_file = os.path.join(self.queue_base_dir, secreview_id, 'queue_item.json')
            
            if not os.path.exists(queue_file):
                return None
            
            with open(queue_file, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            logger.error(f"Error retrieving queue item {secreview_id}: {str(e)}")
            raise
    
    def update_queue_item_status(self, secreview_id: str, status: str, 
                                 threat_model_status: str = None, 
                                 error_message: str = None) -> Dict:
        """Update queue item status"""
        try:
            queue_file = os.path.join(self.queue_base_dir, secreview_id, 'queue_item.json')
            
            if not os.path.exists(queue_file):
                raise ValueError(f"Queue item {secreview_id} not found")
            
            with open(queue_file, 'r') as f:
                queue_item = json.load(f)
            
            queue_item['status'] = status
            if threat_model_status:
                queue_item['threat_model_status'] = threat_model_status
            if error_message:
                queue_item['error_message'] = error_message
            
            queue_item['updated_at'] = datetime.utcnow().isoformat()
            
            with open(queue_file, 'w') as f:
                json.dump(queue_item, f, indent=2)
            
            logger.info(f"Updated queue item {secreview_id} status to {status}")
            
            return queue_item
            
        except Exception as e:
            logger.error(f"Error updating queue item {secreview_id}: {str(e)}")
            raise
    
    def get_pending_items(self) -> List[Dict]:
        """Get all pending items in queue"""
        try:
            all_items = self.get_queue_items()
            pending_items = [item for item in all_items if item['status'] == 'pending']
            return pending_items
            
        except Exception as e:
            logger.error(f"Error retrieving pending items: {str(e)}")
            raise
    
    def store_queue_data(self, secreview_id: str, data: Dict) -> None:
        """Store queue-related data (PDFs, additional files)"""
        try:
            data_dir = os.path.join(self.queue_base_dir, secreview_id, 'data')
            os.makedirs(data_dir, exist_ok=True)
            
            data_file = os.path.join(data_dir, 'queue_data.json')
            with open(data_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.info(f"Stored queue data for {secreview_id}")
            
        except Exception as e:
            logger.error(f"Error storing queue data: {str(e)}")
            raise
    
    def get_queue_data(self, secreview_id: str) -> Optional[Dict]:
        """Get queue-related data"""
        try:
            data_file = os.path.join(self.queue_base_dir, secreview_id, 'data', 'queue_data.json')
            
            if not os.path.exists(data_file):
                return None
            
            with open(data_file, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            logger.error(f"Error retrieving queue data for {secreview_id}: {str(e)}")
            raise
    
    def delete_queue_item(self, secreview_id: str) -> bool:
        """Delete a queue item"""
        try:
            import shutil
            secreview_dir = os.path.join(self.queue_base_dir, secreview_id)
            
            if os.path.exists(secreview_dir):
                shutil.rmtree(secreview_dir)
                logger.info(f"Deleted queue item {secreview_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error deleting queue item {secreview_id}: {str(e)}")
            raise