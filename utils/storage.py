import json
import os
import uuid
from datetime import datetime
from langchain_core.messages import HumanMessage, AIMessage

class StorageHandler:
    def __init__(self, base_dir='storage'):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        
    def save_prompts(self, assessment_id, prompts_data):
        """Save prompts used for generating threat model, attack tree, mitigations, and DREAD."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "prompts": prompts_data
        }
        self._save_json(assessment_id, 'prompts.json', data)
        
    def get_prompts(self, assessment_id):
        """Get prompts used for generating threat model, attack tree, mitigations, and DREAD."""
        return self._load_json(assessment_id, 'prompts.json')
        
    def create_assessment(self):
        """Create a new assessment directory and return its ID."""
        assessment_id = str(uuid.uuid4())
        assessment_dir = os.path.join(self.base_dir, assessment_id)
        os.makedirs(assessment_dir, exist_ok=True)
        return assessment_id
    
    def retrive_from_storage(self, assessment_id=None, assessment_name=None):
        """Retrieve specific results from the assessment or list all assessments"""
        if assessment_id:
            # Return specific assessment data
            if assessment_name == 'rag_result':
                return self.get_rag_result(assessment_id)
            elif assessment_name == 'threat_model':
                return self.get_threat_model(assessment_id)
            elif assessment_name == 'dread_assessment':
                return self.get_dread_assessment(assessment_id)
            elif assessment_name == 'mitigation':
                return self.get_mitigation_result(assessment_id)
            elif assessment_name == 'attack_tree':
                return self.get_attack_tree(assessment_id)
            elif assessment_name == 'test_cases':
                return self.get_test_cases(assessment_id)
            elif assessment_name == 'chat_history':
                return self.get_chat_history(assessment_id)
            elif assessment_name == 'prompts':
                return self.get_prompts(assessment_id)
            elif assessment_name == 'additionalinfo':
                return self.get_additional_info(assessment_id)
            else:
                raise ValueError(f"Unknown name: {assessment_name}")
        else:
            # Return list of all assessments with their metadata
            return self._list_all_assessments()
            
    def _list_all_assessments(self):
        """List all assessments and their available reports"""
        assessments = []
        
        # Check if base directory exists
        if not os.path.exists(self.base_dir):
            return assessments
            
        # Iterate through all assessment directories
        for assessment_id in os.listdir(self.base_dir):
            assessment_dir = os.path.join(self.base_dir, assessment_id)
            
            # Skip if not a directory
            if not os.path.isdir(assessment_dir):
                continue
                
            # Get available report types
            available_reports = {}
            report_types = {
                'rag_result.json': 'rag_result',
                'threat_model.json': 'threat_model',
                'dread_assessment.json': 'dread_assessment',
                'mitigation.json': 'mitigation',
                'attack_tree.json': 'attack_tree',
                'test_cases.json': 'test_cases',
                'chat_history.json': 'chat_history',
                'prompts.json': 'prompts'
            }
            
            # Get timestamp from any available report
            timestamp = None
            name = None
            
            # Check which reports exist and get metadata
            for filename, report_type in report_types.items():
                filepath = os.path.join(assessment_dir, filename)
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            data = json.load(f)
                            available_reports[report_type] = data  # Store full report data
                            
                            # If we don't have timestamp yet, get it from this report
                            if timestamp is None:
                                timestamp = data.get('timestamp')
                            
                            # Try to get a name from threat model if available
                            if report_type == 'threat_model' and 'result' in data:
                                result = data['result']
                                if isinstance(result, dict) and 'name' in result:
                                    name = result['name']
                    except (json.JSONDecodeError, FileNotFoundError):
                        pass
            
            # Only add if we found at least one report
            if available_reports:
                assessments.append({
                    'id': assessment_id,
                    'name': name or f"Assessment {assessment_id[:8]}",
                    'timestamp': timestamp or datetime.utcnow().isoformat(),
                    **available_reports
                })
                
        # Sort by timestamp, newest first
        assessments.sort(key=lambda x: x['timestamp'], reverse=True)
        return assessments
        
    def save_rag_result(self, assessment_id, rag_result):
        """Save RAG processing results."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "result": rag_result
        }
        self._save_json(assessment_id, 'rag_result.json', data)
        
    def save_threat_model(self, assessment_id, threat_model_result):
        """Save threat model results."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "result": threat_model_result
        }
        self._save_json(assessment_id, 'threat_model.json', data)
        
    def save_dread_assessment(self, assessment_id, dread_result):
        """Save DREAD assessment results."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "result": dread_result
        }
        self._save_json(assessment_id, 'dread_assessment.json', data)
        
    def get_rag_result(self, assessment_id):
        """Get RAG processing results."""
        return self._load_json(assessment_id, 'rag_result.json')
        
    def get_threat_model(self, assessment_id):
        """Get threat model results."""
        return self._load_json(assessment_id, 'threat_model.json')
        
    def get_dread_assessment(self, assessment_id):
        """Get DREAD assessment results."""
        return self._load_json(assessment_id, 'dread_assessment.json')
        
    def save_mitigation_result(self, assessment_id, mitigation_result):
        """Save mitigation results."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "result": mitigation_result
        }
        self._save_json(assessment_id, 'mitigation.json', data)
        
    def get_mitigation_result(self, assessment_id):
        """Get mitigation results."""
        return self._load_json(assessment_id, 'mitigation.json')
        
    def save_attack_tree(self, assessment_id, attack_tree_result):
        """Save attack tree results."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "result": attack_tree_result
        }
        self._save_json(assessment_id, 'attack_tree.json', data)
        
    def get_attack_tree(self, assessment_id):
        """Get attack tree results."""
        return self._load_json(assessment_id, 'attack_tree.json')
        
    def save_test_cases(self, assessment_id, test_cases_result):
        """Save test cases results."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "result": test_cases_result
        }
        self._save_json(assessment_id, 'test_cases.json', data)
        
    def get_test_cases(self, assessment_id):
        """Get test cases results."""
        return self._load_json(assessment_id, 'test_cases.json')

    def save_chat_history(self, assessment_id, messages):
        """Save chat history."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "result": [
                {"role": "user" if isinstance(msg, HumanMessage) else "assistant", "content": msg.content}
                for msg in messages
            ]
        }
        self._save_json(assessment_id, 'chat_history.json', data)

    def get_chat_history(self, assessment_id):
        """Get chat history."""
        return self._load_json(assessment_id, 'chat_history.json')
        
    def save_additional_info(self, assessment_id, additional_info):
        """Save additional info including functional flows and third party integrations."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "result": additional_info
        }
        self._save_json(assessment_id, 'additionalinfo.json', data)
        
    def get_additional_info(self, assessment_id):
        """Get additional info including functional flows and third party integrations."""
        return self._load_json(assessment_id, 'additionalinfo.json')
        
    def _save_json(self, assessment_id, filename, data):
        """Helper method to save JSON data."""
        filepath = os.path.join(self.base_dir, assessment_id, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
            
    def _load_json(self, assessment_id, filename):
        """Helper method to load JSON data."""
        try:
            filepath = os.path.join(self.base_dir, assessment_id, filename)
            with open(filepath, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return None
