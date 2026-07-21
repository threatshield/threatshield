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
            elif assessment_name == 'details':
                return self.get_details_info(assessment_id)
            else:
                raise ValueError(f"Unknown name: {assessment_name}")
        else:
            # Return list of all assessments with their metadata
            return self._list_all_assessments()
            
    def _list_all_assessments(self):
        """List all assessments with metadata only (details.json content + existence flags for other reports).
        Does NOT load full report content — callers that need full data should fetch individual assessments."""
        assessments = []

        if not os.path.exists(self.base_dir):
            return assessments

        # Files that get a presence stub {result: True} rather than full content
        stub_report_files = {
            'rag_result.json': 'rag_result',
            'threat_model.json': 'threat_model',
            'dread_assessment.json': 'dread_assessment',
            'mitigation.json': 'mitigation',
            'attack_tree.json': 'attack_tree',
            'chat_history.json': 'chat_history',
            'prompts.json': 'prompts',
            'additionalinfo.json': 'additionalinfo',
        }

        for assessment_id in os.listdir(self.base_dir):
            assessment_dir = os.path.join(self.base_dir, assessment_id)

            if not os.path.isdir(assessment_dir):
                continue

            # Only read details.json for metadata
            details = None
            details_path = os.path.join(assessment_dir, 'details.json')
            if os.path.exists(details_path):
                try:
                    with open(details_path, 'r') as f:
                        details = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    pass

            # Build presence stubs without reading file contents
            available_reports = {}
            for filename, report_type in stub_report_files.items():
                if os.path.exists(os.path.join(assessment_dir, filename)):
                    available_reports[report_type] = {'result': True}

            # Load test_cases.json with full content so the frontend can compute
            # validated/total counts for the Validation column in ThreatModelList.
            tc_path = os.path.join(assessment_dir, 'test_cases.json')
            if os.path.exists(tc_path):
                try:
                    with open(tc_path, 'r') as f:
                        tc_data = json.load(f)
                    available_reports['test_cases'] = tc_data
                except (json.JSONDecodeError, FileNotFoundError):
                    available_reports['test_cases'] = {'result': True}

            # Skip assessment folders with no reports and no details
            if not available_reports and details is None:
                continue

            timestamp = (details or {}).get('timestamp') or datetime.utcnow().isoformat()
            name = (details or {}).get('projectName') or f"Assessment {assessment_id[:8]}"

            assessments.append({
                'id': assessment_id,
                'name': name,
                'timestamp': timestamp,
                'details': details,
                **available_reports
            })

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

    def save_tmbom(self, assessment_id: str, tmbom: dict):
        """Save TM-BOM to tmbom.json."""
        self._save_json(assessment_id, 'tmbom.json', tmbom)

    def get_tmbom(self, assessment_id: str):
        """Get TM-BOM from tmbom.json."""
        return self._load_json(assessment_id, 'tmbom.json')

    def save_ai_dast_validation(self, assessment_id, data):
        """Save AI DAST verification results to AI_DAST_ASVS_Validation.json."""
        self._save_json(assessment_id, 'AI_DAST_ASVS_Validation.json', data)

    def get_ai_dast_validation(self, assessment_id):
        """Get AI DAST verification results."""
        return self._load_json(assessment_id, 'AI_DAST_ASVS_Validation.json')

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
        
    def save_secbugs(self, assessment_id, secbugs_data):
        """Save SecBugs data."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "result": secbugs_data
        }
        self._save_json(assessment_id, 'secbug.json', data)
    
    def get_secbugs(self, assessment_id):
        """Get SecBugs data."""
        return self._load_json(assessment_id, 'secbug.json')
        
    def save_additional_info(self, assessment_id, additional_info):
        """Save additional info data."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "result": additional_info
        }
        self._save_json(assessment_id, 'additionalinfo.json', data)
    
    def get_additional_info(self, assessment_id):
        """Get additional info data."""
        return self._load_json(assessment_id, 'additionalinfo.json')
    
    def get_details_info(self, assessment_id):
        """Get additional info data."""
        return self._load_json(assessment_id, 'details.json')
        
    def append_log(self, assessment_id, level, step, message):
        """Append a log entry to storage/<assessment_id>/logs.json."""
        filepath = os.path.join(self.base_dir, assessment_id, 'logs.json')
        entry = {
            "ts": datetime.utcnow().isoformat() + 'Z',
            "level": level,
            "step": step,
            "message": message,
        }
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    data = json.load(f)
            else:
                data = {"assessment_id": assessment_id, "logs": []}
            data["logs"].append(entry)
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # Logging must never crash the pipeline

    def get_logs(self, assessment_id):
        """Get all log entries for an assessment."""
        return self._load_json(assessment_id, 'logs.json')

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

    def accumulate_pipeline_cost(self, assessment_id: str, stage: str, input_tokens: int, output_tokens: int, model: str):
        """Add token/cost data for one pipeline stage to details.json."""
        try:
            from llm.openai_module import OpenAIHandler
            cost = OpenAIHandler.estimate_cost(model, input_tokens, output_tokens)
            details_path = os.path.join(self.base_dir, assessment_id, 'details.json')
            details = {}
            if os.path.exists(details_path):
                with open(details_path, 'r') as f:
                    details = json.load(f)
            pc = details.setdefault('pipeline_cost', {
                'total_cost': 0.0, 'total_input_tokens': 0, 'total_output_tokens': 0,
                'model': model, 'breakdown': {}
            })
            pc['total_cost'] = round(pc.get('total_cost', 0.0) + cost, 6)
            pc['total_input_tokens'] = pc.get('total_input_tokens', 0) + input_tokens
            pc['total_output_tokens'] = pc.get('total_output_tokens', 0) + output_tokens
            pc['model'] = model
            pc.setdefault('breakdown', {})[stage] = {
                'cost': cost, 'input_tokens': input_tokens, 'output_tokens': output_tokens
            }
            with open(details_path, 'w') as f:
                json.dump(details, f, indent=2)
        except Exception as e:
            pass  # Cost tracking must never crash the pipeline

    def save_canonical_threats(self, assessment_id: str, threats: list):
        """Write the post-critic filtered threat list to details.json as canonicalThreats.

        Every downstream pipeline step (DREAD, mitigations, attack tree, test cases,
        diagram) should read from this key so they all operate on the same list
        regardless of how the threat model was originally generated.
        """
        try:
            details_path = os.path.join(self.base_dir, assessment_id, 'details.json')
            details = {}
            if os.path.exists(details_path):
                with open(details_path, 'r') as f:
                    details = json.load(f)
            details['canonicalThreats'] = threats
            with open(details_path, 'w') as f:
                json.dump(details, f, indent=2)
        except Exception:
            pass  # Must never crash the pipeline


_default_storage = None

def accumulate_pipeline_cost(assessment_id: str, stage: str, input_tokens: int, output_tokens: int, model: str):
    """Module-level helper so core modules don't need a StorageHandler instance."""
    global _default_storage
    if _default_storage is None:
        import os as _os
        _default_storage = StorageHandler(_os.environ.get('STORAGE_PATH', 'storage'))
    _default_storage.accumulate_pipeline_cost(assessment_id, stage, input_tokens, output_tokens, model)