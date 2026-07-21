from flask import Flask, request, jsonify, render_template, session, Response, send_from_directory
from flask_cors import CORS
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import traceback
from utils.config import get_openai_api_key, test_confluence_connection, test_slack_connection, get_llm_method, get_bedrock_config, get_mcp_admins, save_admins, save_llm_config, set_llm_tested, is_llm_tested, _get_settings, _save_settings, get_threat_filter_config, save_threat_filter_config, get_teams, save_teams, set_setup_dismissed
from utils.jira import fetch_jira_tickets
import os
import re
import glob as _glob
import datetime
from urllib.parse import urlparse
from pdfminer.high_level import extract_text
from utils.confluence_handler import decide_document_source, load_confluence_documents
from utils.slack_handler import load_slack_thread, send_slack_dm
from langchain_core.documents import Document
from utils.document_handler import process_pdf_file
from rag.rag_handler import RAGHandler
from llm.openai_module import OpenAIHandler
from core.threat_modeling import ThreatModelingHandler
from core.dread import DreadHandler
from core.mitigation import MitigationHandler
from core.attack_tree import AttackTreeHandler
from core.asvs_test_cases import ASVSTestCaseGenerator
from core.generate_diagram import DiagramGenerator
from utils.storage import StorageHandler
from utils.queue_handler import QueueHandler
from utils.google_docs_handler import fetch_prd_content
from utils import mcp_handler
from utils.pdf_generator import generate_pdf_report

import base64
from core.chat import Chat
import json
import uuid
import logging
import threading
import time
import queue as _queue_module
import concurrent.futures as _cf

# Configure logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change-me-in-production')

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')

_STORAGE_DIR = os.environ.get('STORAGE_PATH', 'storage')
_UPLOAD_DIR = os.environ.get('UPLOAD_PATH', 'uploads')

_ALLOWED_ORIGINS = [o.strip() for o in os.getenv(
    'ALLOWED_ORIGINS',
    'http://localhost:3000,http://localhost:5001'
).split(',') if o.strip()]

CORS(app, resources={
    r"/api/*": {
        "origins": _ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Origin", "Accept"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})
app.config['UPLOAD_FOLDER'] = _UPLOAD_DIR

# Token serializer for stateless auth tokens (itsdangerous is bundled with Flask)
_token_serializer = URLSafeTimedSerializer(app.secret_key)
_TOKEN_MAX_AGE = 60 * 60 * 24 * 7  # 7 days


def _get_request_user():
    """Extract and verify the Bearer token from the Authorization header."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    token = auth_header[7:]
    try:
        return _token_serializer.loads(token, max_age=_TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def _is_mcp_admin() -> bool:
    """Return True if the current request user is in the MCP_ADMINS list."""
    user = _get_request_user()
    if not user:
        return False
    admins = get_mcp_admins()
    # Empty list → no one is an admin; treat as feature disabled
    if not admins:
        return False
    return user.get('email', '').lower() in admins

# Custom error handler to capture and format all errors
@app.errorhandler(Exception)
def handle_exception(e):
    # Get the full traceback
    error_traceback = traceback.format_exc()
    # Log the error with traceback
    logging.error(f"Unhandled exception: {str(e)}\n{error_traceback}")
    
    # Format the error response
    error_response = {
        "error": str(e),
        "traceback": error_traceback,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    
    # Return a JSON response with the error details
    return jsonify(error_response), 500


# ─── Authentication ──────────────────────────────────────────────────────────

@app.before_request
def require_login():
    """Block all /api/* requests (except auth and public feedback endpoints) unless a valid Bearer token is present."""
    if request.method == 'OPTIONS':
        return None
    if request.path.startswith('/api/auth/'):
        return None
    # Public: queue endpoints and threat-model status (used by external/unauthenticated callers)
    if (request.path.startswith('/api/queue')
            or request.path == '/api/threat-model/status'
            or request.path == '/api/metrics'):
        return None
    # Public feedback endpoints: GET /api/feedback/<uuid> and POST /api/feedback/<uuid>/submit
    import re as _re
    if _re.match(r'^/api/feedback/[^/]+(|/submit)$', request.path):
        return None
    if request.path.startswith('/api/'):
        if not _get_request_user():
            return jsonify({'error': 'Unauthorized', 'message': 'Login required'}), 401
    return None


@app.route('/api/auth/google', methods=['POST'])
def google_login():
    google_token = (request.json or {}).get('token', '')
    if not google_token:
        return jsonify({'error': 'Missing token'}), 400
    if not GOOGLE_CLIENT_ID:
        return jsonify({'error': 'Google OAuth not configured on server'}), 500
    try:
        idinfo = id_token.verify_oauth2_token(
            google_token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        email = idinfo.get('email', '')
        user = {
            'email': email,
            'name': idinfo.get('name', ''),
            'picture': idinfo.get('picture', ''),
        }
        auth_token = _token_serializer.dumps(user)
        return jsonify({'user': user, 'token': auth_token})
    except Exception as exc:
        logging.warning(f"Google token verification failed: {exc}")
        return jsonify({'error': 'Invalid or expired Google token'}), 401


@app.route('/api/auth/user', methods=['GET'])
def get_current_user():
    user = _get_request_user()
    if user:
        return jsonify({'user': user})
    return jsonify({'user': None}), 401


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    # Token-based auth — the client is responsible for discarding the token
    return jsonify({'message': 'Logged out successfully'})


# ─── Initialize handlers ─────────────────────────────────────────────────────

storage_handler = StorageHandler(base_dir=_STORAGE_DIR)
queue_handler = QueueHandler()
openai_handler = OpenAIHandler()
threat_modeling_handler = ThreatModelingHandler(openai_handler)
asvs_generator = ASVSTestCaseGenerator(openai_handler)

# Global chat instance to maintain conversation history across requests
chat_instance = None

# Auto-trigger: single worker processes one assessment at a time
_auto_trigger_queue = _queue_module.Queue()
_auto_trigger_lock = threading.Lock()
_processing_semaphore = threading.Semaphore(1)  # only one assessment pipeline runs at a time

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def extract_text_from_pdf(pdf_path):
    return extract_text(pdf_path)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/status/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'OK'}), 200

def _is_cancelled(assessment_id):
    """Return True if the assessment has been cancelled by the user."""
    details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
    try:
        with open(details_path, 'r') as f:
            return json.load(f).get('status') == 'cancelled'
    except Exception:
        return False


def _update_assessment_step(assessment_id, step, status=None):
    """Helper to update current_step (and optionally status) in details.json"""
    details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
    if os.path.exists(details_path):
        try:
            with open(details_path, 'r') as f:
                d = json.load(f)
            # Never overwrite a 'cancelled' status from background pipeline steps.
            # However, an explicit restart (status='processing') must be allowed through.
            if d.get('status') == 'cancelled' and status != 'processing':
                return
            d['current_step'] = step
            if status:
                d['status'] = status
            # Clear any previous error message when restarting
            if status == 'processing':
                d.pop('error_message', None)
            # Update timestamp to reflect when the (re)run completed
            if status == 'completed':
                d['timestamp'] = datetime.datetime.utcnow().isoformat()
            with open(details_path, 'w') as f:
                json.dump(d, f, indent=2)
        except Exception as e:
            logging.error(f"[BACKGROUND] Error updating step to '{step}': {e}")


def _assessment_log(assessment_id, level, step, message):
    """Write a structured log entry to storage/<assessment_id>/logs.json."""
    logging.log(
        logging.ERROR if level == 'ERROR' else logging.WARNING if level == 'WARNING' else logging.INFO,
        f"[{step.upper()}] {assessment_id}: {message}"
    )
    storage_handler.append_log(assessment_id, level, step, message)


def _run_queue_pipeline_steps(assessment_id, rag_output):
    """Run the full threat modeling pipeline after RAG for queue items."""
    details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')

    # Support both old string format (rag_output is plain str) and new dict format
    if isinstance(rag_output, dict):
        rag_result_str = rag_output.get('app_summary', '')
        security_context = rag_output.get('security_context', {})
    else:
        rag_result_str = rag_output
        security_context = {}

    # Load details for pipeline inputs
    try:
        with open(details_path, 'r') as f:
            details = json.load(f)
    except Exception as e:
        logging.error(f"[PIPELINE] Cannot load details for {assessment_id}: {e}")
        _assessment_log(assessment_id, 'ERROR', 'pipeline', f"Cannot load details: {e}")
        return

    app_type = details.get('applicationType', 'Not specified')
    authentication_str = details.get('authenticationMethod', 'Not specified')
    internet_facing = "Yes" if details.get('isInternetFacing', False) else "No"
    sensitive_data = details.get('dataSensitivityLevel', 'Not specified')

    # Build custom prompt from additionalinfo.json
    custom_prompt = ""
    additionalinfo_path = os.path.join(_STORAGE_DIR, assessment_id, 'additionalinfo.json')
    if os.path.exists(additionalinfo_path):
        try:
            with open(additionalinfo_path, 'r') as f:
                additionalinfo = json.load(f)
            if additionalinfo.get('confluenceDoc') and additionalinfo['confluenceDoc'].get('content'):
                custom_prompt += f"\n\nAdditional Confluence Content:\n{additionalinfo['confluenceDoc']['content']}"
            if additionalinfo.get('slackThread') and additionalinfo['slackThread'].get('content'):
                custom_prompt += f"\n\nSlack Thread Content:\n{additionalinfo['slackThread']['content']}"
            if additionalinfo.get('meetingTranscript') and additionalinfo['meetingTranscript'].get('content'):
                custom_prompt += f"\n\nMeeting Transcript:\n{additionalinfo['meetingTranscript']['content']}"
            if additionalinfo.get('prdDoc') and additionalinfo['prdDoc'].get('content'):
                custom_prompt += f"\n\nPRD Document Content:\n{additionalinfo['prdDoc']['content']}"
        except Exception as e:
            logging.error(f"[PIPELINE] Error loading additionalinfo: {e}")

    # Get SecBugs
    secbugs_data = storage_handler.get_secbugs(assessment_id)
    if secbugs_data and 'result' in secbugs_data and secbugs_data['result']:
        secbugs_list = secbugs_data['result']
        secbugs = ", ".join([f"{bug['id']}: {bug['name']} (Status: {bug['status']}, Priority: {bug['priority']})" for bug in secbugs_list])
    else:
        secbugs = "No security bugs found for this Department."

    # Get org context
    org_context = ""
    try:
        settings = _get_settings()
        preContextType = settings.get('preContextType', 'custom')
        org_context = settings.get('preContext', '')
    except Exception:
        pass

    # Get MCP context from enabled MCP servers
    assessment_name = details.get('name', '')
    mcp_context = ""
    try:
        mcp_context = mcp_handler.run_mcp_tools_for_threat_model(assessment_name, rag_result_str[:2000])
        if mcp_context:
            logging.info(f"[PIPELINE] MCP context collected ({len(mcp_context)} chars)")
    except Exception as exc:
        logging.warning(f"[PIPELINE] MCP context collection failed: {exc}")

    _openai = OpenAIHandler()
    _tm_handler = ThreatModelingHandler(_openai)
    raw_response = None

    # Step 1: Threat model
    if _is_cancelled(assessment_id):
        logging.info(f"[PIPELINE] {assessment_id} cancelled — stopping before threat model")
        _assessment_log(assessment_id, 'WARNING', 'threat_model', "Cancelled before threat model")
        return
    _existing_tm = storage_handler.get_threat_model(assessment_id)
    raw_response = None
    if _existing_tm and _existing_tm.get('result', {}).get('raw_response'):
        raw_response = _existing_tm['result']['raw_response']
        logging.info(f"[PIPELINE] Threat model already exists for {assessment_id} — skipping")
        _assessment_log(assessment_id, 'INFO', 'threat_model', "Threat model already exists — skipping")
        # Backfill canonicalThreats for assessments run before this key was introduced.
        details_check = storage_handler.get_details_info(assessment_id) or {}
        if not details_check.get('canonicalThreats'):
            storage_handler.save_canonical_threats(assessment_id, raw_response.get('threat_model', []))
    else:
        try:
            _update_assessment_step(assessment_id, 'threat_model')
            logging.info(f"[PIPELINE] Generating threat model for {assessment_id}")
            _assessment_log(assessment_id, 'INFO', 'threat_model', "Starting threat model generation")
            tm_result = _tm_handler.generate_threat_model(
                app_type=app_type,
                authentication=authentication_str,
                internet_facing=internet_facing,
                sensitive_data=sensitive_data,
                app_input=rag_result_str,
                secbugs=secbugs,
                custom_prompt=custom_prompt,
                org_context=org_context,
                assessment_id=assessment_id,
                security_context=security_context,
                mcp_context=mcp_context,
            )
            raw_response = {
                "threat_model": tm_result["threat_model"],
                "improvement_suggestions": tm_result["improvement_suggestions"]
            }
            storage_handler.save_threat_model(assessment_id, {
                "raw_response": raw_response,
                "markdown": tm_result["markdown"],
                "critic_pass": tm_result.get("critic_pass") or {},
            })
            storage_handler.save_canonical_threats(assessment_id, tm_result["threat_model"])
            prompts_data = storage_handler.get_prompts(assessment_id) or {"prompts": {}}
            if _tm_handler.last_generated_prompt:
                prompts_data["prompts"]["threat_model"] = _tm_handler.last_generated_prompt
                storage_handler.save_prompts(assessment_id, prompts_data["prompts"])
            logging.info(f"[PIPELINE] Threat model saved for {assessment_id}")
            _assessment_log(assessment_id, 'INFO', 'threat_model', "Threat model generated successfully")
        except Exception as e:
            logging.error(f"[PIPELINE] Error generating threat model for {assessment_id}: {e}", exc_info=True)
            _assessment_log(assessment_id, 'ERROR', 'threat_model', f"Failed to generate threat model: {e}")

    if raw_response is None:
        logging.error(f"[PIPELINE] Threat model failed — aborting pipeline for {assessment_id}")
        _assessment_log(assessment_id, 'ERROR', 'pipeline', "Pipeline aborted: threat model generation failed")
        _update_assessment_step(assessment_id, 'threat_model', status='failed')
        return

    # Phase 2: All downstream steps run in parallel — each only requires raw_response.
    # attack_tree and dread are enrichment context for mitigations in the old sequential flow;
    # running without them is the accepted trade-off for the parallelism gain.
    if _is_cancelled(assessment_id):
        _assessment_log(assessment_id, 'WARNING', 'pipeline', "Cancelled before parallel analysis phase")
        return

    # Serialises concurrent reads + writes to prompts.json to prevent last-write-wins data loss.
    prompts_lock = threading.Lock()

    def _save_prompt(step_key, prompt_value):
        with prompts_lock:
            prompts_data = storage_handler.get_prompts(assessment_id) or {"prompts": {}}
            prompts_data["prompts"][step_key] = prompt_value
            storage_handler.save_prompts(assessment_id, prompts_data["prompts"])

    # Mark the parallel phase as a single step so the UI shows one coherent message.
    _update_assessment_step(assessment_id, 'parallel_analysis')

    def _run_attack_tree():
        if _is_cancelled(assessment_id):
            return
        _existing_at = storage_handler.get_attack_tree(assessment_id)
        if _existing_at and _existing_at.get('result'):
            _assessment_log(assessment_id, 'INFO', 'attack_tree', "Attack tree already exists — skipping")
            return
        try:
            _assessment_log(assessment_id, 'INFO', 'attack_tree', "Starting attack tree generation")
            _attack_tree_handler = AttackTreeHandler(_openai)
            attack_tree_prompt = _attack_tree_handler.create_attack_tree_prompt(raw_response, assessment_id)
            result = _attack_tree_handler.generate_attack_tree(raw_response, assessment_id)
            if "attack_tree" not in result:
                result["attack_tree"] = {"nodes": [{"id": "root", "type": "goal", "label": "Attack Tree"}]}
            if "markdown" in result:
                result["markdown"] = f"```mermaid\n{result['markdown']}\n```"
            storage_handler.save_attack_tree(assessment_id, result)
            _save_prompt("attack_tree", attack_tree_prompt)
            _assessment_log(assessment_id, 'INFO', 'attack_tree', "Attack tree generated successfully")
        except Exception as e:
            logging.error(f"[PIPELINE] Error generating attack tree for {assessment_id}: {e}")
            _assessment_log(assessment_id, 'ERROR', 'attack_tree', f"Failed to generate attack tree: {e}")

    def _run_diagrams():
        if _is_cancelled(assessment_id):
            return
        try:
            _assessment_log(assessment_id, 'INFO', 'diagrams', "Starting diagram generation")
            _diagram_generator = DiagramGenerator(_openai)
            _diagram_generator.generate_diagrams(raw_response, assessment_id)
            error_files = _glob.glob(os.path.join(_STORAGE_DIR, assessment_id, '*_error.json'))
            if error_files:
                for ef in error_files:
                    diagram_type = os.path.basename(ef).replace('_error.json', '')
                    try:
                        with open(ef) as f:
                            err_data = json.load(f)
                        _assessment_log(assessment_id, 'ERROR', 'diagrams',
                                        f"Diagram '{diagram_type}' failed: {err_data.get('error', 'unknown error')}")
                    except Exception:
                        _assessment_log(assessment_id, 'ERROR', 'diagrams',
                                        f"Diagram '{diagram_type}' failed (could not read error file)")
            else:
                _assessment_log(assessment_id, 'INFO', 'diagrams', "Architecture diagrams generated successfully")
        except Exception as e:
            logging.error(f"[PIPELINE] Error generating diagrams for {assessment_id}: {e}")
            _assessment_log(assessment_id, 'ERROR', 'diagrams', f"Failed to generate diagrams: {e}")

    def _run_dread():
        if _is_cancelled(assessment_id):
            return
        _existing_dread = storage_handler.get_dread_assessment(assessment_id)
        if _existing_dread and _existing_dread.get('result'):
            _assessment_log(assessment_id, 'INFO', 'dread', "DREAD assessment already exists — skipping")
            return
        try:
            _assessment_log(assessment_id, 'INFO', 'dread', "Starting DREAD assessment generation")
            _dread_handler = DreadHandler(_openai)
            dread_prompt = _dread_handler.create_dread_assessment_prompt(raw_response, None, assessment_id, security_context)
            result = _dread_handler.generate_dread_assessment(dread_prompt, assessment_id)
            storage_handler.save_dread_assessment(assessment_id, result)
            _save_prompt("dread", dread_prompt)
            _assessment_log(assessment_id, 'INFO', 'dread', "DREAD assessment generated successfully")
        except Exception as e:
            logging.error(f"[PIPELINE] Error generating DREAD for {assessment_id}: {e}")
            _assessment_log(assessment_id, 'ERROR', 'dread', f"Failed to generate DREAD assessment: {e}")

    def _run_mitigations():
        if _is_cancelled(assessment_id):
            return
        _existing_mit = storage_handler.get_mitigation_result(assessment_id)
        if _existing_mit and _existing_mit.get('result'):
            _assessment_log(assessment_id, 'INFO', 'mitigation', "Mitigations already exist — skipping")
            return
        try:
            _assessment_log(assessment_id, 'INFO', 'mitigation', "Starting mitigation generation")
            _mitigation_handler = MitigationHandler(_openai)
            mitigation_prompt = _mitigation_handler.create_mitigations_prompt(raw_response, assessment_id)
            result = _mitigation_handler.generate_mitigations(mitigation_prompt, assessment_id)
            storage_handler.save_mitigation_result(assessment_id, result)
            _save_prompt("mitigation", mitigation_prompt)
            _assessment_log(assessment_id, 'INFO', 'mitigation', "Mitigations generated successfully")
        except Exception as e:
            logging.error(f"[PIPELINE] Error generating mitigations for {assessment_id}: {e}")
            _assessment_log(assessment_id, 'ERROR', 'mitigation', f"Failed to generate mitigations: {e}")

    def _run_test_cases():
        if _is_cancelled(assessment_id):
            return
        _existing_tc = storage_handler.get_test_cases(assessment_id)
        if _existing_tc and _existing_tc.get('result'):
            _assessment_log(assessment_id, 'INFO', 'test_cases', "Test cases already exist — skipping")
            return
        try:
            _assessment_log(assessment_id, 'INFO', 'test_cases', "Starting ASVS test case generation")
            _asvs_gen = ASVSTestCaseGenerator(_openai)
            asvs_prompt = _asvs_gen.create_asvs_test_cases_prompt(raw_response, assessment_id)
            result = _asvs_gen.generate_asvs(raw_response, assessment_id)
            storage_handler.save_test_cases(assessment_id, result)
            _save_prompt("asvs_test_cases", asvs_prompt)
            _assessment_log(assessment_id, 'INFO', 'test_cases', "ASVS test cases generated successfully")
        except Exception as e:
            logging.error(f"[PIPELINE] Error generating test cases for {assessment_id}: {e}")
            _assessment_log(assessment_id, 'ERROR', 'test_cases', f"Failed to generate test cases: {e}")

    _assessment_log(assessment_id, 'INFO', 'pipeline',
                    "Starting parallel analysis phase (attack_tree, diagrams, dread, mitigations, test_cases)")
    with _cf.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(_run_attack_tree): 'attack_tree',
            executor.submit(_run_diagrams): 'diagrams',
            executor.submit(_run_dread): 'dread',
            executor.submit(_run_mitigations): 'mitigations',
            executor.submit(_run_test_cases): 'test_cases',
        }
        for future in _cf.as_completed(futures):
            step_name = futures[future]
            try:
                future.result()
                logging.info(f"[PIPELINE] {step_name} completed for {assessment_id}")
            except Exception as e:
                logging.error(f"[PIPELINE] {step_name} raised unhandled exception for {assessment_id}: {e}")

    # Mark fully completed
    _update_assessment_step(assessment_id, 'completed', status='completed')
    logging.info(f"[PIPELINE] Full pipeline completed for {assessment_id}")
    _assessment_log(assessment_id, 'INFO', 'pipeline', "Pipeline completed successfully")

    # Create a feedback entry and notify the requester via Slack DM
    try:
        _create_feedback_and_notify(assessment_id, details)
    except Exception as e:
        logging.warning(f"[PIPELINE] Feedback/notification step failed (non-blocking): {e}")


_FEEDBACK_FILE = os.path.join(_STORAGE_DIR, 'data', 'feedback', 'feedback.json')
_feedback_lock = threading.Lock()


def _load_feedback_store():
    """Load the feedback.json file, returning an empty list if it doesn't exist."""
    if not os.path.exists(_FEEDBACK_FILE):
        return []
    try:
        with open(_FEEDBACK_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return []


def _save_feedback_store(entries):
    """Persist the full feedback list atomically."""
    os.makedirs(os.path.dirname(_FEEDBACK_FILE), exist_ok=True)
    with open(_FEEDBACK_FILE, 'w') as f:
        json.dump(entries, f, indent=2)


def _create_feedback_and_notify(assessment_id, details):
    """
    Create a feedback entry for a completed assessment and send a Slack DM
    to the requester with the feedback link.
    """
    # Resolve recipient email: queue items use initiated_by; upload items use created_by
    queue_data = details.get('queue', {}) if isinstance(details.get('queue'), dict) else {}
    recipient_email = (
        queue_data.get('initiated_by')
        or details.get('created_by')
        or ''
    )
    if not recipient_email:
        logging.info(f"[FEEDBACK] No recipient email for {assessment_id}, skipping")
        return

    assessment_name = (
        details.get('projectName')
        or queue_data.get('service_name')
        or assessment_id
    )

    feedback_uuid = str(uuid.uuid4())
    entry = {
        "uuid": feedback_uuid,
        "assessment_id": assessment_id,
        "assessment_name": assessment_name,
        "created_for": recipient_email,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "threat_modeling_methodology": details.get('threatModelingMethodology', ''),
        "department": details.get('department', ''),
        "submitted": False,
        "submitted_at": None,
        "answers": {}
    }

    with _feedback_lock:
        store = _load_feedback_store()
        store.append(entry)
        _save_feedback_store(store)

    logging.info(f"[FEEDBACK] Created feedback entry {feedback_uuid} for {assessment_id}")

    # Send Slack DM
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
    feedback_url = f"{frontend_url}/provide-feedback/{feedback_uuid}"
    threat_model_url = f"{frontend_url}/view-threat-model/{assessment_id}"
    fallback_text = f"Your threat model is ready! Assessment: {assessment_name}"
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":white_check_mark:  Your threat model is ready!",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Assessment:*\n{assessment_name}"
                }
            ]
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Threat Model", "emoji": True},
                    "style": "primary",
                    "url": threat_model_url
                }
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "Please take a moment to provide feedback on the quality of the generated threat model. Your input helps us improve ThreatShield."
            }
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Provide Feedback", "emoji": True},
                    "url": feedback_url
                }
            ]
        }
    ]
    send_slack_dm(recipient_email, fallback_text, blocks=blocks)


def _has_any_successful_doc(additional_documents):
    """Return True if at least one additional document was fetched without error."""
    for key in ('prdDoc', 'confluenceDoc', 'slackThread', 'meetingTranscript'):
        doc = additional_documents.get(key)
        if doc and isinstance(doc, dict) and not doc.get('error') and (
            doc.get('fetched') or doc.get('stored') or doc.get('content')
        ):
            return True
    return False


def _enqueue_assessment(assessment_id):
    """Mark assessment as queued and add to the auto-trigger processing queue."""
    details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
    with _auto_trigger_lock:
        try:
            with open(details_path, 'r') as f:
                d = json.load(f)
            if d.get('status') not in ('pending', 'failed'):
                logging.info(f"[AUTO] {assessment_id} status={d.get('status')}, skipping enqueue")
                return
            d['status'] = 'queued'
            d.pop('error_message', None)
            with open(details_path, 'w') as f:
                json.dump(d, f, indent=2)
            _auto_trigger_queue.put(assessment_id)
            logging.info(f"[AUTO] Enqueued assessment {assessment_id}")
        except Exception as e:
            logging.error(f"[AUTO] Failed to enqueue {assessment_id}: {e}")


def _auto_process_assessment(assessment_id):
    """Claim a queued assessment and run the full RAG + pipeline."""
    # Acquire the semaphore — blocks until no other pipeline is running.
    # This is the single source of truth for serialization, regardless of
    # how many threads/workers end up calling this function.
    logging.info(f"[AUTO] {assessment_id} waiting for processing slot...")
    _processing_semaphore.acquire()
    logging.info(f"[AUTO] {assessment_id} acquired processing slot")
    try:
        _auto_process_assessment_inner(assessment_id)
    finally:
        _processing_semaphore.release()


def _auto_process_assessment_inner(assessment_id):
    """Inner implementation — called only when semaphore is held."""
    details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')

    # Atomically claim: queued → processing
    details = None
    with _auto_trigger_lock:
        try:
            with open(details_path, 'r') as f:
                details = json.load(f)
            if details.get('status') != 'queued':
                logging.info(f"[AUTO] {assessment_id} is no longer queued (status={details.get('status')}), skipping")
                return
            details['status'] = 'processing'
            details.pop('error_message', None)
            with open(details_path, 'w') as f:
                json.dump(details, f, indent=2)
        except Exception as e:
            logging.error(f"[AUTO] Failed to claim {assessment_id}: {e}")
            return

    logging.info(f"[AUTO] Starting auto-processing for {assessment_id}")
    _assessment_log(assessment_id, 'INFO', 'pipeline', f"Assessment processing started")

    # Build LangChain Documents from additionalinfo.json
    documents = []
    additionalinfo_path = os.path.join(_STORAGE_DIR, assessment_id, 'additionalinfo.json')
    try:
        with open(additionalinfo_path, 'r') as f:
            additionalinfo = json.load(f)
        for key in ('confluenceDoc', 'slackThread', 'meetingTranscript', 'prdDoc'):
            doc = additionalinfo.get(key)
            if doc and isinstance(doc, dict) and doc.get('content') and not doc.get('error'):
                documents.append(Document(
                    page_content=doc['content'],
                    metadata={"source": doc.get('url', key), "title": doc.get('title', key)}
                ))
    except Exception as e:
        logging.error(f"[AUTO] Failed to load additionalinfo for {assessment_id}: {e}")

    # If no content documents, build a synthetic one from details
    if not documents:
        try:
            content = (
                f"Service: {details.get('projectName', 'Unknown')}\n"
                f"Description: {details.get('description', '')}\n"
                f"Department: {details.get('department', '')}\n"
                f"Application Type: {details.get('applicationType', '')}\n"
                f"Authentication: {details.get('authenticationMethod', '')}\n"
                f"Internet Facing: {'Yes' if details.get('isInternetFacing') else 'No'}\n"
                f"Data Sensitivity: {details.get('dataSensitivityLevel', '')}"
            )
            documents.append(Document(page_content=content, metadata={"source": "details"}))
        except Exception as e:
            logging.error(f"[AUTO] Failed to build synthetic document for {assessment_id}: {e}")

    # Run RAG
    _update_assessment_step(assessment_id, 'rag')
    _assessment_log(assessment_id, 'INFO', 'rag', "Starting RAG processing")
    try:
        service_name = details.get('projectName', assessment_id).replace(' ', '_')
        persist_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"persist_{service_name}")
        os.makedirs(persist_dir, exist_ok=True)
        _openai_handler = OpenAIHandler()
        rag_handler = RAGHandler(openai_handler=_openai_handler, persist_dir=persist_dir, assessment_id=assessment_id)
        rag_result = rag_handler.rag_main(documents)
        storage_handler.save_rag_result(assessment_id, rag_result)
        logging.info(f"[AUTO] RAG completed for {assessment_id}")
        _assessment_log(assessment_id, 'INFO', 'rag', "RAG processing completed successfully")
    except Exception as e:
        logging.error(f"[AUTO] RAG failed for {assessment_id}: {e}")
        _assessment_log(assessment_id, 'ERROR', 'rag', f"RAG processing failed: {e}")
        try:
            with open(details_path, 'r') as f:
                d = json.load(f)
            d['status'] = 'failed'
            d['error_message'] = f"RAG processing failed: {str(e)}"
            with open(details_path, 'w') as f:
                json.dump(d, f, indent=2)
        except Exception:
            pass
        return

    # Fetch JIRA security bugs for this assessment's DEPARTMENT
    department = details.get('department', '')
    if department:
        try:
            secbugs_raw = fetch_jira_tickets(department)
            if isinstance(secbugs_raw, list) and secbugs_raw:
                formatted_secbugs = [
                    {
                        "id": bug.get('key', ''),
                        "name": bug.get('description', ''),
                        "status": bug.get('status', ''),
                        "priority": bug.get('priority', '')
                    }
                    for bug in secbugs_raw
                ]
                storage_handler.save_secbugs(assessment_id, formatted_secbugs)
                logging.info(f"[AUTO] Stored {len(formatted_secbugs)} SecBugs for DEPARTMENT: {department}")
            else:
                storage_handler.save_secbugs(assessment_id, [])
                logging.info(f"[AUTO] No SecBugs found for DEPARTMENT: {department}")
        except Exception as e:
            logging.error(f"[AUTO] Error fetching JIRA tickets for {assessment_id}: {e}")
            storage_handler.save_secbugs(assessment_id, [])

    # Run full pipeline steps
    _run_queue_pipeline_steps(assessment_id, rag_result)

def _rescan_queued_items():
    """Watchdog: find any assessments stuck in 'queued' state and re-add to queue."""
    if not _auto_trigger_queue.empty():
        return
    storage_dir = _STORAGE_DIR
    if not os.path.exists(storage_dir):
        return
    for entry in os.listdir(storage_dir):
        details_path = os.path.join(storage_dir, entry, 'details.json')
        if not os.path.exists(details_path):
            continue
        try:
            with open(details_path, 'r') as f:
                d = json.load(f)
            if d.get('status') == 'queued':
                logging.info(f"[AUTO] Watchdog: re-enqueuing stuck assessment {entry}")
                _auto_trigger_queue.put(entry)
        except Exception:
            pass


def _auto_trigger_worker():
    """Single daemon thread that processes queued assessments one at a time."""
    logging.info("[AUTO] Auto-trigger worker started")
    _last_scan = [0.0]
    while True:
        try:
            assessment_id = _auto_trigger_queue.get(timeout=5)
            logging.info(f"[AUTO] Worker picked up {assessment_id}")
            try:
                # Run the pipeline in a sub-thread so the worker can detect
                # cancellation quickly instead of waiting for the current LLM
                # step to finish (which can take 30–120 s).
                t = threading.Thread(
                    target=_auto_process_assessment,
                    args=(assessment_id,),
                    daemon=True,
                    name=f"pipeline-{assessment_id[:8]}"
                )
                t.start()
                while t.is_alive():
                    t.join(timeout=1)
                    if _is_cancelled(assessment_id):
                        logging.info(f"[AUTO] {assessment_id} cancelled — worker moving to next item")
                        break  # Let the sub-thread finish its current step on its own
            except Exception as e:
                logging.error(f"[AUTO] Worker error processing {assessment_id}: {e}")
            finally:
                _auto_trigger_queue.task_done()
        except _queue_module.Empty:
            # Watchdog: rescan every 30 s for stuck queued items
            now = time.time()
            if now - _last_scan[0] >= 30:
                _last_scan[0] = now
                _rescan_queued_items()
            continue
        except Exception as e:
            logging.error(f"[AUTO] Worker unexpected error: {e}")


def process_threat_model_background(assessment_id, form_data, documents, temp_pdf_paths, is_queue_item=False):
    """Process threat model generation in background thread"""
    try:
        logging.info(f"[BACKGROUND] Starting threat model processing for assessment {assessment_id}")

        # Get threat modeling inputs
        name = form_data.get('name', 'Not specified').replace(" ", "_")
        description = form_data.get('description', 'Not specified')
        department = form_data.get('department', 'Not specified')
        app_type = form_data.get('app_type', 'Not specified')
        sensitivity_level = form_data.get('sensitivity_level', 'Not specified')
        internet_facing = form_data.get('internet_facing', 'Yes')
        authentication = form_data.getlist('authentication[]') if isinstance(form_data.get('authentication[]'), list) else [form_data.get('authentication[]')]
        authentication_str = ', '.join(authentication) if authentication and authentication[0] else 'Not specified'
        sensitive_data = form_data.get('sensitive_data', 'Not specified')
        custom_prompt = form_data.get('custom_prompt', '')

        logging.info(f"[BACKGROUND] Processing RAG for assessment {assessment_id}")
        _update_assessment_step(assessment_id, 'rag')

        # Determine persist directory
        persist_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"persist_{name}")
        os.makedirs(persist_dir, exist_ok=True)

        # Initialize OpenAI handler and RAG
        openai_handler = OpenAIHandler()
        rag_handler = RAGHandler(openai_handler=openai_handler, persist_dir=persist_dir, assessment_id=assessment_id)

        # Generate RAG report
        try:
            rag_result = rag_handler.rag_main(documents)
            logging.info(f"[BACKGROUND] RAG report generated successfully for {assessment_id}")
        except Exception as e:
            logging.error(f"[BACKGROUND] Error generating RAG report: {str(e)}")
            rag_result = f"Error generating RAG report: {str(e)}"

        # Store RAG results in the assessment storage location
        storage_handler.save_rag_result(assessment_id, rag_result)
        logging.info(f"[BACKGROUND] RAG results saved for assessment {assessment_id}")

        if is_queue_item:
            # Queue flow: run the full pipeline (threat model → attack tree → DREAD → mitigations → test cases)
            if _is_cancelled(assessment_id):
                logging.info(f"[BACKGROUND] {assessment_id} cancelled after RAG — skipping pipeline")
            else:
                _run_queue_pipeline_steps(assessment_id, rag_result)
        else:
            # Normal flow: just mark RAG as completed; frontend handles subsequent steps via individual API calls
            details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
            if os.path.exists(details_path):
                with open(details_path, 'r') as f:
                    details = json.load(f)
                details['status'] = 'completed'
                details['current_step'] = 'completed'
                with open(details_path, 'w') as f:
                    json.dump(details, f, indent=2)
                logging.info(f"[BACKGROUND] Updated status to completed for {assessment_id}")

    except Exception as e:
        logging.error(f"[BACKGROUND] Error in background processing for {assessment_id}: {str(e)}")
        logging.exception("[BACKGROUND] Full traceback:")

        # Update status to error
        try:
            details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
            if os.path.exists(details_path):
                with open(details_path, 'r') as f:
                    details = json.load(f)
                details['status'] = 'failed'
                details['error_message'] = str(e)
                with open(details_path, 'w') as f:
                    json.dump(details, f, indent=2)
        except Exception as update_error:
            logging.error(f"[BACKGROUND] Error updating status: {str(update_error)}")

@app.route('/api/upload', methods=['POST'])
def upload_documents():
    # Handle Confluence input  
    confluence_url = request.form.get('confluence_url')
    
    # Check if assessment_id is provided from queue
    assessment_id = request.form.get('assessment_id')
    is_queue_item = False
    
    if not assessment_id:
        # Create new assessment if not from queue
        assessment_id = str(uuid.uuid4())
        logging.info(f"[UPLOAD] New assessment created: {assessment_id}")
    else:
        # Check if this assessment already exists in storage
        existing_storage_dir = os.path.join(_STORAGE_DIR, assessment_id)
        if os.path.exists(existing_storage_dir):
            is_queue_item = True
            logging.info(f"[UPLOAD] Using existing assessment from queue: {assessment_id}")
        else:
            logging.info(f"[UPLOAD] Assessment ID provided but folder doesn't exist yet: {assessment_id}")

    # Get threat modeling inputs
    session['name'] = request.form.get('name', 'Not specified').replace(" ", "_")
    session['description'] = request.form.get('description', 'Not specified')
    session['department'] = request.form.get('department', 'Not specified')
    session['app_type'] = request.form.get('app_type', 'Not specified')
    session['sensitivity_level'] = request.form.get('sensitivity_level', 'Not specified')
    session['internet_facing'] = request.form.get('internet_facing', 'Yes')
    session['authentication'] = request.form.getlist('authentication[]')
    session['authentication_str'] = ', '.join(session['authentication']) if session['authentication'] else 'Not specified'
    session['sensitive_data'] = request.form.get('sensitive_data', 'Not specified')
    # Get and log initial custom prompt
    session['custom_prompt'] = request.form.get('custom_prompt', '')
    logging.info(f"Initial custom prompt from form: '{session['custom_prompt']}'")
    
    # Get additional document sources
    additional_info = request.form.get('additional_info', '{}')
    additional_info_json = {}
    try:
        additional_info_json = json.loads(additional_info)
        # Store additional info in a file - don't override assessment_id from queue
        session['assessment_id'] = assessment_id
        
        # Create storage directory if it doesn't exist (only for non-queue items or new queue items)
        storage_dir = os.path.join(_STORAGE_DIR, assessment_id)
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir, exist_ok=True)
            logging.info(f"[UPLOAD] Created new storage directory for assessment {assessment_id}")
        else:
            logging.info(f"[UPLOAD] Using existing storage directory for assessment {assessment_id}")

        # For brand-new (non-queue) uploads, seed a details.json with status='processing'
        # so that the cancel endpoint can find and cancel it if the user aborts early.
        if not is_queue_item:
            details_path = os.path.join(storage_dir, 'details.json')
            if not os.path.exists(details_path):
                with open(details_path, 'w') as f:
                    json.dump({
                        "status": "processing",
                        "source": "upload",
                        "timestamp": datetime.datetime.utcnow().isoformat()
                    }, f, indent=2)
                logging.info(f"[UPLOAD] Seeded details.json (status=processing) for {assessment_id}")
        
        # Get the selected DEPARTMENT and fetch SecBugs
        department = request.form.get('department', '')
        if department:
            try:
                # Fetch SecBugs for the selected DEPARTMENT
                secbugs_raw = fetch_jira_tickets(department)
                logging.info(f"{secbugs_raw}")
                # Format the SecBugs data with id and name keys
                formatted_secbugs = []
                if isinstance(secbugs_raw, list) and secbugs_raw:
                    for bug in secbugs_raw:
                        formatted_secbugs.append({
                            "id": bug.get('key', ''),  # SECBUG-1, etc.
                            "name": bug.get('description', ''),  # Summary from Jira
                            "status": bug.get('status', ''),  # Status from Jira
                            "priority": bug.get('priority', '')  # Priority from Jira
                        })
                    
                    # Store the formatted SecBugs in a file
                    storage_handler.save_secbugs(assessment_id, formatted_secbugs)
                    logging.info(f"Stored {len(formatted_secbugs)} SecBugs for DEPARTMENT: {department}")
                else:
                    # Store empty array if no SecBugs found
                    storage_handler.save_secbugs(assessment_id, [])
                    logging.info(f"No SecBugs found for DEPARTMENT: {department}")
            except Exception as e:
                logging.error(f"Error fetching SecBugs: {str(e)}")
                # Store empty array on error
                storage_handler.save_secbugs(assessment_id, [])
        
        # Process and store additional document sources
        enhanced_info = {
            "confluenceDoc": None,
            "slackThread": None,
            "meetingTranscript": None,
            "prdDoc": None
        }
        
        # Extract Confluence content if provided
        confluence_doc_input = additional_info_json.get('confluenceDoc')
        if confluence_doc_input:
            try:
                if isinstance(confluence_doc_input, dict) and confluence_doc_input.get('content'):
                    # Pre-fetched content from queue — use directly
                    content = confluence_doc_input['content']
                    enhanced_info['confluenceDoc'] = confluence_doc_input
                    logging.info(f"Using pre-fetched Confluence content ({len(content)} chars)")
                elif isinstance(confluence_doc_input, str):
                    # URL string — fetch fresh
                    logging.info(f"Attempting to extract content from Confluence URL: {confluence_doc_input}")
                    confluence_result = load_confluence_documents(confluence_doc_input)
                    content = "\n\n".join([doc.page_content for doc in confluence_result])
                    enhanced_info['confluenceDoc'] = {
                        "url": confluence_doc_input,
                        "content": content,
                        "title": "Confluence Document"
                    }
                    logging.info(f"Successfully extracted {len(confluence_result)} documents from Confluence")
                else:
                    content = ""

                if content:
                    confluence_content = f"##Additional Details\n\nAdditional Confluence Content:\n{content[:1000]}..." if len(content) > 1000 else f"\n\nAdditional Confluence Content:\n{content}"
                    session['custom_prompt'] += confluence_content
                    logging.info(f"Added Confluence content to custom prompt")

            except Exception as e:
                logging.error(f"Error extracting Confluence content: {str(e)}")
                url_ref = confluence_doc_input if isinstance(confluence_doc_input, str) else confluence_doc_input.get('url', str(confluence_doc_input))
                enhanced_info['confluenceDoc'] = {"url": url_ref, "error": str(e)}
                session['custom_prompt'] += f"\n\nAdditional Confluence Document Link (content extraction failed):\n{url_ref}"
        
        # Extract Slack thread content if provided
        slack_thread_input = additional_info_json.get('slackThread')
        if slack_thread_input:
            try:
                if isinstance(slack_thread_input, dict) and slack_thread_input.get('content'):
                    # Pre-fetched content from queue — use directly
                    content = slack_thread_input['content']
                    enhanced_info['slackThread'] = slack_thread_input
                    logging.info(f"Using pre-fetched Slack thread content ({len(content)} chars)")
                elif isinstance(slack_thread_input, str):
                    # URL string — fetch fresh
                    logging.info(f"Attempting to extract content from Slack thread: {slack_thread_input}")
                    slack_result = load_slack_thread(slack_thread_input)
                    content = slack_result['content']
                    enhanced_info['slackThread'] = {
                        "url": slack_thread_input,
                        "content": content,
                        "channel": slack_result['channel']
                    }
                    logging.info(f"Successfully extracted {slack_result.get('message_count', 0)} messages from Slack thread")
                else:
                    content = ""

                if content:
                    slack_content = f"\n\nSlack Thread Content:\n{content[:1000]}..." if len(content) > 1000 else f"\n\nSlack Thread Content:\n{content}"
                    session['custom_prompt'] += slack_content
                    logging.info(f"Added Slack content to custom prompt")

            except Exception as e:
                logging.error(f"Error extracting Slack thread content: {str(e)}")
                url_ref = slack_thread_input if isinstance(slack_thread_input, str) else slack_thread_input.get('url', str(slack_thread_input))
                enhanced_info['slackThread'] = {"url": url_ref, "error": str(e)}
                session['custom_prompt'] += f"\n\nSlack Thread Link (content extraction failed):\n{url_ref}"
        
        # Store meeting transcript if provided
        meeting_transcript_input = additional_info_json.get('meetingTranscript')
        if meeting_transcript_input:
            if isinstance(meeting_transcript_input, dict) and meeting_transcript_input.get('content'):
                # Pre-fetched from queue — already in correct shape
                enhanced_info['meetingTranscript'] = meeting_transcript_input
                meeting_text = meeting_transcript_input['content']
            else:
                # Raw string from UI
                meeting_text = str(meeting_transcript_input)
                enhanced_info['meetingTranscript'] = {"content": meeting_text, "title": "Meeting Transcript"}
            meeting_content = f"\n\nMeeting Transcript:\n{meeting_text}"
            session['custom_prompt'] += meeting_content
            logging.info(f"Added meeting transcript to custom prompt")

        # Extract PRD document content if provided
        prd_doc_input = additional_info_json.get('prdDoc')
        if prd_doc_input:
            try:
                if isinstance(prd_doc_input, dict) and prd_doc_input.get('content'):
                    # Pre-fetched content from queue — use directly
                    content = prd_doc_input['content']
                    enhanced_info['prdDoc'] = prd_doc_input
                    logging.info(f"Using pre-fetched PRD content ({len(content)} chars)")
                elif isinstance(prd_doc_input, str):
                    # URL string — detect type: Google Docs vs Confluence
                    logging.info(f"Attempting to fetch PRD from URL: {prd_doc_input}")
                    content = None
                    if 'docs.google.com' in prd_doc_input:
                        from utils.google_docs_handler import GoogleDocsHandler
                        gd_handler = GoogleDocsHandler()
                        if gd_handler.is_configured():
                            try:
                                gd_result = gd_handler.fetch_document_content(prd_doc_input)
                                if gd_result and gd_result.get('content'):
                                    content = gd_result['content']
                            except Exception as gd_e:
                                logging.warning(f"Google Docs fetch failed: {gd_e}")
                    else:
                        try:
                            prd_docs = load_confluence_documents(prd_doc_input)
                            if prd_docs:
                                content = "\n\n".join([doc.page_content for doc in prd_docs])
                        except Exception as conf_e:
                            logging.warning(f"Confluence fetch failed: {conf_e}")
                    if content:
                        enhanced_info['prdDoc'] = {"url": prd_doc_input, "content": content, "title": "PRD Document"}
                    else:
                        content = ""
                else:
                    content = ""

                if content:
                    prd_content = f"\n\nPRD Document Content:\n{content[:1000]}..." if len(content) > 1000 else f"\n\nPRD Document Content:\n{content}"
                    session['custom_prompt'] += prd_content
                    logging.info(f"Added PRD content to custom prompt")

            except Exception as e:
                logging.error(f"Error extracting PRD content: {str(e)}")
                url_ref = prd_doc_input if isinstance(prd_doc_input, str) else prd_doc_input.get('url', str(prd_doc_input))
                enhanced_info['prdDoc'] = {"url": url_ref, "error": str(e)}
                session['custom_prompt'] += f"\n\nPRD Document Link (content extraction failed):\n{url_ref}"

        # Save enhanced info to file
        additional_info_path = os.path.join(_STORAGE_DIR, assessment_id, 'additionalinfo.json')
        os.makedirs(os.path.dirname(additional_info_path), exist_ok=True)
        with open(additional_info_path, 'w') as f:
            json.dump(enhanced_info, f, indent=2)
            
    except json.JSONDecodeError:
        logging.error("Failed to parse additional_info JSON")
    
    image_files = request.files.getlist('image_files')

    logging.info("Request files: %s", request.files)
    pdf_files = request.files.getlist('pdf_file')
    logging.info("Retrieved PDF files: %s", pdf_files)
    image_files = request.files.getlist('image_files')
    print(image_files)
    persist_dir = ""
    documents = []
    
    # Determine persist directory based on Confluence space or random name
    if session['name']:
        persist_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"persist_{session['name']}")
    else:
        persist_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"persist_{uuid.uuid4()}")
    
    # Ensure the persist directory exists
    os.makedirs(persist_dir, exist_ok=True)
    
    try:
        # Process documents from either Confluence or PDF
        temp_pdf_path = None
        documents = []
        
        # Handle PDF files if provided
        temp_pdf_paths = []
        if pdf_files:
            try:
                # Log the PDF files received
                logging.info(f"PDF files received: {len(pdf_files)}")
                for i, pdf_file in enumerate(pdf_files):
                    if pdf_file and hasattr(pdf_file, 'filename'):
                        logging.info(f"PDF file {i+1}: {pdf_file.filename}, content_type: {pdf_file.content_type}")
                    else:
                        logging.warning(f"PDF file {i+1} is invalid or missing filename attribute")
                
                # Create a unique directory for this upload
                upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], session['name']+"_files")
                os.makedirs(upload_dir, exist_ok=True)
                logging.info(f"Created upload directory: {upload_dir}")
                
                # Save all uploaded PDF files
                for pdf_file in pdf_files:
                    if pdf_file and pdf_file.filename:
                        temp_pdf_path = os.path.join(upload_dir, pdf_file.filename)
                        logging.info(f"Saving PDF file to: {temp_pdf_path}")
                        pdf_file.save(temp_pdf_path)
                        
                        # Verify the file exists and has content
                        if not os.path.exists(temp_pdf_path):
                            error_msg = f"Failed to save PDF file: {pdf_file.filename}"
                            logging.error(error_msg)
                            raise ValueError(error_msg)
                            
                        file_size = os.path.getsize(temp_pdf_path)
                        logging.info(f"PDF file saved to: {temp_pdf_path} (size: {file_size} bytes)")
                        
                        if file_size == 0:
                            logging.warning(f"PDF file is empty: {pdf_file.filename}")
                        else:
                            temp_pdf_paths.append(temp_pdf_path)
                            logging.info(f"Added {temp_pdf_path} to processing list")
                    
            except Exception as e:
                logging.error(f"Error saving PDF file: {str(e)}")
                return jsonify({"error": f"Error saving PDF file: {str(e)}"}), 500
        
        try:
            # decide_document_source will handle both Confluence and PDF sources
            try:
                documents = decide_document_source(confluence_url, file_paths=temp_pdf_paths)
            except Exception as doc_source_err:
                logging.warning(f"decide_document_source failed (will try fallbacks): {str(doc_source_err)}")
                documents = []

            # If no documents from primary source, try building from pre-fetched content in additional_info
            if not documents and additional_info_json:
                prefetched_docs = []

                confluence_doc = additional_info_json.get('confluenceDoc')
                if isinstance(confluence_doc, dict) and confluence_doc.get('content'):
                    prefetched_docs.append(Document(
                        page_content=confluence_doc['content'],
                        metadata={"source": confluence_doc.get('url', 'confluence'), "title": confluence_doc.get('title', 'Confluence Document')}
                    ))
                    logging.info(f"Built RAG document from pre-fetched Confluence content")

                slack_doc = additional_info_json.get('slackThread')
                if isinstance(slack_doc, dict) and slack_doc.get('content'):
                    prefetched_docs.append(Document(
                        page_content=slack_doc['content'],
                        metadata={"source": slack_doc.get('url', 'slack'), "title": "Slack Thread"}
                    ))
                    logging.info(f"Built RAG document from pre-fetched Slack thread content")

                if prefetched_docs:
                    documents = prefetched_docs
                    logging.info(f"Using {len(documents)} pre-fetched document(s) for RAG")

            # Always append Slack, meeting transcript, and PRD doc to vector DB documents.
            # These are not captured by decide_document_source (which only handles PDF/Confluence URL).
            # Mirrors the queue flow behaviour in _auto_process_assessment_inner.
            for _key, _title in [('slackThread', 'Slack Thread'), ('meetingTranscript', 'Meeting Transcript'), ('prdDoc', 'PRD Document')]:
                _doc = enhanced_info.get(_key)
                if _doc and isinstance(_doc, dict) and _doc.get('content') and not _doc.get('error'):
                    _source = _doc.get('url', _key)
                    # Avoid duplicating if the fallback path already added this source
                    already_present = any(
                        hasattr(d, 'metadata') and d.metadata.get('source') == _source
                        for d in documents
                    )
                    if not already_present:
                        documents.append(Document(
                            page_content=_doc['content'],
                            metadata={"source": _source, "title": _doc.get('title', _title)}
                        ))
                        logging.info(f"Added {_title} to RAG documents for vector DB embedding")

            # If still no documents, create a minimal synthetic document from description
            if not documents:
                _desc = request.form.get('description', 'Not specified')
                _name = request.form.get('name', 'Unknown Service')
                _department = request.form.get('department', '')
                _app_type = request.form.get('app_type', '')
                synthetic_content = f"Service: {_name}\nDescription: {_desc}"
                if _department:
                    synthetic_content += f"\nDepartment: {_department}"
                if _app_type:
                    synthetic_content += f"\nApplication Type: {_app_type}"
                documents = [Document(
                    page_content=synthetic_content,
                    metadata={"source": "description", "title": f"{_name} Description"}
                )]
                logging.info(f"No documents available — using synthetic document from description for RAG")
                
            logging.info(f"Documents processed: {len(documents)}")
            # Log content length of each document
            for i, doc in enumerate(documents):
                content = doc.page_content if hasattr(doc, 'page_content') else str(doc)
                logging.info(f"Document {i+1} content length: {len(content)}")
                if len(content) == 0:
                    logging.warning(f"Document {i+1} is empty")
                else:
                    logging.info(f"Document {i+1} first 100 chars: {content[:100]}")
                        
        except Exception as e:
            logging.error(f"Error processing documents: {str(e)}")
            error_message = f"Error processing documents: {str(e)}"
            
            # Update assessment status to failed in storage
            try:
                details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
                if os.path.exists(details_path):
                    with open(details_path, 'r') as f:
                        details = json.load(f)
                    details['status'] = 'failed'
                    details['error_message'] = error_message
                    with open(details_path, 'w') as f:
                        json.dump(details, f, indent=2)
                    logging.info(f"[UPLOAD] Updated assessment {assessment_id} status to failed")
            except Exception as update_error:
                logging.error(f"[UPLOAD] Error updating assessment status: {str(update_error)}")
            
            return jsonify({"error": error_message}), 400
    
    except Exception as e:
            logging.error(f"Error processing documents: {str(e)}")
            return jsonify({"error": f"Error processing documents: {str(e)}"}), 500
    # Store assessment_id in session
    session['assessment_id'] = assessment_id
    
    # For queue items, update status to processing immediately so the UI reflects it
    if is_queue_item:
        _update_assessment_step(assessment_id, 'rag', status='processing')

    # Start background thread for threat model processing
    logging.info(f"[UPLOAD] Starting background thread for assessment {assessment_id}")
    background_thread = threading.Thread(
        target=process_threat_model_background,
        args=(assessment_id, request.form, documents, temp_pdf_paths, is_queue_item),
        daemon=True
    )
    background_thread.start()
    logging.info(f"[UPLOAD] Background thread started for assessment {assessment_id}")
    
    # Return results immediately without waiting for background processing
    return jsonify({
        "message": "Threat model generation started in background",
        "assessment_id": assessment_id,
        "document_count": len(documents),
        "status": "processing"
    })

@app.route('/api/query-ai', methods=['POST'])
def query_ai():
    try:
        data = request.get_json()
        user_query = data.get('user_query')
        assessment_id = data.get('assessment_id')

        if not user_query:
            return jsonify({"error": "User query is required"}), 400
            
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400

        # Initialize OpenAI handler
        openai_handler = OpenAIHandler()
        
        # Use the chat instance from a global variable if it exists, otherwise create a new one
        global chat_instance
        if not chat_instance:
            chat_instance = Chat(openai_handler)
            
        Answer = chat_instance.chat_about_report(assessment_id=assessment_id, user_query=user_query)

        # Return the Answer directly without nesting it under 'result'
        # This matches the frontend's expectation of finding response.Result
        return jsonify(Answer)

    except Exception as e:
        logging.error(f"Error querying AI: {str(e)}")
        return jsonify({"error": f"Error querying AI: {str(e)}"}), 500

@app.route('/api/threat-model', methods=['GET'])
def generate_threat_model():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400

        # Get RAG results from storage
        rag_data = storage_handler.get_rag_result(assessment_id)
        if not rag_data:
            # Check if the assessment is still processing (background thread running)
            details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
            if os.path.exists(details_path):
                try:
                    with open(details_path, 'r') as f:
                        details_check = json.load(f)
                    current_status = details_check.get('status', 'pending')
                    if current_status in ('pending', 'processing'):
                        return jsonify({"status": "processing", "message": "RAG processing still in progress, please retry"}), 202
                except Exception:
                    pass
            return jsonify({"error": "RAG results not found"}), 404

        # Compat shim: rag_result.json 'result' is a plain string in old assessments,
        # and a dict {"app_summary": ..., "security_context": ...} in new ones.
        _rag_raw = rag_data['result']
        if isinstance(_rag_raw, dict):
            rag_output = _rag_raw.get('app_summary', '')
            security_context = _rag_raw.get('security_context', {})
        else:
            rag_output = _rag_raw
            security_context = {}
        
        # Load details.json for project information
        details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
        custom_prompt = ""
        
        # Get SecBugs from storage
        secbugs_data = storage_handler.get_secbugs(assessment_id)
        if secbugs_data and 'result' in secbugs_data and secbugs_data['result']:
            # Convert to string format for the prompt
            secbugs_list = secbugs_data['result']
            secbugs_str = ", ".join([f"{bug['id']}: {bug['name']} (Status: {bug['status']}, Priority: {bug['priority']})" for bug in secbugs_list])
            secbugs = secbugs_str
        else:
            secbugs = "No security bugs found for this Department."
        
        if os.path.exists(details_path):
            try:
                with open(details_path, 'r') as f:
                    details = json.load(f)
                
                # Extract values from details.json
                app_type = details.get('applicationType', '')
                authentication_str = details.get('authenticationMethod', '')
                internet_facing = "Yes" if details.get('isInternetFacing', False) else "No"
                sensitive_data = details.get('dataSensitivityLevel', '')
                
                # Build custom prompt from details
                custom_prompt = f"Custom Prompt"
                
                logging.info(f"Loaded project details from details.json: {app_type}, {authentication_str}, {internet_facing}, {sensitive_data}")
            except Exception as e:
                logging.error(f"Error loading details.json: {str(e)}")
                # Fallback to session variables
                app_type = session.get('app_type', '')
                authentication_str = session.get('authentication_str', '')
                internet_facing = session.get('internet_facing', '')
                sensitive_data = session.get('sensitive_data', '')
        else:
            # Fallback to session variables if file doesn't exist
            logging.warning(f"details.json not found for assessment {assessment_id}, falling back to session variables")
            app_type = session.get('app_type', '')
            authentication_str = session.get('authentication_str', '')
            internet_facing = session.get('internet_facing', '')
            sensitive_data = session.get('sensitive_data', '')
        
        # Load additionalinfo.json for additional context
        additionalinfo_path = os.path.join(_STORAGE_DIR, assessment_id, 'additionalinfo.json')
        if os.path.exists(additionalinfo_path):
            try:
                with open(additionalinfo_path, 'r') as f:
                    additionalinfo = json.load(f)
                
                # Add Confluence content if available
                if additionalinfo.get('confluenceDoc') and additionalinfo['confluenceDoc'].get('content'):
                    custom_prompt += f"\n\nAdditional Confluence Content:\n{additionalinfo['confluenceDoc']['content']}"

                # Add Slack thread content if available
                if additionalinfo.get('slackThread') and additionalinfo['slackThread'].get('content'):
                    custom_prompt += f"\n\nSlack Thread Content:\n{additionalinfo['slackThread']['content']}"

                # Add meeting transcript if available
                if additionalinfo.get('meetingTranscript') and additionalinfo['meetingTranscript'].get('content'):
                    custom_prompt += f"\n\nMeeting Transcript:\n{additionalinfo['meetingTranscript']['content']}"

                # Add PRD document content if available
                if additionalinfo.get('prdDoc') and additionalinfo['prdDoc'].get('content'):
                    custom_prompt += f"\n\nPRD Document Content:\n{additionalinfo['prdDoc']['content']}"
                
                logging.info(f"Added additional context from additionalinfo.json")
            except Exception as e:
                logging.error(f"Error loading additionalinfo.json: {str(e)}")
                # Try to get custom prompt from session as fallback
                session_custom_prompt = session.get('custom_prompt', '')
                if session_custom_prompt:
                    custom_prompt += f"\n\n{session_custom_prompt}"
        else:
            # Try to get custom prompt from session as fallback
            logging.warning(f"additionalinfo.json not found for assessment {assessment_id}, checking session for custom prompt")
            session_custom_prompt = session.get('custom_prompt', '')
            if session_custom_prompt:
                custom_prompt += f"\n\n{session_custom_prompt}"
        
        # Ensure custom_prompt is not None
        if custom_prompt is None:
            custom_prompt = ''
            logging.warning("Custom prompt was None, setting to empty string")
        
        # Log the custom prompt for debugging
        logging.info(f"Final custom prompt: {custom_prompt[:100]}...")
        
        # Get organization context from settings.json
        org_context = ""
        try:
            settings = _get_settings()
            preContextType = settings.get('preContextType', 'custom')
            org_context = settings.get('preContext', '')
            logging.info(f"Loaded organization context from settings.json: {org_context[:100]}...")
        except Exception as e:
            logging.error(f"Error loading organization context from settings.json: {str(e)}")
        
        # Get methodology from details.json
        methodology = None
        assessment_name = ""
        if os.path.exists(details_path):
            try:
                with open(details_path, 'r') as f:
                    details = json.load(f)
                assessment_name = details.get('name', '')
                # Get the methodology from details.json
                methodology = details.get('threatModelingMethodology')
                if methodology:
                    logging.info(f"Using threat modeling methodology from details.json: {methodology}")
                else:
                    error_msg = "No threat modeling methodology found in details.json"
                    logging.error(error_msg)
                    return jsonify({"error": error_msg}), 400
            except Exception as e:
                error_msg = f"Error reading methodology from details.json: {str(e)}"
                logging.error(error_msg)
                return jsonify({"error": error_msg}), 500
        else:
            error_msg = f"details.json not found for assessment {assessment_id}"
            logging.error(error_msg)
            return jsonify({"error": error_msg}), 404

        # Get MCP context from enabled MCP servers
        mcp_context = ""
        try:
            mcp_context = mcp_handler.run_mcp_tools_for_threat_model(assessment_name, rag_output[:2000])
            if mcp_context:
                logging.info(f"MCP context collected ({len(mcp_context)} chars)")
        except Exception as exc:
            logging.warning(f"MCP context collection failed: {exc}")

        # Generate threat model (this will internally create the prompt)
        _openai_handler = OpenAIHandler()
        _tm_handler = ThreatModelingHandler(_openai_handler)
        threat_model_result = _tm_handler.generate_threat_model(
            app_type=app_type,
            authentication=authentication_str,
            internet_facing=internet_facing,
            sensitive_data=sensitive_data,
            app_input=rag_output,
            secbugs=secbugs,
            custom_prompt=custom_prompt,
            org_context=org_context,
            assessment_id=assessment_id,
            security_context=security_context,
            mcp_context=mcp_context,
        )

        # Get the prompt that was actually used (for storage)
        threat_model_prompt = _tm_handler.last_generated_prompt
        
        # Store threat model results without duplication but maintaining frontend compatibility
        storage_handler.save_threat_model(assessment_id, {
            "raw_response": {
                "threat_model": threat_model_result["threat_model"],
                "improvement_suggestions": threat_model_result["improvement_suggestions"]
            },
            "markdown": threat_model_result["markdown"],
            "critic_pass": threat_model_result.get("critic_pass") or {}
        })
        storage_handler.save_canonical_threats(assessment_id, threat_model_result["threat_model"])
        
        # Log the prompt that was actually used
        logging.info(f"Prompt actually used for threat model: {threat_model_prompt}")
        
        # Initialize prompts storage if it doesn't exist
        prompts_data = storage_handler.get_prompts(assessment_id) or {"prompts": {}}
        
        # Store the threat model prompt while preserving other prompts
        prompts_data["prompts"]["threat_model"] = threat_model_prompt
        storage_handler.save_prompts(assessment_id, prompts_data["prompts"])
        
        # Return in the format expected by the frontend
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": threat_model_result
        })

    except Exception as e:
        app.logger.error(f"Error generating threat model: {str(e)}")
        return jsonify({
            "error": "Failed to generate threat model",
            "details": str(e)
        }), 500

@app.route('/api/dread-assessment', methods=['GET'])
def generate_dread_assessment():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Get threat model and attack tree from storage
        threat_model_data = storage_handler.get_threat_model(assessment_id)
        attack_tree_data = storage_handler.get_attack_tree(assessment_id)

        if not threat_model_data:
            return jsonify({"error": "Threat model not found"}), 404

        # Load security context from RAG result if available
        rag_data = storage_handler.get_rag_result(assessment_id)
        security_context = {}
        if rag_data and isinstance(rag_data.get('result'), dict):
            security_context = rag_data['result'].get('security_context', {})
            
        # Initialize OpenAI handler
        openai_handler = OpenAIHandler()
        
        # Generate DREAD assessment
        dread_handler = DreadHandler(openai_handler)
        
        # Create the prompt for DREAD assessment
        dread_prompt = dread_handler.create_dread_assessment_prompt(
            threat_model_data['result']['raw_response'],
            attack_tree_data['result'] if attack_tree_data else None,
            assessment_id,
            security_context
        )
        
        # Generate DREAD assessment
        dread_result = dread_handler.generate_dread_assessment(
            dread_prompt,
            assessment_id
        )
        
        # Get existing prompts or initialize new
        prompts_data = storage_handler.get_prompts(assessment_id) or {"prompts": {}}
        
        # Store the DREAD assessment prompt
        prompts_data["prompts"]["dread"] = dread_prompt
        storage_handler.save_prompts(assessment_id, prompts_data["prompts"])
        
        # Store DREAD results
        storage_handler.save_dread_assessment(assessment_id, dread_result)
        
        # Return in the format expected by the frontend
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": dread_result
        })
        
    except Exception as e:
        logging.error(f"Error generating DREAD assessment: {str(e)}")
        return jsonify({
            "error": f"Error generating DREAD assessment: {str(e)}"
        }), 500

@app.route('/api/mitigations', methods=['GET'])
def generate_mitigations():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Get threat model, attack tree, and DREAD data from storage
        threat_model_data = storage_handler.get_threat_model(assessment_id)
        attack_tree_data = storage_handler.get_attack_tree(assessment_id)
        dread_data = storage_handler.get_dread_assessment(assessment_id)
        
        if not threat_model_data:
            return jsonify({"error": "Threat model not found"}), 404
            
        # Initialize OpenAI handler
        openai_handler = OpenAIHandler()
        
        # Generate mitigations
        mitigation_handler = MitigationHandler(openai_handler)
        
        # Create the prompt for mitigations
        mitigation_prompt = mitigation_handler.create_mitigations_prompt(
            threat_model_data['result']['raw_response'],
            assessment_id
        )
        
        # Generate mitigations
        result = mitigation_handler.generate_mitigations(
            mitigation_prompt,
            assessment_id
        )
        
        # Get existing prompts or initialize new
        prompts_data = storage_handler.get_prompts(assessment_id) or {"prompts": {}}
        
        # Store the mitigations prompt
        prompts_data["prompts"]["mitigation"] = mitigation_prompt
        storage_handler.save_prompts(assessment_id, prompts_data["prompts"])
        
        # Store mitigation results
        storage_handler.save_mitigation_result(assessment_id, result)
        
        # Return in the format expected by the frontend
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": result
        })
        
    except Exception as e:
        logging.error(f"Error generating mitigations: {str(e)}")
        return jsonify({
            "error": f"Error generating mitigations: {str(e)}"
        }), 500

@app.route('/api/attack-tree', methods=['GET'])
def generate_attack_tree():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Get threat model from storage
        threat_model_data = storage_handler.get_threat_model(assessment_id)
        if not threat_model_data:
            return jsonify({"error": "Threat model not found"}), 404
            
        # Initialize OpenAI handler
        openai_handler = OpenAIHandler()
        
        # Generate attack tree
        attack_tree_handler = AttackTreeHandler(openai_handler)
        
        # Create the prompt for attack tree
        attack_tree_prompt = attack_tree_handler.create_attack_tree_prompt(threat_model_data['result']['raw_response'], assessment_id)
        
        # Generate attack tree
        result = attack_tree_handler.generate_attack_tree(threat_model_data['result']['raw_response'], assessment_id)
        
        # Get existing prompts or initialize new
        prompts_data = storage_handler.get_prompts(assessment_id) or {"prompts": {}}
        
        # Store the attack tree prompt
        prompts_data["prompts"]["attack_tree"] = attack_tree_prompt
        storage_handler.save_prompts(assessment_id, prompts_data["prompts"])
        
        # Ensure the result has the expected structure for the frontend
        if "attack_tree" not in result:
            # Create a default structure if missing
            result["attack_tree"] = {
                "nodes": [
                    {
                        "id": "error",
                        "type": "goal",
                        "label": "Error generating attack tree"
                    }
                ]
            }
        
        # Format the markdown for display
        if "markdown" in result:
            result["markdown"] = f"```mermaid\n{result['markdown']}\n```"
        
        # Store attack tree results
        storage_handler.save_attack_tree(assessment_id, result)
        
        # Return in the format expected by the frontend
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": result
        })
        
    except Exception as e:
        logging.error(f"Error generating attack tree: {str(e)}")
        return jsonify({
            "error": f"Error generating attack tree: {str(e)}"
        }), 500

@app.route('/api/asvs-test-cases', methods=['GET'])
def generate_s():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Get threat model from storage
        threat_model_data = storage_handler.get_threat_model(assessment_id)
        if not threat_model_data:
            return jsonify({"error": "Threat model not found"}), 404
        
        # Generate test cases by processing each threat type separately
        # This avoids truncation by making separate API calls per threat type
        _openai_handler = OpenAIHandler()
        test_cases = ASVSTestCaseGenerator(_openai_handler).generate_asvs(
            threat_model_data['result']['raw_response'],
            assessment_id
        )
        
        # Get existing prompts or initialize new
        existing_prompts_data = storage_handler.get_prompts(assessment_id)
        if existing_prompts_data and "prompts" in existing_prompts_data:
            prompts_dict = existing_prompts_data["prompts"]
        else:
            prompts_dict = {}
        
        # Store a note about the ASVS test cases generation
        prompts_dict["asvs_test_cases"] = "Generated per threat type to avoid truncation"
        storage_handler.save_prompts(assessment_id, prompts_dict)
        
        # Save test cases to storage
        storage_handler.save_test_cases(assessment_id, test_cases)
        
        # Return in the format expected by the frontend
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": test_cases
        })
        
    except Exception as e:
        logging.error(f"Error generating ASVS test cases: {str(e)}")
        return jsonify({
            "error": f"Error generating ASVS test cases: {str(e)}"
        }), 500

def _handle_batch_test_case_update(assessment_id, test_cases_to_update):
    """
    Handle batch update of multiple test cases in a single file operation.
    """
    try:
        logging.info(f"[BATCH-UPDATE] Processing {len(test_cases_to_update)} test case(s)")
        
        # Read the file once
        filepath = os.path.join(_STORAGE_DIR, assessment_id, 'test_cases.json')
        logging.info(f"[BATCH-UPDATE] Reading file from: {filepath}")
        
        if not os.path.exists(filepath):
            logging.error(f"[BATCH-UPDATE] Test cases file not found at {filepath}")
            return jsonify({"error": "Test cases file not found"}), 404
        
        try:
            with open(filepath, 'r') as f:
                file_data = json.load(f)
            logging.info(f"[BATCH-UPDATE] File loaded successfully")
        except json.JSONDecodeError as e:
            logging.error(f"[BATCH-UPDATE] JSON decode error: {str(e)}")
            return jsonify({"error": "Invalid JSON in test cases file"}), 400
        
        # Track updates
        updated_count = 0
        not_found = []
        
        # Process each test case to update
        for update_item in test_cases_to_update:
            scenario = update_item.get('scenario')
            threat = update_item.get('threat')
            validated = update_item.get('validated', False)
            
            logging.info(f"[BATCH-UPDATE] Processing: scenario='{scenario[:30] if scenario else 'None'}...', threat='{threat}', validated={validated}")
            
            if not scenario:
                logging.warning("[BATCH-UPDATE] Skipping update with no scenario")
                not_found.append({"scenario": scenario, "threat": threat, "reason": "Missing scenario"})
                continue
            
            # Find and update the matching test case
            found = False
            
            if isinstance(file_data.get("result"), dict) and "test_cases" in file_data["result"]:
                for tc in file_data["result"]["test_cases"]:
                    tc_scenario = tc.get("Scenario", "")
                    tc_threat = tc.get("Threat Type", "")
                    
                    if threat:
                        match = tc_scenario == scenario and tc_threat == threat
                    else:
                        match = tc_scenario == scenario
                    
                    if match:
                        # Update the validated field
                        if "validated" in tc:
                            tc["validated"] = validated
                            logging.info(f"[BATCH-UPDATE] Updated test case (top level)")
                            updated_count += 1
                            found = True
                            break
                        elif "test_cases" in tc and len(tc["test_cases"]) > 0:
                            tc["test_cases"][0]["validated"] = validated
                            logging.info(f"[BATCH-UPDATE] Updated test case (nested)")
                            updated_count += 1
                            found = True
                            break
            
            elif isinstance(file_data.get("result"), list):
                for tc in file_data["result"]:
                    tc_scenario = tc.get("Scenario", "")
                    tc_threat = tc.get("Threat Type", "")
                    
                    if threat:
                        match = tc_scenario == scenario and tc_threat == threat
                    else:
                        match = tc_scenario == scenario
                    
                    if match:
                        # Update the validated field
                        if "validated" in tc:
                            tc["validated"] = validated
                            logging.info(f"[BATCH-UPDATE] Updated test case (top level)")
                            updated_count += 1
                            found = True
                            break
                        elif "test_cases" in tc and len(tc["test_cases"]) > 0:
                            tc["test_cases"][0]["validated"] = validated
                            logging.info(f"[BATCH-UPDATE] Updated test case (nested)")
                            updated_count += 1
                            found = True
                            break
            
            if not found:
                threat_info = f" and threat '{threat}'" if threat else ""
                logging.warning(f"[BATCH-UPDATE] Test case NOT FOUND with scenario '{scenario}'{threat_info}")
                not_found.append({"scenario": scenario, "threat": threat, "reason": "Test case not found"})
        
        # Write back to file once after all updates
        try:
            logging.info(f"[BATCH-UPDATE] Writing updated file back to {filepath}")
            with open(filepath, 'w') as f:
                json.dump(file_data, f, indent=2)
            logging.info(f"[BATCH-UPDATE] File written successfully")
        except Exception as write_error:
            logging.error(f"[BATCH-UPDATE] Error writing to file: {str(write_error)}")
            return jsonify({"error": f"Error saving changes: {str(write_error)}"}), 500
        
        # Prepare response
        response_data = {
            "message": f"Batch update completed: {updated_count} test case(s) updated",
            "updated_count": updated_count,
            "total_requested": len(test_cases_to_update),
            "not_found": not_found if not_found else None
        }
        
        logging.info(f"[BATCH-UPDATE] Sending response: {json.dumps(response_data)}")
        return jsonify(response_data)
        
    except Exception as e:
        logging.error(f"[BATCH-UPDATE] Error in batch update: {str(e)}")
        logging.exception("[BATCH-UPDATE] Full traceback:")
        return jsonify({
            "error": f"Error in batch update: {str(e)}"
        }), 500

@app.route('/api/update-asvs-test-cases', methods=['PUT'])
def update_test_case_validation():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        logging.info(f"[UPDATE-ASVS] Assessment ID: {assessment_id}")
        
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Get validation status, scenario, and threat from request body
        data = request.get_json()
        logging.info(f"[UPDATE-ASVS] Request body: {json.dumps(data)}")
        
        # Check if this is a batch update
        if 'test_cases' in data:
            logging.info(f"[UPDATE-ASVS] Batch update request with {len(data['test_cases'])} test case(s)")
            return _handle_batch_test_case_update(assessment_id, data['test_cases'])
        
        # Single test case update
        validated = data.get('validated', False)
        scenario = data.get('scenario')
        threat = data.get('threat')
        
        logging.info(f"[UPDATE-ASVS] Extracted - Validated: {validated}, Scenario: {scenario[:50] if scenario else 'None'}..., Threat: {threat}")
        
        if not scenario:
            logging.error("[UPDATE-ASVS] Scenario is required but was not provided")
            return jsonify({"error": "Scenario is required"}), 400
        
        # Read the file directly to maintain structure
        filepath = os.path.join(_STORAGE_DIR, assessment_id, 'test_cases.json')
        logging.info(f"[UPDATE-ASVS] Reading file from: {filepath}")
        
        if not os.path.exists(filepath):
            logging.error(f"[UPDATE-ASVS] Test cases file not found at {filepath}")
            return jsonify({"error": "Test cases file not found"}), 404
        
        try:
            with open(filepath, 'r') as f:
                file_data = json.load(f)
            logging.info(f"[UPDATE-ASVS] File loaded successfully, structure keys: {list(file_data.keys())}")
        except json.JSONDecodeError as e:
            logging.error(f"[UPDATE-ASVS] JSON decode error: {str(e)}")
            return jsonify({"error": "Invalid JSON in test cases file"}), 400
        
        # Update the validated field in the result
        found = False
        update_location = None
        
        if isinstance(file_data.get("result"), dict) and "test_cases" in file_data["result"]:
            logging.info(f"[UPDATE-ASVS] Found result as dict with test_cases, total test cases: {len(file_data['result']['test_cases'])}")
            
            for idx, tc in enumerate(file_data["result"]["test_cases"]):
                tc_scenario = tc.get("Scenario", "")
                tc_threat = tc.get("Threat Type", "")
                
                logging.debug(f"[UPDATE-ASVS] Checking test case {idx}: Threat='{tc_threat}', Scenario='{tc_scenario[:30]}...'")
                
                if threat:
                    match = tc_scenario == scenario and tc_threat == threat
                else:
                    match = tc_scenario == scenario
                
                if match:
                    logging.info(f"[UPDATE-ASVS] FOUND MATCH at index {idx}")
                    logging.info(f"[UPDATE-ASVS] Test case before update: {json.dumps(tc, default=str)[:200]}...")
                    
                    # Update the validated field - try top level first, then nested
                    if "validated" in tc:
                        old_value = tc.get("validated")
                        tc["validated"] = validated
                        update_location = "top_level"
                        logging.info(f"[UPDATE-ASVS] Updated 'validated' at TOP LEVEL from {old_value} to {validated}")
                    elif "test_cases" in tc and len(tc["test_cases"]) > 0:
                        old_value = tc["test_cases"][0].get("validated")
                        tc["test_cases"][0]["validated"] = validated
                        update_location = "nested"
                        logging.info(f"[UPDATE-ASVS] Updated 'validated' at NESTED level from {old_value} to {validated}")
                    else:
                        logging.warning(f"[UPDATE-ASVS] No 'validated' field found at either level")
                    
                    logging.info(f"[UPDATE-ASVS] Test case after update: {json.dumps(tc, default=str)[:200]}...")
                    found = True
                    break
        elif isinstance(file_data.get("result"), list):
            logging.info(f"[UPDATE-ASVS] Found result as list, total test cases: {len(file_data['result'])}")
            
            for idx, tc in enumerate(file_data["result"]):
                tc_scenario = tc.get("Scenario", "")
                tc_threat = tc.get("Threat Type", "")
                
                logging.debug(f"[UPDATE-ASVS] Checking test case {idx}: Threat='{tc_threat}', Scenario='{tc_scenario[:30]}...'")
                
                if threat:
                    match = tc_scenario == scenario and tc_threat == threat
                else:
                    match = tc_scenario == scenario
                
                if match:
                    logging.info(f"[UPDATE-ASVS] FOUND MATCH at index {idx}")
                    logging.info(f"[UPDATE-ASVS] Test case before update: {json.dumps(tc, default=str)[:200]}...")
                    
                    # Update the validated field - try top level first, then nested
                    if "validated" in tc:
                        old_value = tc.get("validated")
                        tc["validated"] = validated
                        update_location = "top_level"
                        logging.info(f"[UPDATE-ASVS] Updated 'validated' at TOP LEVEL from {old_value} to {validated}")
                    elif "test_cases" in tc and len(tc["test_cases"]) > 0:
                        old_value = tc["test_cases"][0].get("validated")
                        tc["test_cases"][0]["validated"] = validated
                        update_location = "nested"
                        logging.info(f"[UPDATE-ASVS] Updated 'validated' at NESTED level from {old_value} to {validated}")
                    else:
                        logging.warning(f"[UPDATE-ASVS] No 'validated' field found at either level")
                    
                    logging.info(f"[UPDATE-ASVS] Test case after update: {json.dumps(tc, default=str)[:200]}...")
                    found = True
                    break
        else:
            logging.error(f"[UPDATE-ASVS] Unexpected result structure type: {type(file_data.get('result'))}")
        
        if not found:
            threat_info = f" and threat '{threat}'" if threat else ""
            logging.error(f"[UPDATE-ASVS] Test case NOT FOUND with scenario '{scenario}'{threat_info}")
            return jsonify({"error": f"Test case with scenario '{scenario}'{threat_info} not found"}), 404
        
        # Write back to file with minimal changes
        try:
            logging.info(f"[UPDATE-ASVS] Writing updated file back to {filepath}")
            with open(filepath, 'w') as f:
                json.dump(file_data, f, indent=2)
            logging.info(f"[UPDATE-ASVS] File written successfully")
        except Exception as write_error:
            logging.error(f"[UPDATE-ASVS] Error writing to file: {str(write_error)}")
            return jsonify({"error": f"Error saving changes: {str(write_error)}"}), 500
        
        # Read back the file to verify the update
        try:
            with open(filepath, 'r') as f:
                verify_data = json.load(f)
            logging.info(f"[UPDATE-ASVS] File verified after write")
        except Exception as verify_error:
            logging.error(f"[UPDATE-ASVS] Error verifying file: {str(verify_error)}")
        
        response_data = {
            "message": "Test case validation status updated successfully",
            "scenario": scenario,
            "threat": threat,
            "validated": validated,
            "update_location": update_location
        }
        logging.info(f"[UPDATE-ASVS] Sending response: {json.dumps(response_data)}")
        
        return jsonify(response_data)
            
    except Exception as e:
        logging.error(f"[UPDATE-ASVS] Error updating test case validation: {str(e)}")
        logging.exception("[UPDATE-ASVS] Full traceback:")
        return jsonify({
            "error": f"Error updating test case validation: {str(e)}"
        }), 500
    
@app.route('/api/store-details', methods=['POST'])
def store_details():
    try:
        user = _get_request_user()
        data = request.get_json()
        assessment_id = data.get('assessment_id')
        details = data.get('details')

        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400

        if not details:
            return jsonify({"error": "Details are required"}), 400

        # Stamp the authenticated user's email so we can notify them later
        if user and user.get('email') and not details.get('created_by'):
            details['created_by'] = user['email']

        # Create the directory if it doesn't exist
        storage_dir = os.path.join(_STORAGE_DIR, assessment_id)
        os.makedirs(storage_dir, exist_ok=True)

        # Write the details to a JSON file
        details_file_path = os.path.join(storage_dir, 'details.json')
        with open(details_file_path, 'w') as f:
            json.dump(details, f, indent=2)

        return jsonify({
            "message": "Details stored successfully",
            "file_path": details_file_path
        })
        
    except Exception as e:
        logging.error(f"Error storing details: {str(e)}")
        return jsonify({
            "error": f"Error storing details: {str(e)}"
        }), 500

@app.route('/api/validate-connections', methods=['POST'])
def validate_connections():
    """
    Validate connections to external services like Confluence and Slack.
    """
    try:
        data = request.get_json()
        
        # Initialize response
        response = {
            "confluence": {"valid": True, "message": ""},
            "slack": {"valid": True, "message": ""}
        }
        
        # Validate Confluence connection if URL provided
        confluence_url = data.get('confluence_url')
        if confluence_url:
            # Basic URL validation
            try:
                parsed_url = urlparse(confluence_url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    response["confluence"] = {"valid": False, "message": "Invalid Confluence URL format"}
                else:
                    # Test connection using credentials from .env file
                    success, message = test_confluence_connection(confluence_url)
                    response["confluence"] = {"valid": success, "message": message}
            except Exception as e:
                response["confluence"] = {"valid": False, "message": f"Invalid Confluence URL: {str(e)}"}
        
        # Validate Slack connection if URL provided
        slack_url = data.get('slack_url')
        if slack_url:
            # Basic URL validation
            try:
                parsed_url = urlparse(slack_url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    response["slack"] = {"valid": False, "message": "Invalid Slack URL format"}
                else:
                    # Test connection using credentials from .env file
                    success, message = test_slack_connection(slack_url)
                    response["slack"] = {"valid": success, "message": message}
            except Exception as e:
                response["slack"] = {"valid": False, "message": f"Invalid Slack URL: {str(e)}"}
        
        return jsonify(response)
        
    except Exception as e:
        logging.error(f"Error validating connections: {str(e)}")
        return jsonify({
            "error": f"Error validating connections: {str(e)}"
        }), 500

@app.route('/api/connections', methods=['GET'])
def check_all_connections():
    """Check status of all external service connections."""
    from dotenv import dotenv_values
    env = dotenv_values('.env')

    connections = {}

    # OpenAI — actually validate the key with a live API call
    openai_key = env.get('OPENAI_API_KEY') or os.getenv('OPENAI_API_KEY', '')
    if not openai_key:
        connections['openai'] = {'connected': False, 'message': 'API key not configured'}
    else:
        try:
            import openai as _openai
            _client = _openai.OpenAI(api_key=openai_key)
            _client.models.list()
            connections['openai'] = {'connected': True, 'message': 'API key valid'}
        except _openai.AuthenticationError:
            connections['openai'] = {'connected': False, 'message': 'Invalid API key'}
        except Exception as _e:
            connections['openai'] = {'connected': False, 'message': f'Connection failed: {str(_e)[:120]}'}

    # JIRA
    jira_url = env.get('JIRA_URL', '')
    jira_user = env.get('JIRA_USERNAME', '')
    jira_token = env.get('JIRA_TOKEN', '')
    jira_project = env.get('JIRA_PROJECT', '')
    if jira_url and jira_user and jira_token:
        try:
            from jira import JIRA
            jira_client = JIRA({'server': jira_url}, basic_auth=(jira_user, jira_token))
            jira_client.myself()
            connections['jira'] = {
                'connected': True,
                'message': f'Connected to {jira_url}' + (f' (project: {jira_project})' if jira_project else '')
            }
        except Exception as e:
            connections['jira'] = {'connected': False, 'message': f'Connection failed: {str(e)[:120]}'}
    else:
        missing = [k for k, v in {'JIRA_URL': jira_url, 'JIRA_USERNAME': jira_user, 'JIRA_TOKEN': jira_token}.items() if not v]
        connections['jira'] = {'connected': False, 'message': f'Missing: {", ".join(missing)}'}

    # Confluence
    conf_key = env.get('CONFLUENCE_API_KEY') or os.getenv('CONFLUENCE_API_KEY', '')
    conf_user = env.get('CONFLUENCE_USERNAME') or os.getenv('CONFLUENCE_USERNAME', '')
    if conf_key and conf_user:
        connections['confluence'] = {'connected': True, 'message': f'Credentials configured for {conf_user}'}
    else:
        missing = [k for k, v in {'CONFLUENCE_API_KEY': conf_key, 'CONFLUENCE_USERNAME': conf_user}.items() if not v]
        connections['confluence'] = {'connected': False, 'message': f'Missing: {", ".join(missing)}'}

    # Slack
    slack_token = env.get('SLACK_API_TOKEN') or os.getenv('SLACK_API_TOKEN', '')
    if slack_token:
        slack_ok, slack_msg = test_slack_connection('https://slack.com')
        connections['slack'] = {'connected': slack_ok, 'message': slack_msg}
        # Fetch channels the bot is a member of
        if slack_ok:
            try:
                import requests as _req
                all_channels = []
                cursor = None
                while True:
                    params = {
                        'limit': 200,
                        'types': 'public_channel,private_channel',
                        'exclude_archived': True
                    }
                    if cursor:
                        params['cursor'] = cursor
                    ch_resp = _req.get(
                        'https://slack.com/api/conversations.list',
                        headers={'Authorization': f'Bearer {slack_token}'},
                        params=params,
                        timeout=10
                    )
                    ch_data = ch_resp.json()
                    if not ch_data.get('ok'):
                        logging.warning(f"Slack conversations.list error: {ch_data.get('error', 'unknown')}")
                        break
                    all_channels.extend([
                        {'id': c['id'], 'name': c['name'], 'is_private': c.get('is_private', False)}
                        for c in ch_data.get('channels', [])
                        if c.get('is_member', False)
                    ])
                    cursor = ch_data.get('response_metadata', {}).get('next_cursor')
                    if not cursor:
                        break
                connections['slack_channels'] = all_channels
            except Exception:
                connections['slack_channels'] = []
        else:
            connections['slack_channels'] = []
    else:
        connections['slack'] = {'connected': False, 'message': 'SLACK_API_TOKEN not configured'}
        connections['slack_channels'] = []

    # Google Docs — actually attempt to authenticate, not just check env var
    try:
        from utils.google_docs_handler import GoogleDocsHandler
        gd_handler = GoogleDocsHandler()
        if gd_handler.is_configured():
            connections['google_docs'] = {'connected': True, 'message': 'Service account authenticated successfully'}
        else:
            connections['google_docs'] = {'connected': False, 'message': 'GOOGLE_SERVICE_ACCOUNT_JSON not configured or authentication failed'}
    except Exception as e:
        connections['google_docs'] = {'connected': False, 'message': f'Error: {str(e)[:100]}'}

    return jsonify(connections)


@app.route('/api/settings', methods=['GET'])
def get_settings():
    try:
        # Read LLM config from env
        llm_method = get_llm_method()
        if llm_method == 'BEDROCK':
            bedrock_cfg = get_bedrock_config()
            llm_config = {
                'method': 'BEDROCK',
                'model': bedrock_cfg.get('model', 'claude-3.7-sonnet'),
                'base_url': bedrock_cfg.get('base_url', ''),
            }
        else:
            openai_key = get_openai_api_key()
            llm_config = {
                'method': 'OPENAI',
                'model': 'gpt-4o',
                'configured': bool(openai_key),
            }

        settings = _get_settings()
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "data": settings if settings else {"preContext": ""},
            "llmConfig": llm_config
        })
    except Exception as e:
        logging.error(f"Error getting settings: {str(e)}")
        return jsonify({
            "error": f"Error getting settings: {str(e)}"
        }), 500

@app.route('/api/settings', methods=['POST'])
def save_settings():
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — admin access required"}), 403
    try:
        # Get settings from request
        settings = request.get_json()
        
        # Save settings to storage/data/settings/settings.json
        _save_settings(settings)

        return jsonify({
            "message": "Settings saved successfully",
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
    except Exception as e:
        logging.error(f"Error saving settings: {str(e)}")
        return jsonify({
            "error": f"Error saving settings: {str(e)}"
        }), 500

@app.route('/api/setup/bootstrap-admin', methods=['POST'])
def bootstrap_admin():
    """Set the first admin. Only succeeds when the admins list is empty."""
    user = _get_request_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    current_admins = get_mcp_admins()
    if current_admins:
        return jsonify({"error": "Bootstrap unavailable — admins already configured"}), 403
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    if not email or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({"error": "A valid email address is required"}), 400
    save_admins([email])
    set_setup_dismissed(True)
    logging.info(f"[BOOTSTRAP] First admin set: {email}")
    return jsonify({"message": "Admin configured successfully", "admins": [email]})

@app.route('/api/admin/llm-config', methods=['GET'])
def get_admin_llm_config():
    """Return current LLM config readable by admins (no secrets)."""
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — admin access required"}), 403
    try:
        method = get_llm_method()
        tested = is_llm_tested()
        if method == 'BEDROCK':
            bedrock_cfg = get_bedrock_config()
            llm_config = {
                'method': 'BEDROCK',
                'model': bedrock_cfg.get('model', ''),
                'large_output_model': bedrock_cfg.get('large_output_model', ''),
                'base_url': bedrock_cfg.get('base_url', ''),
                'api_key_configured': bool(bedrock_cfg.get('api_key')),
                'tested': tested,
            }
        else:
            llm_config = {
                'method': 'OPENAI',
                'model': 'gpt-4o',
                'api_key_configured': bool(get_openai_api_key()),
                'tested': tested,
            }
        return jsonify({"llmConfig": llm_config})
    except Exception as e:
        logging.error(f"Error getting admin LLM config: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/llm-config', methods=['POST'])
def save_admin_llm_config():
    """Persist LLM config to settings.json. Keys stay in .env.
    Accepts optional `tested: true` flag — only set when frontend has verified
    the connection. Resets tested=False otherwise.
    """
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — admin access required"}), 403
    try:
        data = request.get_json() or {}
        allowed_keys = {'method', 'model', 'large_output_model', 'base_url'}
        llm_config = {k: v for k, v in data.items() if k in allowed_keys}
        save_llm_config(llm_config)  # resets tested=False
        if data.get('tested') is True:
            set_llm_tested(True)
        return jsonify({"message": "LLM config saved", "llmConfig": llm_config})
    except Exception as e:
        logging.error(f"Error saving admin LLM config: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/model-status', methods=['GET'])
def model_status():
    """Public endpoint — returns whether the LLM is configured AND tested.
    Reads fresh from settings.json on every request.
    """
    try:
        method = get_llm_method()
        if method == 'BEDROCK':
            cfg = get_bedrock_config()
            fields_ok = bool(cfg.get('model') and cfg.get('base_url') and cfg.get('api_key'))
        else:
            fields_ok = bool(get_openai_api_key())
        configured = fields_ok and is_llm_tested()
        return jsonify({'configured': configured, 'method': method})
    except Exception as e:
        logging.error(f"Error checking model status: {e}")
        return jsonify({'configured': False, 'method': 'UNKNOWN'})


@app.route('/api/admin/test-llm', methods=['POST'])
def test_admin_llm():
    """Admin endpoint — tests the LLM with optional pre-save config override.
    Pass { llmConfig: { method, model, base_url } } to test before saving,
    or call with an empty body to test current settings.json config.
    """
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — admin access required"}), 403
    try:
        from openai import OpenAI as _OpenAI
        data = request.get_json() or {}
        test_cfg = data.get('llmConfig')

        if test_cfg:
            # Test provided (unsaved) config
            method = test_cfg.get('method', get_llm_method())
            if method == 'BEDROCK':
                base_url = test_cfg.get('base_url') or os.getenv('BEDROCK_BASE_URL', '')
                api_key = os.getenv('BEDROCK_API_KEY', '')
                model = test_cfg.get('model', '')
                if not base_url:
                    return jsonify({"success": False, "error": "Bedrock endpoint URL is required"})
                if not api_key:
                    return jsonify({"success": False, "error": "BEDROCK_API_KEY is not set in .env"})
                if not model:
                    return jsonify({"success": False, "error": "Model name is required"})
                client = _OpenAI(base_url=base_url, default_headers={"Authorization": f"Bearer {api_key}"})
            else:
                api_key = os.getenv('OPENAI_API_KEY', '')
                model = test_cfg.get('model', 'gpt-4o')
                if not api_key:
                    return jsonify({"success": False, "error": "OPENAI_API_KEY is not set in .env"})
                client = _OpenAI(api_key=api_key)

            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Reply with just the word OK."}],
                max_tokens=10
            )
            result = response.choices[0].message.content.strip()
            return jsonify({"success": True, "response": result, "model": model})
        else:
            # Test current settings.json config via OpenAIHandler
            from llm.openai_module import OpenAIHandler
            handler = OpenAIHandler()
            if not handler.configured:
                return jsonify({"success": False, "error": "LLM is not configured — set model and endpoint in Settings"})
            result = handler.send_prompt("Reply with just the word OK.")
            return jsonify({"success": True, "response": result, "model": handler.model})
    except Exception as e:
        logging.error(f"LLM test failed: {e}")
        return jsonify({"success": False, "error": str(e)})


@app.route('/api/admin/test-github', methods=['GET'])
def test_github_connection():
    """Admin endpoint — verifies GITHUB_TOKEN from .env by calling the GitHub API."""
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — admin access required"}), 403
    import urllib.request as _urllib_request
    import urllib.error as _urllib_error
    token = os.getenv('GITHUB_TOKEN', '').strip()
    if not token:
        return jsonify({"success": False, "error": "GITHUB_TOKEN is not set in .env"})
    try:
        req = _urllib_request.Request(
            'https://api.github.com/user',
            headers={'Authorization': f'token {token}', 'User-Agent': 'ThreatShield/1.0', 'Accept': 'application/vnd.github+json'},
        )
        with _urllib_request.urlopen(req, timeout=8) as resp:
            scopes = resp.headers.get('X-OAuth-Scopes', '')
            import json as _json
            user = _json.loads(resp.read().decode())
        return jsonify({
            "success": True,
            "login": user.get('login'),
            "name": user.get('name') or user.get('login'),
            "scopes": [s.strip() for s in scopes.split(',') if s.strip()],
        })
    except _urllib_error.HTTPError as e:
        return jsonify({"success": False, "error": f"GitHub API returned {e.code}: {e.reason}"})
    except Exception as e:
        logging.error(f"GitHub connection test failed: {e}")
        return jsonify({"success": False, "error": str(e)})


@app.route('/api/admin/admins', methods=['GET'])
def get_admin_list():
    """Return the current admin email list."""
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — admin access required"}), 403
    try:
        return jsonify({"admins": get_mcp_admins()})
    except Exception as e:
        logging.error(f"Error getting admin list: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/admins', methods=['POST'])
def save_admin_list():
    """Persist admin email list to settings.json."""
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — admin access required"}), 403
    try:
        data = request.get_json() or {}
        admins = data.get('admins', [])
        if not isinstance(admins, list):
            return jsonify({"error": "'admins' must be a list of email strings"}), 400
        cleaned = [e.strip().lower() for e in admins if e.strip()]
        if not cleaned:
            return jsonify({"error": "At least one admin must remain"}), 400
        save_admins(cleaned)
        return jsonify({"message": "Admin list saved", "admins": get_mcp_admins()})
    except Exception as e:
        logging.error(f"Error saving admin list: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/general-config', methods=['GET'])
def get_general_config_route():
    """Return general app config (e.g. display timezone). Public — used to render timestamps."""
    return jsonify({"generalConfig": get_general_config()})


@app.route('/api/admin/general-config', methods=['POST'])
def save_general_config_route():
    """Persist general app config (display timezone) to settings.json."""
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — admin access required"}), 403
    config = request.get_json()
    if not config:
        return jsonify({"error": "Request body must be a JSON object"}), 400
    save_general_config(config)
    return jsonify({
        "message": "General config saved",
        "generalConfig": get_general_config(),
        "timestamp": datetime.datetime.utcnow().isoformat()
    })


@app.route('/api/admin/threat-filter-config', methods=['GET'])
def get_threat_filter_config_route():
    """Return the current threat filter / false-positive suppression config."""
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — admin access required"}), 403
    return jsonify({"threatFilterConfig": get_threat_filter_config()})


@app.route('/api/admin/threat-filter-config', methods=['POST'])
def save_threat_filter_config_route():
    """Persist a new threat filter config to settings.json."""
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — admin access required"}), 403
    config = request.get_json()
    if not config:
        return jsonify({"error": "Request body must be a JSON object"}), 400
    save_threat_filter_config(config)
    return jsonify({
        "message": "Threat filter config saved",
        "timestamp": datetime.datetime.utcnow().isoformat()
    })


@app.route('/api/mcp-servers', methods=['GET'])
def list_mcp_servers_endpoint():
    try:
        servers = mcp_handler.list_mcp_servers()
        return jsonify({"servers": servers})
    except Exception as e:
        logging.error(f"Error listing MCP servers: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/mcp-admin-check', methods=['GET'])
def mcp_admin_check():
    return jsonify({"is_admin": _is_mcp_admin()})


@app.route('/api/mcp-servers', methods=['POST'])
def add_mcp_server_endpoint():
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — MCP admin access required"}), 403
    try:
        config = request.get_json()
        server = mcp_handler.add_mcp_server(config)
        return jsonify({"server": server}), 201
    except Exception as e:
        logging.error(f"Error adding MCP server: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/mcp-servers/<server_id>', methods=['PUT'])
def update_mcp_server_endpoint(server_id):
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — MCP admin access required"}), 403
    try:
        updates = request.get_json()
        server = mcp_handler.update_mcp_server(server_id, updates)
        if server is None:
            return jsonify({"error": "Server not found"}), 404
        return jsonify({"server": server})
    except Exception as e:
        logging.error(f"Error updating MCP server: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/mcp-servers/<server_id>', methods=['DELETE'])
def delete_mcp_server_endpoint(server_id):
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — MCP admin access required"}), 403
    try:
        mcp_handler.delete_mcp_server(server_id)
        return jsonify({"message": "Server deleted"})
    except Exception as e:
        logging.error(f"Error deleting MCP server: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/mcp-servers/<server_id>/test', methods=['POST'])
def test_mcp_server_endpoint(server_id):
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden — MCP admin access required"}), 403
    try:
        result = mcp_handler.test_mcp_server(server_id)
        status = 200 if result.get("success") else 400
        return jsonify(result), status
    except Exception as e:
        logging.error(f"Error testing MCP server: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/threat-model/<assessment_id>', methods=['DELETE'])
def delete_threat_model(assessment_id):
    if not _is_mcp_admin():
        return jsonify({"error": "Unauthorized. Admin privileges required"}), 403

    try:
        import shutil
        assessment_dir = os.path.join(_STORAGE_DIR, assessment_id)
        if os.path.exists(assessment_dir):
            shutil.rmtree(assessment_dir)

        upload_dirs = [
            os.path.join(_UPLOAD_DIR, f"{assessment_id}_files"),
            os.path.join(_UPLOAD_DIR, f"persist_{assessment_id}")
        ]
        for upload_dir in upload_dirs:
            if os.path.exists(upload_dir):
                shutil.rmtree(upload_dir)

        return jsonify({"message": f"Threat model {assessment_id} deleted successfully"})
    except Exception as e:
        logging.error(f"Error deleting threat model: {str(e)}")
        return jsonify({"error": f"Error deleting threat model: {str(e)}"}), 500


@app.route('/api/admin/retrigger/<assessment_id>', methods=['POST'])
def admin_retrigger_assessment(assessment_id):
    if not _is_mcp_admin():
        return jsonify({"error": "Unauthorized. Admin privileges required"}), 403

    details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
    if not os.path.exists(details_path):
        return jsonify({"error": "Assessment not found"}), 404

    try:
        # Remove output files so the pipeline regenerates them
        output_files = ['rag_result.json', 'threat_model.json', 'dread_assessment.json',
                        'mitigation.json', 'attack_tree.json', 'test_cases.json']
        for fname in output_files:
            fpath = os.path.join(_STORAGE_DIR, assessment_id, fname)
            if os.path.exists(fpath):
                os.remove(fpath)

        # Reset status to 'failed' so _enqueue_assessment will accept it
        with open(details_path, 'r') as f:
            details = json.load(f)
        details['status'] = 'failed'
        details.pop('error_message', None)
        details.pop('current_step', None)
        with open(details_path, 'w') as f:
            json.dump(details, f, indent=2)

        _enqueue_assessment(assessment_id)
        return jsonify({"message": f"Assessment {assessment_id} re-queued successfully"})
    except Exception as e:
        logging.error(f"Error retriggering assessment {assessment_id}: {str(e)}")
        return jsonify({"error": f"Error retriggering assessment: {str(e)}"}), 500

@app.route("/api/assessment-files/<assessment_id>", methods=['GET'])
def get_assessment_files(assessment_id):
    """List uploaded source files for an assessment."""
    try:
        details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
        if not os.path.exists(details_path):
            return jsonify({"files": []})
        with open(details_path, 'r') as f:
            details = json.load(f)
        project_name = details.get('projectName', '').replace(' ', '_')
        if not project_name:
            return jsonify({"files": []})
        upload_dir = os.path.join(_UPLOAD_DIR, f"{project_name}_files")
        if not os.path.exists(upload_dir):
            return jsonify({"files": []})
        files = []
        for fname in os.listdir(upload_dir):
            fpath = os.path.join(upload_dir, fname)
            if os.path.isfile(fpath):
                files.append({
                    "name": fname,
                    "size": os.path.getsize(fpath),
                })
        return jsonify({"files": files})
    except Exception as e:
        logging.error(f"Error listing assessment files: {str(e)}")
        return jsonify({"files": []})

@app.route("/api/download-assessment-file/<assessment_id>/<path:filename>", methods=['GET'])
def download_assessment_file(assessment_id, filename):
    """Download a specific uploaded source file for an assessment."""
    try:
        details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
        if not os.path.exists(details_path):
            return jsonify({"error": "Assessment not found"}), 404
        with open(details_path, 'r') as f:
            details = json.load(f)
        project_name = details.get('projectName', '').replace(' ', '_')
        if not project_name:
            return jsonify({"error": "Project name not found"}), 404
        upload_dir = os.path.join(_UPLOAD_DIR, f"{project_name}_files")
        safe_filename = os.path.basename(filename)
        file_path = os.path.join(upload_dir, safe_filename)
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
        return send_from_directory(upload_dir, safe_filename, as_attachment=True)
    except Exception as e:
        logging.error(f"Error downloading assessment file: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/storage",methods=['GET'])
def access_storage():
    try:
        assessment_id = request.args.get('assessment_id')
        assessment_name = request.args.get('assessment_name')
        
        # If no assessment_id is provided, return list of all assessments (metadata only)
        if not assessment_id:
            assessments = storage_handler.retrive_from_storage()
            return jsonify({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "data": assessments
            })
        
        # If assessment_id is provided but no assessment_name, return error
        if not assessment_name:
            return jsonify({"error": "Assessment name is required when assessment ID is provided"}), 400
            
        # Get specific assessment data from storage
        retrieved_data = storage_handler.retrive_from_storage(assessment_id=assessment_id, assessment_name=assessment_name)
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": retrieved_data
        })
    except ValueError as e:
        logging.error(f"Invalid request: {str(e)}")
        return jsonify({
            "error": f"Invalid request: {str(e)}"
        }), 400
    except Exception as e:
        logging.error(f"Error retrieving data: {str(e)}")
        return jsonify({
            "error": f"Error retrieving data: {str(e)}"
        }), 500

@app.route('/api/analytics-data', methods=['GET'])
def get_analytics_data():
    """Return only the data fields needed by the Analytics page for all assessments.
    Reads details.json + 4 report JSONs per assessment instead of all 10."""
    try:
        storage_dir = _STORAGE_DIR
        if not os.path.exists(storage_dir):
            return jsonify({"timestamp": datetime.datetime.utcnow().isoformat(), "data": []})

        # Only the files Analytics actually uses
        analytics_files = {
            'threat_model.json': 'threat_model',
            'dread_assessment.json': 'dread_assessment',
            'mitigation.json': 'mitigation',
            'attack_tree.json': 'attack_tree',
            'test_cases.json': 'test_cases',
        }

        results = []
        for assessment_id in os.listdir(storage_dir):
            assessment_dir = os.path.join(storage_dir, assessment_id)
            if not os.path.isdir(assessment_dir):
                continue

            # Read details.json
            details = None
            details_path = os.path.join(assessment_dir, 'details.json')
            if os.path.exists(details_path):
                try:
                    with open(details_path, 'r') as f:
                        details = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    pass

            # Read only the 4 analytics report files
            report_data = {}
            for filename, report_type in analytics_files.items():
                filepath = os.path.join(assessment_dir, filename)
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            report_data[report_type] = json.load(f)
                    except (json.JSONDecodeError, FileNotFoundError):
                        pass

            # Only include assessments that have at least one analytics report
            if not report_data:
                continue

            timestamp = (details or {}).get('timestamp') or \
                        next((v.get('timestamp') for v in report_data.values() if v.get('timestamp')), None) or \
                        datetime.datetime.utcnow().isoformat()

            # Read lightweight fields from additionalinfo.json for DEPARTMENT detail views
            data_flow_diagram_code = ''
            third_party_integrations_text = ''
            additionalinfo_path = os.path.join(assessment_dir, 'additionalinfo.json')
            if os.path.exists(additionalinfo_path):
                try:
                    with open(additionalinfo_path, 'r') as f:
                        additionalinfo = json.load(f)
                    data_flow_diagram_code = (additionalinfo.get('data_flow_diagrams') or {}).get('diagram') or ''
                    third_party_integrations_text = additionalinfo.get('third_party_integrations') or ''
                except (json.JSONDecodeError, FileNotFoundError):
                    pass

            results.append({
                'id': assessment_id,
                'name': (details or {}).get('projectName') or f"Assessment {assessment_id[:8]}",
                'timestamp': timestamp,
                'details': details,
                'data_flow_diagram_code': data_flow_diagram_code,
                'third_party_integrations_text': third_party_integrations_text,
                **report_data,
            })

        results.sort(key=lambda x: x['timestamp'], reverse=True)
        return jsonify({"timestamp": datetime.datetime.utcnow().isoformat(), "data": results})
    except Exception as e:
        logging.error(f"Error fetching analytics data: {str(e)}")
        return jsonify({"error": f"Error fetching analytics data: {str(e)}"}), 500



@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Return aggregated metrics for the Metrics dashboard.

    Query parameters (mutually exclusive):
      period=weekly          Last 7 days from now
      period=monthly         Last 30 days from now
      start_date=YYYY-MM-DD  } Custom range — both required together.
      end_date=YYYY-MM-DD    } end_date is inclusive (extended to 23:59:59).

    Returns 400 if:
      - period is not weekly/monthly and no dates supplied
      - only one of start_date / end_date is supplied
      - dates cannot be parsed
      - start_date >= end_date
    """
    try:
        import datetime as dt
        storage_dir = _STORAGE_DIR
        now = dt.datetime.utcnow()

        period   = (request.args.get('period') or '').strip().lower()
        start_str = (request.args.get('start_date') or '').strip()
        end_str   = (request.args.get('end_date')   or '').strip()

        # ── Resolve window ─────────────────────────────────────────────────────
        if start_str or end_str:
            # Custom date range — both sides are required
            if not start_str or not end_str:
                return jsonify({"error": "Both start_date and end_date are required for a custom range"}), 400
            try:
                window_start = dt.datetime.strptime(start_str, '%Y-%m-%d')
                # Include the full end day (23:59:59)
                window_end   = dt.datetime.strptime(end_str, '%Y-%m-%d').replace(
                    hour=23, minute=59, second=59
                )
            except ValueError:
                return jsonify({"error": "Invalid date format. Use YYYY-MM-DD (e.g. 2026-01-15)"}), 400
            if window_start >= window_end:
                return jsonify({"error": "start_date must be earlier than end_date"}), 400
        elif period == 'monthly':
            window_start = now - dt.timedelta(days=30)
            window_end   = now
        elif period in ('weekly', ''):
            # Default to weekly when no period or dates are provided
            window_start = now - dt.timedelta(days=7)
            window_end   = now
        else:
            return jsonify({"error": f"Unknown period '{period}'. Use weekly, monthly, or supply start_date + end_date"}), 400

        if not os.path.exists(storage_dir):
            return jsonify({
                "timestamp": now.isoformat(),
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "period": {}, "all_time": {}, "cost_trend": []
            })

        all_assessments = []
        period_assessments = []

        for assessment_id in os.listdir(storage_dir):
            assessment_dir = os.path.join(storage_dir, assessment_id)
            if not os.path.isdir(assessment_dir):
                continue
            details_path = os.path.join(assessment_dir, 'details.json')
            if not os.path.exists(details_path):
                continue
            try:
                with open(details_path) as f:
                    details = json.load(f)
            except Exception:
                continue

            ts_str = details.get('timestamp') or ''
            try:
                ts = dt.datetime.fromisoformat(ts_str.replace('Z', '+00:00')).replace(tzinfo=None)
            except Exception:
                ts = now

            # Read pipeline outputs
            def _read_json(name):
                p = os.path.join(assessment_dir, name)
                try:
                    with open(p) as f:
                        return json.load(f)
                except Exception:
                    return None

            threat_model = _read_json('threat_model.json')
            dread = _read_json('dread_assessment.json')
            test_cases = _read_json('test_cases.json')
            additionalinfo = _read_json('additionalinfo.json')

            threats = []
            if threat_model:
                raw = threat_model.get('result') or threat_model
                if isinstance(raw, dict):
                    raw = raw.get('raw_response') or raw
                threats = raw.get('threat_model') if isinstance(raw, dict) else []
                if not isinstance(threats, list):
                    threats = []

            dread_items = []
            if dread:
                raw_d = dread.get('result') or dread
                if isinstance(raw_d, dict):
                    raw_d = raw_d.get('raw_response') or raw_d
                dread_items = raw_d.get('Risk Assessment') if isinstance(raw_d, dict) else []
                if not isinstance(dread_items, list):
                    dread_items = []

            tc_list = []
            if test_cases:
                raw_tc = test_cases.get('result') or test_cases
                if isinstance(raw_tc, dict):
                    raw_tc = raw_tc.get('result') or raw_tc
                tc_list = raw_tc.get('test_cases') if isinstance(raw_tc, dict) else []
                if not isinstance(tc_list, list):
                    tc_list = []

            has_dfd = bool(additionalinfo and (additionalinfo.get('data_flow_diagrams') or {}).get('diagram'))
            has_mind_map = bool(additionalinfo and (additionalinfo.get('data_flow_diagrams') or {}).get('reactflow'))
            third_party_text = (additionalinfo or {}).get('third_party_integrations') or ''
            third_party_count = len([l for l in third_party_text.split('\n') if l.strip()]) if third_party_text else 0

            pipeline_cost = details.get('pipeline_cost') or {}
            status = details.get('status', '')
            source = details.get('source', '')
            queue = details.get('queue') or {}
            has_slack = bool((details.get('additionalDocuments') or {}).get('slackThread') or queue.get('slack_thread'))
            has_confluence = bool((details.get('additionalDocuments') or {}).get('confluenceDoc') or queue.get('prd_url'))

            entry = {
                'id': assessment_id,
                'ts': ts,
                'details': details,
                'status': status,
                'source': source,
                'threats': threats,
                'dread_items': dread_items,
                'tc_list': tc_list,
                'has_diagram': has_dfd or has_mind_map,
                'third_party_count': third_party_count,
                'pipeline_cost': pipeline_cost,
                'has_slack': has_slack,
                'has_confluence': has_confluence,
                'is_auto': source == 'queue',
                'secreview_id': queue.get('secreview_id'),
            }
            all_assessments.append(entry)
            if window_start <= ts <= window_end:
                period_assessments.append(entry)

        def _compute_metrics(assessments, all_a):
            total = len(assessments)
            completed = [a for a in assessments if a['status'] == 'completed']
            auto_triggered = [a for a in assessments if a['is_auto']]
            auto_completed = [a for a in auto_triggered if a['status'] == 'completed']
            secreview_with_auto = [a for a in assessments if a['secreview_id']]

            all_threats = [t for a in assessments for t in a['threats']]
            threat_count = len(all_threats)

            # DREAD tier buckets
            tier_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for a in assessments:
                for item in a['dread_items']:
                    scores = [item.get('Damage Potential', 0), item.get('Reproducibility', 0),
                              item.get('Exploitability', 0), item.get('Affected Users', 0),
                              item.get('Discoverability', 0)]
                    avg = sum(s for s in scores if isinstance(s, (int, float))) / max(len([s for s in scores if isinstance(s, (int, float))]), 1)
                    if avg >= 8:
                        tier_counts['Critical'] += 1
                    elif avg >= 6:
                        tier_counts['High'] += 1
                    elif avg >= 4:
                        tier_counts['Medium'] += 1
                    else:
                        tier_counts['Low'] += 1

            total_dread = sum(tier_counts.values())

            # Test case coverage
            threats_with_tc = set()
            for a in assessments:
                for tc in a['tc_list']:
                    t_name = tc.get('Threat Type') or tc.get('threat') or tc.get('threat_type') or ''
                    if t_name:
                        threats_with_tc.add(f"{a['id']}::{t_name}")
            all_threat_keys = set()
            for a in assessments:
                for t in a['threats']:
                    all_threat_keys.add(f"{a['id']}::{t.get('Threat Type','')}")
            tc_coverage_pct = round(len(threats_with_tc) / max(len(all_threat_keys), 1) * 100, 1)

            # DFD / mind-map success
            # Diagram (DFD) generation — both Mermaid and React Flow come from the same call
            diagram_success = len([a for a in completed if a['has_diagram']])
            diagram_rate = round(diagram_success / max(len(completed), 1) * 100, 1)

            # DREAD report coverage
            dread_covered = [a for a in completed if a['dread_items']]
            dread_coverage_pct = round(len(dread_covered) / max(len(completed), 1) * 100, 1)

            # Avg threats per review
            avg_threats = round(threat_count / max(len(completed), 1), 1)

            # Auto-trigger success rate
            auto_success_rate = round(len(auto_completed) / max(len(auto_triggered), 1) * 100, 1)

            # End-to-end completion rate
            e2e_rate = round(len(completed) / max(total, 1) * 100, 1)

            # Context validation failure
            missing_context = [a for a in assessments if not a['has_slack'] and not a['has_confluence']]
            ctx_fail_rate = round(len(missing_context) / max(total, 1) * 100, 1)

            # SecReview % with auto trigger
            secreview_total = len([a for a in assessments if a['secreview_id']])
            secreview_auto_pct = round(len([a for a in assessments if a['secreview_id'] and a['is_auto']]) / max(secreview_total, 1) * 100, 1)

            # Cost metrics
            total_cost = round(sum(a['pipeline_cost'].get('total_cost', 0) for a in assessments), 4)
            total_input_tokens = sum(a['pipeline_cost'].get('total_input_tokens', 0) for a in assessments)
            total_output_tokens = sum(a['pipeline_cost'].get('total_output_tokens', 0) for a in assessments)
            avg_cost_per_review = round(total_cost / max(len(completed), 1), 4)
            avg_tokens_per_review = round((total_input_tokens + total_output_tokens) / max(len(completed), 1))
            cost_per_threat = round(total_cost / max(threat_count, 1), 6)
            total_tc = sum(len(a['tc_list']) for a in assessments)
            cost_per_tc = round(total_cost / max(total_tc, 1), 6)

            # Period-over-period threat count (compare to previous same-length window)
            # Stored in the result so the frontend can compare two periods

            return {
                'total_assessments': total,
                'completed_assessments': len(completed),
                'auto_triggered': len(auto_triggered),
                'secreview_total': secreview_total,
                'secreview_auto_pct': secreview_auto_pct,
                'total_threats': threat_count,
                'dread_tiers': tier_counts,
                'total_dread_scored': total_dread,
                'tc_coverage_pct': tc_coverage_pct,
                'total_test_cases': total_tc,
                'dread_coverage_pct': dread_coverage_pct,
                'diagram_success_rate': diagram_rate,
                'avg_threats_per_review': avg_threats,
                'auto_trigger_success_rate': auto_success_rate,
                'e2e_completion_rate': e2e_rate,
                'context_failure_rate': ctx_fail_rate,
                'total_cost': total_cost,
                'total_input_tokens': total_input_tokens,
                'total_output_tokens': total_output_tokens,
                'avg_cost_per_review': avg_cost_per_review,
                'avg_tokens_per_review': avg_tokens_per_review,
                'cost_per_threat': cost_per_threat,
                'cost_per_test_case': cost_per_tc,
            }

        def _empty_metrics():
            return {
                'period': {}, 'all_time': {},
                'window_start': '', 'window_end': ''
            }

        period_m = _compute_metrics(period_assessments, all_assessments)
        all_time_m = _compute_metrics(all_assessments, all_assessments)

        # Period-over-period threat comparison: get prev window of same length
        delta = window_end - window_start
        prev_start = window_start - delta
        prev_end = window_start
        prev_assessments = [a for a in all_assessments if prev_start <= a['ts'] <= prev_end]
        prev_threats = sum(len(a['threats']) for a in prev_assessments)
        period_m['prev_period_threats'] = prev_threats

        # Monthly cost trend (last 6 months)
        monthly_costs = {}
        for a in all_assessments:
            key = a['ts'].strftime('%Y-%m')
            if key not in monthly_costs:
                monthly_costs[key] = {'cost': 0.0, 'input_tokens': 0, 'output_tokens': 0, 'count': 0}
            monthly_costs[key]['cost'] += a['pipeline_cost'].get('total_cost', 0)
            monthly_costs[key]['input_tokens'] += a['pipeline_cost'].get('total_input_tokens', 0)
            monthly_costs[key]['output_tokens'] += a['pipeline_cost'].get('total_output_tokens', 0)
            monthly_costs[key]['count'] += 1

        sorted_months = sorted(monthly_costs.keys())[-6:]
        cost_trend = [{'month': m, **monthly_costs[m]} for m in sorted_months]

        return jsonify({
            "timestamp": now.isoformat(),
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "period": period_m,
            "all_time": all_time_m,
            "cost_trend": cost_trend,
        })
    except Exception as e:
        logging.error(f"Error computing metrics: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/department-additional-info', methods=['GET'])
def get_department_additional_info():
    """Return vendor text and DFD diagram code for every assessment in a DEPARTMENT."""
    department = (request.args.get('department') or '').strip().lower()
    if not department:
        return jsonify({'error': 'department parameter required'}), 400
    try:
        storage_dir = _STORAGE_DIR
        results = []
        if not os.path.exists(storage_dir):
            return jsonify({'data': []})
        for assessment_id in os.listdir(storage_dir):
            assessment_dir = os.path.join(storage_dir, assessment_id)
            if not os.path.isdir(assessment_dir):
                continue
            details_path = os.path.join(assessment_dir, 'details.json')
            if not os.path.exists(details_path):
                continue
            try:
                with open(details_path) as f:
                    details = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                continue
            if (details.get('department') or '').strip().lower() != department:
                continue
            data_flow_diagram_code = ''
            reactflow_data = ''
            third_party_integrations_text = ''
            additionalinfo_path = os.path.join(assessment_dir, 'additionalinfo.json')
            if os.path.exists(additionalinfo_path):
                try:
                    with open(additionalinfo_path) as f:
                        ai = json.load(f)
                    dfd = ai.get('data_flow_diagrams') or {}
                    data_flow_diagram_code = dfd.get('diagram') or ''
                    reactflow_data = dfd.get('reactflow') or ''
                    third_party_integrations_text = ai.get('third_party_integrations') or ''
                except (json.JSONDecodeError, FileNotFoundError):
                    pass
            results.append({
                'id': assessment_id,
                'data_flow_diagram_code': data_flow_diagram_code,
                'reactflow_data': reactflow_data,
                'third_party_integrations_text': third_party_integrations_text,
            })
        return jsonify({'data': results})
    except Exception as e:
        logging.error(f"Error fetching DEPARTMENT additional info: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/department-secbugs', methods=['GET'])
def get_department_secbugs():
    """Return deduplicated open SecBugs for every assessment in a DEPARTMENT."""
    department = (request.args.get('department') or '').strip().lower()
    if not department:
        return jsonify({'error': 'department parameter required'}), 400
    try:
        storage_dir = _STORAGE_DIR
        seen_ids = set()
        results = []
        if not os.path.exists(storage_dir):
            return jsonify({'data': []})
        # Sort assessment dirs by mtime descending so the most recent data wins dedup
        dirs = sorted(
            [d for d in os.listdir(storage_dir) if os.path.isdir(os.path.join(storage_dir, d))],
            key=lambda d: os.path.getmtime(os.path.join(storage_dir, d)),
            reverse=True,
        )
        for assessment_id in dirs:
            assessment_dir = os.path.join(storage_dir, assessment_id)
            details_path = os.path.join(assessment_dir, 'details.json')
            if not os.path.exists(details_path):
                continue
            try:
                with open(details_path) as f:
                    details = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                continue
            if (details.get('department') or '').strip().lower() != department:
                continue
            secbug_path = os.path.join(assessment_dir, 'secbug.json')
            if not os.path.exists(secbug_path):
                continue
            try:
                with open(secbug_path) as f:
                    secbug_data = json.load(f)
                bugs = (secbug_data.get('result') or [])
                for bug in bugs:
                    bug_id = bug.get('id') or ''
                    if not bug_id or bug_id in seen_ids:
                        continue
                    seen_ids.add(bug_id)
                    results.append({
                        'id':       bug_id,
                        'name':     bug.get('name') or '',
                        'status':   bug.get('status') or '',
                        'priority': bug.get('priority') or '',
                    })
            except (json.JSONDecodeError, FileNotFoundError):
                continue
        _priority_order = {
            'critical': 0, 'highest': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'lowest': 4,
        }
        results.sort(key=lambda b: _priority_order.get((b['priority'] or '').lower(), 5))
        return jsonify({'data': results})
    except Exception as e:
        logging.error(f"Error fetching DEPARTMENT secbugs: {e}")
        return jsonify({'error': str(e)}), 500


# ── Consolidated diagram ───────────────────────────────────────────────────────

_CONSOLIDATED_DIR = os.path.join(_STORAGE_DIR, 'data', 'consolidated_diagrams')


def _consolidated_group_dir(group_id: str) -> str:
    return os.path.join(_CONSOLIDATED_DIR, group_id)


def _get_consolidated_status(group_id: str) -> dict:
    path = os.path.join(_consolidated_group_dir(group_id), 'status.json')
    if not os.path.exists(path):
        return {'status': 'idle'}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {'status': 'idle'}


def _set_consolidated_status(group_id: str, status: str, **kwargs):
    d = _consolidated_group_dir(group_id)
    os.makedirs(d, exist_ok=True)
    current = _get_consolidated_status(group_id)
    current['status'] = status
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if status == 'running':
        current['started_at'] = now
        current.pop('completed_at', None)
        current.pop('error', None)
    elif status in ('completed', 'failed'):
        current['completed_at'] = now
    for k, v in kwargs.items():
        current[k] = v
    with open(os.path.join(d, 'status.json'), 'w') as f:
        json.dump(current, f, indent=2)


def _get_consolidated_diagram(group_id: str):
    path = os.path.join(_consolidated_group_dir(group_id), 'diagram.json')
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _run_consolidated_diagram(group_id: str, assessment_ids: list):
    """Background task: collect reactflow data and generate consolidated diagram."""
    try:
        from core.consolidate_diagram import ConsolidateDiagramGenerator
        openai_handler = OpenAIHandler()
        generator = ConsolidateDiagramGenerator(openai_handler)

        reactflow_inputs = []
        for aid in assessment_ids:
            ai_path = os.path.join(_STORAGE_DIR, aid, 'additionalinfo.json')
            if os.path.exists(ai_path):
                try:
                    with open(ai_path) as f:
                        ai = json.load(f)
                    rf = (ai.get('data_flow_diagrams') or {}).get('reactflow') or ''
                    if rf:
                        reactflow_inputs.append({'assessment_id': aid, 'reactflow': rf})
                except Exception as e:
                    logging.warning(f"[consolidate] Skipping {aid}: {e}")

        if not reactflow_inputs:
            _set_consolidated_status(
                group_id, 'failed',
                error='No reactflow diagram data found in any of the selected assessments.'
            )
            return

        _set_consolidated_status(group_id, 'running', source_count=len(reactflow_inputs))
        result = generator.consolidate(reactflow_inputs, group_id)

        d = _consolidated_group_dir(group_id)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, 'diagram.json'), 'w') as f:
            json.dump(result, f, indent=2)

        _set_consolidated_status(group_id, 'completed', source_count=len(reactflow_inputs))
        logging.info(f"[consolidate] Completed for group '{group_id}' ({len(reactflow_inputs)} sub-models)")

    except Exception as e:
        logging.error(f"[consolidate] Failed for group '{group_id}': {e}")
        _set_consolidated_status(group_id, 'failed', error=str(e))


@app.route('/api/consolidated-diagram/generate', methods=['POST'])
def generate_consolidated_diagram():
    """Trigger consolidated diagram generation for a DEPARTMENT or custom group."""
    data = request.get_json() or {}
    group_id = (data.get('group_id') or '').strip()
    assessment_ids = data.get('assessment_ids') or []

    if not group_id:
        return jsonify({'error': 'group_id is required'}), 400
    if not assessment_ids:
        return jsonify({'error': 'assessment_ids is required'}), 400

    current = _get_consolidated_status(group_id)
    if current.get('status') == 'running':
        return jsonify({'message': 'Consolidation already in progress', 'status': current}), 200

    _set_consolidated_status(group_id, 'running')
    t = threading.Thread(
        target=_run_consolidated_diagram,
        args=(group_id, assessment_ids),
        daemon=True,
        name=f"consolidate-{group_id}",
    )
    t.start()

    return jsonify({'message': 'Consolidation started', 'status': {'status': 'running'}}), 202


@app.route('/api/consolidated-diagram/status', methods=['GET'])
def get_consolidated_diagram_status():
    """Return current status and (if completed) the diagram for a group."""
    group_id = (request.args.get('group_id') or '').strip()
    if not group_id:
        return jsonify({'error': 'group_id is required'}), 400

    status = _get_consolidated_status(group_id)
    diagram = _get_consolidated_diagram(group_id) if status.get('status') == 'completed' else None
    return jsonify({'status': status, 'diagram': diagram})


@app.route('/api/teams', methods=['GET'])
def list_teams():
    return jsonify({"teams": get_teams()})

@app.route('/api/teams', methods=['POST'])
def add_team():
    if not _is_mcp_admin():
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({"error": "Team name is required"}), 400
    teams = get_teams()
    if name in teams:
        return jsonify({"error": "Team already exists"}), 409
    teams.append(name)
    save_teams(teams)
    return jsonify({"teams": teams})

@app.route('/api/teams/<path:name>', methods=['DELETE'])
def delete_team(name):
    if not _is_mcp_admin():
        return jsonify({"error": "Admin access required"}), 403
    teams = get_teams()
    if name not in teams:
        return jsonify({"error": "Team not found"}), 404
    teams.remove(name)
    save_teams(teams)
    return jsonify({"teams": teams})

@app.route('/api/report/download-json', methods=['GET'])
def download_combined_json():
    try:
        assessment_id = request.args.get('assessment_id')
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Create the combined JSON structure
        combined_data = {
            "Info": {},
            "threatmodel": {},
            "attacktree": {},
            "dread": {},
            "mitigations": {}
        }
        
        # Load details.json
        details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
        if os.path.exists(details_path):
            with open(details_path, 'r') as f:
                combined_data["Info"] = json.load(f)
        
        # Load threat_model.json
        threat_model_path = os.path.join(_STORAGE_DIR, assessment_id, 'threat_model.json')
        if os.path.exists(threat_model_path):
            with open(threat_model_path, 'r') as f:
                combined_data["threatmodel"] = json.load(f)
        
        # Load attack_tree.json
        attack_tree_path = os.path.join(_STORAGE_DIR, assessment_id, 'attack_tree.json')
        if os.path.exists(attack_tree_path):
            with open(attack_tree_path, 'r') as f:
                combined_data["attacktree"] = json.load(f)
        
        # Load dread_assessment.json
        dread_path = os.path.join(_STORAGE_DIR, assessment_id, 'dread_assessment.json')
        if os.path.exists(dread_path):
            with open(dread_path, 'r') as f:
                combined_data["dread"] = json.load(f)
        
        # Load mitigation.json
        mitigation_path = os.path.join(_STORAGE_DIR, assessment_id, 'mitigation.json')
        if os.path.exists(mitigation_path):
            with open(mitigation_path, 'r') as f:
                combined_data["mitigations"] = json.load(f)
        
        # Return as downloadable JSON file
        response = Response(
            json.dumps(combined_data, indent=2),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename=threat-shield-report-{assessment_id}.json'
            }
        )
        return response
        
    except Exception as e:
        logging.error(f"Error generating combined JSON: {str(e)}")
        return jsonify({
            "error": f"Error generating combined JSON: {str(e)}"
        }), 500

@app.route('/api/report/download-pdf', methods=['GET'])
def download_pdf_report():
    """Generate and return a PDF report for the given assessment."""
    try:
        assessment_id = request.args.get('assessment_id')
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400

        storage_dir = os.path.join(_STORAGE_DIR, assessment_id)
        if not os.path.exists(storage_dir):
            return jsonify({"error": f"Assessment {assessment_id} not found"}), 404

        pdf_bytes = generate_pdf_report(assessment_id, storage_root=_STORAGE_DIR)
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=threat-shield-report-{assessment_id}.pdf'
            }
        )
    except Exception as e:
        logging.error(f"Error generating PDF report: {str(e)}")
        return jsonify({"error": f"Error generating PDF report: {str(e)}"}), 500

@app.route('/api/details', methods=['GET'])
def get_details():
    assessment_id = request.args.get('assessment_id')
    if not assessment_id:
        return jsonify({"error": "Assessment ID is required"}), 400
    details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
    if not os.path.exists(details_path):
        return jsonify({"error": f"details.json not found for assessment {assessment_id}"}), 404
    with open(details_path, 'r') as f:
        data = json.load(f)
    return jsonify(data)

@app.route('/api/generate-diagrams', methods=['GET'])
def generate_diagrams():
    try:
        # Get assessment_id from query parameter or session
        assessment_id = request.args.get('assessment_id') or session.get('assessment_id')
        if not assessment_id:
            return jsonify({"error": "Assessment ID is required"}), 400
            
        # Get threat model from storage
        threat_model_data = storage_handler.get_threat_model(assessment_id)
        if not threat_model_data:
            return jsonify({"error": "Threat model not found"}), 404
            
        # Initialize OpenAI handler
        openai_handler = OpenAIHandler()
        
        # Generate diagrams
        diagram_generator = DiagramGenerator(openai_handler)
        
        # Generate diagrams and store them
        diagram_generator.generate_diagrams(
            threat_model_data['result']['raw_response'],
            assessment_id
        )
        
        # Get the updated additionalinfo.json
        additional_info_path = os.path.join(_STORAGE_DIR, assessment_id, 'additionalinfo.json')
        if os.path.exists(additional_info_path):
            with open(additional_info_path, 'r') as f:
                additional_info = json.load(f)
        else:
            additional_info = {}
        
        # Return in the format expected by the frontend
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "result": additional_info
        })
        
    except Exception as e:
        logging.error(f"Error generating diagrams: {str(e)}")
        return jsonify({
            "error": f"Error generating diagrams: {str(e)}"
        }), 500

# ============ QUEUE MANAGEMENT ENDPOINTS ============

@app.route('/api/queue', methods=['GET'])
def get_queue():
    """Get all queue items"""
    try:
        queue_items = queue_handler.get_queue_items()
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "data": queue_items
        })
    except Exception as e:
        logging.error(f"Error retrieving queue: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/queue', methods=['POST'])
def add_queue_item():
    """Add item to queue - creates assessment folder in storage with details.json and additionalinfo.json"""
    try:
        data = request.get_json()

        required_fields = ['secreview_id', 'initiated_by', 'service_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400

        # Generate assessment_id (UUID)
        assessment_id = str(uuid.uuid4())

        # Create storage directory for this assessment
        storage_dir = os.path.join(_STORAGE_DIR, assessment_id)
        os.makedirs(storage_dir, exist_ok=True)

        # Extract queue-specific fields (matching API documentation)
        secreview_id = data.get('secreview_id', '')
        initiated_by = data.get('initiated_by', '')
        service_name = data.get('service_name', '')
        department = data.get('department', '')
        app_type = data.get('app_type', data.get('applicationType', ''))
        sensitivity_level = data.get('sensitivity_level', data.get('dataSensitivityLevel', ''))
        internet_facing = data.get('internet_facing', 'No')
        authentication = data.get('authentication', [])
        sensitive_data = data.get('sensitive_data', '')
        prd_url = data.get('prd_url', '')
        slack_thread_url = data.get('slack_thread', data.get('slackThread', ''))
        custom_prompt = data.get('custom_prompt', '')
        methodology = data.get('methodology', data.get('threatModelingMethodology', 'STRIDE'))

        # Legacy fields with defaults from new fields
        project_name = data.get('projectName', service_name)
        description = data.get('description', f'Queue assessment for {service_name}')

        # Build nested queue object (same fields as sent in API request)
        queue_data = {
            "secreview_id": secreview_id,
            "initiated_by": initiated_by,
            "service_name": service_name,
            "department": department,
            "app_type": app_type,
            "sensitivity_level": sensitivity_level,
            "internet_facing": internet_facing,
            "authentication": authentication,
            "sensitive_data": sensitive_data,
            "prd_url": prd_url,
            "slack_thread": slack_thread_url,
            "custom_prompt": custom_prompt,
            "methodology": methodology
        }

        # Create details.json
        details = {
            "projectName": project_name,
            "description": description,
            "documentSource": data.get('documentSource', 'pdf'),
            "confluenceUrl": prd_url if prd_url and ('atlassian.net' in prd_url.lower() or 'confluence' in prd_url.lower()) else '',
            "department": department,
            "applicationType": app_type,
            "isInternetFacing": internet_facing in ('Yes', True, 'yes', 'true', 1),
            "dataSensitivityLevel": sensitivity_level,
            "authenticationMethod": ', '.join(authentication) if isinstance(authentication, list) else str(authentication),
            "threatModelingMethodology": methodology,
            "status": "pending",
            "source": "queue",

            "queue": queue_data,
            "additionalDocuments": {
                "prdDoc": None,
                "confluenceDoc": None,
                "slackThread": None,
                "meetingTranscript": None
            },
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

        details_path = os.path.join(storage_dir, 'details.json')
        with open(details_path, 'w') as f:
            json.dump(details, f, indent=2)

        logging.info(f"Created details.json for assessment {assessment_id}")

        # Create additionalinfo.json
        additional_info = {
            "prdDoc": None,
            "confluenceDoc": None,
            "slackThread": None,
            "meetingTranscript": None
        }

        additionalinfo_path = os.path.join(storage_dir, 'additionalinfo.json')
        with open(additionalinfo_path, 'w') as f:
            json.dump(additional_info, f, indent=2)

        logging.info(f"Created additionalinfo.json for assessment {assessment_id}")

        # Fetch PRD content from prd_url — detect URL type and route to the right handler.
        # Only prd_url is used as a document source via the API; confluence_doc is not accepted.
        # If prd_url is a Google Doc → use service account flow.
        # If prd_url is a Confluence/Atlassian URL → use Confluence credentials.
        if prd_url and prd_url.strip():
            try:
                logging.info(f"Fetching PRD content from: {prd_url}")
                content = None

                if 'docs.google.com' in prd_url:
                    # Google Docs URL — use service account flow
                    from utils.google_docs_handler import GoogleDocsHandler
                    gd_handler = GoogleDocsHandler()
                    if gd_handler.is_configured():
                        gd_result = gd_handler.fetch_document_content(prd_url)
                        if gd_result and gd_result.get('content'):
                            content = gd_result['content']
                            logging.info("Successfully fetched PRD from Google Docs")
                    if not content:
                        raise ValueError("Google Docs service account not configured or content fetch returned empty")
                else:
                    # Confluence URL (atlassian.net or any self-hosted Confluence instance)
                    prd_docs = load_confluence_documents(prd_url)
                    if prd_docs:
                        content = "\n\n".join([doc.page_content for doc in prd_docs])
                        logging.info("Successfully fetched PRD from Confluence")

                if content:
                    additional_info['prdDoc'] = {'url': prd_url, 'content': content, 'title': 'PRD Document'}
                    details['additionalDocuments']['prdDoc'] = {'url': prd_url, 'fetched': True}
                else:
                    raise ValueError("No content could be extracted from PRD URL")
            except Exception as e:
                logging.error(f"Error fetching PRD: {str(e)}")
                additional_info['prdDoc'] = {'url': prd_url, 'error': str(e)}
                details['additionalDocuments']['prdDoc'] = {'url': prd_url, 'error': str(e)}

        # Fetch Slack thread if provided
        if slack_thread_url and slack_thread_url.strip():
            try:
                logging.info(f"Fetching Slack thread from: {slack_thread_url}")
                slack_result = load_slack_thread(slack_thread_url)
                additional_info['slackThread'] = {
                    'url': slack_thread_url,
                    'content': slack_result['content'],
                    'channel': slack_result.get('channel', '')
                }
                details['additionalDocuments']['slackThread'] = {'url': slack_thread_url, 'fetched': True}
                logging.info(f"Successfully fetched Slack thread")
            except Exception as e:
                logging.error(f"Error fetching Slack: {str(e)}")
                additional_info['slackThread'] = {'url': slack_thread_url, 'error': str(e)}
                details['additionalDocuments']['slackThread'] = {'url': slack_thread_url, 'error': str(e)}

        # Store meeting transcript if provided
        meeting_transcript = data.get('meetingTranscript', '')
        if meeting_transcript and meeting_transcript.strip():
            additional_info['meetingTranscript'] = {'content': meeting_transcript, 'title': 'Meeting Transcript'}
            details['additionalDocuments']['meetingTranscript'] = {'stored': True}
            logging.info(f"Stored meeting transcript")

        # Write updated files
        with open(details_path, 'w') as f:
            json.dump(details, f, indent=2)

        with open(additionalinfo_path, 'w') as f:
            json.dump(additional_info, f, indent=2)

        logging.info(f"Assessment {assessment_id} created successfully in storage")

        # Auto-trigger: if any document was fetched successfully, enqueue for processing
        if _has_any_successful_doc(details.get('additionalDocuments', {})):
            _enqueue_assessment(assessment_id)
            logging.info(f"[AUTO] Triggered auto-enqueue for {assessment_id}")

        return jsonify({
            "message": "Assessment created successfully",
            "assessment_id": assessment_id,
            "secreview_id": secreview_id,
            "storage_path": storage_dir
        }), 201

    except Exception as e:
        logging.error(f"Error creating assessment: {str(e)}")
        logging.exception("Full traceback:")
        return jsonify({"error": str(e)}), 500

@app.route('/api/queue/<secreview_id>', methods=['GET'])
def get_queue_item(secreview_id):
    """Get specific queue item"""
    try:
        queue_item = queue_handler.get_queue_item(secreview_id)
        
        if not queue_item:
            return jsonify({"error": "Queue item not found"}), 404
        
        return jsonify({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "data": queue_item
        })
        
    except Exception as e:
        logging.error(f"Error retrieving queue item: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/queue/<secreview_id>/status', methods=['PUT'])
def update_queue_status(secreview_id):
    """Update queue item status"""
    try:
        data = request.get_json()
        
        queue_item = queue_handler.update_queue_item_status(
            secreview_id,
            data.get('status'),
            threat_model_status=data.get('threat_model_status'),
            error_message=data.get('error_message')
        )
        
        return jsonify({
            "message": "Queue item status updated",
            "data": queue_item
        })
        
    except Exception as e:
        logging.error(f"Error updating queue status: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/queue/<secreview_id>', methods=['DELETE'])
def delete_queue_item(secreview_id):
    """Delete queue item"""
    try:
        success = queue_handler.delete_queue_item(secreview_id)
        
        if not success:
            return jsonify({"error": "Queue item not found"}), 404
        
        return jsonify({"message": "Queue item deleted successfully"})
        
    except Exception as e:
        logging.error(f"Error deleting queue item: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/cancel-assessment/<assessment_id>', methods=['POST'])
def cancel_assessment_route(assessment_id):
    """Cancel an assessment regardless of its current status (unless already cancelled)."""
    details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
    if not os.path.exists(details_path):
        return jsonify({"error": "Assessment not found"}), 404
    try:
        with open(details_path, 'r') as f:
            details = json.load(f)
        if details.get('status') == 'cancelled':
            return jsonify({"message": "Assessment already cancelled"})
        details['status'] = 'cancelled'
        details['error_message'] = 'Processing was cancelled by the user.'
        with open(details_path, 'w') as f:
            json.dump(details, f, indent=2)
        logging.info(f"Assessment {assessment_id} marked as cancelled by user")
        return jsonify({"message": "Assessment cancelled successfully"})
    except Exception as e:
        logging.error(f"Error cancelling assessment {assessment_id}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/retry-fetch-doc/<assessment_id>/<doc_type>', methods=['POST'])
def retry_fetch_doc(assessment_id, doc_type):
    """Re-fetch a single additional document (prdDoc, confluenceDoc, or slackThread) for an assessment."""
    if doc_type not in ('prdDoc', 'confluenceDoc', 'slackThread'):
        return jsonify({"error": "Invalid doc_type"}), 400

    details_path = os.path.join(_STORAGE_DIR, assessment_id, 'details.json')
    if not os.path.exists(details_path):
        return jsonify({"error": "Assessment not found"}), 404

    try:
        with open(details_path, 'r') as f:
            details = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Failed to read assessment: {str(e)}"}), 500

    queue_data = details.get('queue', {})

    if 'additionalDocuments' not in details:
        details['additionalDocuments'] = {"prdDoc": None, "confluenceDoc": None, "slackThread": None, "meetingTranscript": None}

    additionalinfo_path = os.path.join(_STORAGE_DIR, assessment_id, 'additionalinfo.json')
    if os.path.exists(additionalinfo_path):
        try:
            with open(additionalinfo_path, 'r') as f:
                additionalinfo = json.load(f)
        except Exception:
            additionalinfo = {"prdDoc": None, "confluenceDoc": None, "slackThread": None, "meetingTranscript": None}
    else:
        additionalinfo = {"prdDoc": None, "confluenceDoc": None, "slackThread": None, "meetingTranscript": None}

    # If a new URL is provided, update it in details AND additionalinfo immediately before fetching
    request_data = request.get_json(silent=True) or {}
    new_url = request_data.get('url', '').strip()
    if new_url:
        url_key = {'prdDoc': 'prd_url', 'slackThread': 'slack_thread', 'confluenceDoc': 'confluence_doc'}.get(doc_type)
        if url_key:
            if 'queue' not in details:
                details['queue'] = {}
            details['queue'][url_key] = new_url
            queue_data = details['queue']
            # Update URL in additionalinfo immediately (preserve existing content if any)
            existing = additionalinfo.get(doc_type)
            if existing and isinstance(existing, dict):
                existing['url'] = new_url
            else:
                additionalinfo[doc_type] = {'url': new_url}
            # Pre-save URL to both files so it persists even if the fetch crashes
            try:
                with open(details_path, 'w') as f:
                    json.dump(details, f, indent=2)
                with open(additionalinfo_path, 'w') as f:
                    json.dump(additionalinfo, f, indent=2)
                logging.info(f"Pre-saved URL update for {doc_type} on {assessment_id}: {new_url}")
            except Exception as pre_save_err:
                logging.warning(f"Pre-save URL failed: {pre_save_err}")

    if doc_type == 'prdDoc':
        url = queue_data.get('prd_url', '')
        if not url:
            return jsonify({"error": "No PRD URL configured for this assessment"}), 400
        try:
            content = None
            if 'docs.google.com' in url:
                from utils.google_docs_handler import GoogleDocsHandler
                gd_handler = GoogleDocsHandler()
                if gd_handler.is_configured():
                    gd_result = gd_handler.fetch_document_content(url)
                    if gd_result and gd_result.get('content'):
                        content = gd_result['content']
                if not content:
                    raise ValueError("Google Docs service account not configured or content fetch returned empty")
            else:
                prd_docs = load_confluence_documents(url)
                if prd_docs:
                    content = "\n\n".join([doc.page_content for doc in prd_docs])
            if content:
                additionalinfo['prdDoc'] = {'url': url, 'content': content, 'title': 'PRD Document'}
                details['additionalDocuments']['prdDoc'] = {'url': url, 'fetched': True}
            else:
                raise ValueError("No content returned from PRD source")
        except Exception as e:
            details['additionalDocuments']['prdDoc'] = {'url': url, 'error': str(e)}
            additionalinfo['prdDoc'] = {'url': url, 'error': str(e)}

    elif doc_type == 'confluenceDoc':
        url = queue_data.get('confluence_doc', '')
        if not url:
            return jsonify({"error": "No Confluence URL configured for this assessment"}), 400
        try:
            confluence_result = load_confluence_documents(url)
            if confluence_result:
                content = "\n\n".join([doc.page_content for doc in confluence_result])
                additionalinfo['confluenceDoc'] = {'url': url, 'content': content, 'title': 'Confluence Document'}
                details['additionalDocuments']['confluenceDoc'] = {'url': url, 'fetched': True}
            else:
                raise ValueError("No content returned from Confluence")
        except Exception as e:
            details['additionalDocuments']['confluenceDoc'] = {'url': url, 'error': str(e)}
            additionalinfo['confluenceDoc'] = {'url': url, 'error': str(e)}

    elif doc_type == 'slackThread':
        url = queue_data.get('slack_thread', '')
        if not url:
            return jsonify({"error": "No Slack thread URL configured for this assessment"}), 400
        try:
            slack_result = load_slack_thread(url)
            additionalinfo['slackThread'] = {
                'url': url,
                'content': slack_result['content'],
                'channel': slack_result.get('channel', '')
            }
            details['additionalDocuments']['slackThread'] = {'url': url, 'fetched': True}
        except Exception as e:
            details['additionalDocuments']['slackThread'] = {'url': url, 'error': str(e)}
            additionalinfo['slackThread'] = {'url': url, 'error': str(e)}

    try:
        with open(details_path, 'w') as f:
            json.dump(details, f, indent=2)
        with open(additionalinfo_path, 'w') as f:
            json.dump(additionalinfo, f, indent=2)
    except Exception as e:
        return jsonify({"error": f"Failed to save: {str(e)}"}), 500

    logging.info(f"Retry fetch for {doc_type} on assessment {assessment_id} completed")

    # Auto-trigger: if this retry succeeded and assessment is still pending/failed, enqueue
    doc_result = details.get('additionalDocuments', {}).get(doc_type, {})
    enqueued = False
    if doc_result and not doc_result.get('error') and details.get('status') in ('pending', 'failed'):
        _enqueue_assessment(assessment_id)
        enqueued = True
        logging.info(f"[AUTO] Retry success — enqueued {assessment_id}")

    return jsonify({
        "success": True,
        "additionalDocuments": details.get('additionalDocuments', {}),
        "prd_url": details.get('queue', {}).get('prd_url', ''),
        "slack_thread": details.get('queue', {}).get('slack_thread', ''),
        "status": "queued" if enqueued else details.get('status'),
    })


@app.route('/api/nudge-queued', methods=['POST'])
def nudge_queued_assessments():
    """Re-enqueue any assessments currently stuck in 'queued' state."""
    count = 0
    storage_dir = _STORAGE_DIR
    if os.path.exists(storage_dir):
        for entry in os.listdir(storage_dir):
            details_path = os.path.join(storage_dir, entry, 'details.json')
            if not os.path.exists(details_path):
                continue
            try:
                with open(details_path, 'r') as f:
                    d = json.load(f)
                if d.get('status') == 'queued':
                    # Put directly into queue (status is already 'queued', skip _enqueue_assessment guard)
                    # Only add if not already being processed
                    if not any(True for t in threading.enumerate() if t.name.startswith(f"pipeline-{entry[:8]}")):
                        _auto_trigger_queue.put(entry)
                        count += 1
                        logging.info(f"[NUDGE] Re-enqueued {entry}")
            except Exception:
                pass
    return jsonify({"nudged": count})


@app.route('/api/storage-queue-items', methods=['GET'])
def get_storage_queue_items():
    """Get queue items from storage directory"""
    try:
        queue_items = []
        storage_dir = _STORAGE_DIR
        
        # List all directories in storage
        if not os.path.exists(storage_dir):
            return jsonify({"items": []})
        
        for assessment_dir in os.listdir(storage_dir):
            assessment_path = os.path.join(storage_dir, assessment_dir)
            
            # Skip if not a directory
            if not os.path.isdir(assessment_path):
                continue
            
            # Check if details.json exists
            details_path = os.path.join(assessment_path, 'details.json')
            if not os.path.exists(details_path):
                continue
            
            try:
                with open(details_path, 'r') as f:
                    details = json.load(f)
                
                # Filter for items with source: "queue"
                if details.get('source') != 'queue':
                    continue
                
                # Read queue-specific fields: prefer nested queue object, fall back to top-level
                queue_data = details.get('queue', {})
                secreview_id = queue_data.get('secreview_id') or details.get('projectName', assessment_dir[:8])
                initiated_by = queue_data.get('initiated_by') or 'Queue System'
                service_name = queue_data.get('service_name') or details.get('projectName', 'Unknown')
                department = queue_data.get('department') or details.get('department', '')
                prd_url = queue_data.get('prd_url', '')
                slack_thread_val = queue_data.get('slack_thread', '')

                # Convert storage item to QueueItem format
                queue_item = {
                    "id": assessment_dir,
                    "secreview_id": secreview_id,
                    "assessment_id": assessment_dir,
                    "initiated_by": initiated_by,
                    "prd_url": prd_url,
                    "service_name": service_name,
                    "slack_thread": slack_thread_val,
                    "department": department,
                    "created_at": details.get('timestamp', datetime.datetime.now(datetime.timezone.utc).isoformat()),
                    "status": details.get('status', 'pending'),
                    "current_step": details.get('current_step', None),
                    "threat_model_status": None,
                    "error_message": details.get('error_message', None),
                    "additional_data": {
                        "projectName": details.get('projectName', ''),
                        "description": details.get('description', ''),
                        "department": department,
                        "app_type": queue_data.get('app_type') or details.get('applicationType', ''),
                        "sensitivity_level": queue_data.get('sensitivity_level') or details.get('dataSensitivityLevel', ''),
                        "internet_facing": queue_data.get('internet_facing', 'No'),
                        "authentication": queue_data.get('authentication', []),
                        "sensitive_data": queue_data.get('sensitive_data', ''),
                        "custom_prompt": queue_data.get('custom_prompt', ''),
                        "methodology": queue_data.get('methodology') or details.get('threatModelingMethodology', 'STRIDE'),
                        "confluence_doc": queue_data.get('confluence_doc') or details.get('confluenceUrl', ''),
                        "department": department,
                        "applicationType": queue_data.get('app_type') or details.get('applicationType', ''),
                        "dataSensitivityLevel": queue_data.get('sensitivity_level') or details.get('dataSensitivityLevel', ''),
                        "isInternetFacing": details.get('isInternetFacing', False),
                        "authenticationMethod": details.get('authenticationMethod', ''),
                        "threatModelingMethodology": queue_data.get('methodology') or details.get('threatModelingMethodology', 'STRIDE'),
                        "additionalDocuments": details.get('additionalDocuments', {})
                    }
                }
                
                queue_items.append(queue_item)
                # logging.info(f"Added queue item from storage: {assessment_dir}")
                
            except json.JSONDecodeError as e:
                logging.error(f"Error reading details.json from {assessment_dir}: {str(e)}")
                continue
            except Exception as e:
                logging.error(f"Error processing assessment {assessment_dir}: {str(e)}")
                continue
        
        return jsonify({
            "items": queue_items,
            "count": len(queue_items)
        })
        
    except Exception as e:
        logging.error(f"Error retrieving queue items from storage: {str(e)}")
        return jsonify({
            "error": str(e),
            "items": []
        }), 500

@app.route('/api/threat-model/status', methods=['POST'])
def get_threat_model_status():
    """
    Fetch the status and summary of a threat model assessment by sec_review_id.
    Accepts JSON body: { "secreview_id": "SEC-2025-001" }
    Also accepts { "assessment_id": "<uuid>" } as an alternative lookup key.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400

        sec_review_id = data.get('secreview_id')
        assessment_id_param = data.get('assessment_id')

        if not sec_review_id and not assessment_id_param:
            return jsonify({"error": "Either secreview_id or assessment_id is required"}), 400

        # ── Locate the assessment ────────────────────────────────────────────
        found_assessment_id = None
        found_details = None

        storage_dir = _STORAGE_DIR
        if not os.path.exists(storage_dir):
            return jsonify({"error": "Storage directory not found"}), 500

        for entry in os.listdir(storage_dir):
            details_path = os.path.join(storage_dir, entry, 'details.json')
            if not os.path.exists(details_path):
                continue
            try:
                with open(details_path, 'r') as f:
                    details = json.load(f)

                # Match by assessment_id directly
                if assessment_id_param and entry == assessment_id_param:
                    found_assessment_id = entry
                    found_details = details
                    break

                # Match by sec_review_id inside queue metadata
                if sec_review_id:
                    queue_meta = details.get('queue') or {}
                    if queue_meta.get('secreview_id') == sec_review_id:
                        found_assessment_id = entry
                        found_details = details
                        break
            except Exception:
                continue

        if not found_assessment_id:
            lookup_val = sec_review_id or assessment_id_param
            return jsonify({"error": f"Assessment not found for identifier: {lookup_val}"}), 404

        # ── Activities completed ─────────────────────────────────────────────
        def _has_result(filename):
            path = os.path.join(storage_dir, found_assessment_id, f'{filename}.json')
            if not os.path.exists(path):
                return False
            try:
                with open(path, 'r') as f:
                    obj = json.load(f)
                result = obj.get('result')
                if not result:
                    return False
                # For dicts check non-empty; for strings check non-blank
                if isinstance(result, dict):
                    return bool(result)
                if isinstance(result, str):
                    return bool(result.strip())
                return True
            except Exception:
                return False

        activities_completed = {
            "threat_model": _has_result('threat_model'),
            "dread":        _has_result('dread_assessment'),
            "mitigations":  _has_result('mitigation'),
            "attack_tree":  _has_result('attack_tree'),
            "test_cases":   _has_result('test_cases'),
        }

        # ── DREAD stats ──────────────────────────────────────────────────────
        average_dread_score = None
        high_issues_count = 0
        HIGH_DREAD_THRESHOLD = 8.0

        dread_path = os.path.join(storage_dir, found_assessment_id, 'dread_assessment.json')
        if os.path.exists(dread_path):
            try:
                with open(dread_path, 'r') as f:
                    dread_data = json.load(f)
                risk_items = (
                    dread_data.get('result', {})
                              .get('raw_response', {})
                              .get('Risk Assessment', [])
                )
                if risk_items:
                    dread_fields = ['Damage Potential', 'Reproducibility', 'Exploitability',
                                    'Affected Users', 'Discoverability']
                    per_threat_averages = []
                    for item in risk_items:
                        scores = [item.get(f, 0) for f in dread_fields]
                        scores = [s for s in scores if isinstance(s, (int, float))]
                        if scores:
                            threat_avg = sum(scores) / len(scores)
                            per_threat_averages.append(threat_avg)
                            if threat_avg >= HIGH_DREAD_THRESHOLD:
                                high_issues_count += 1
                    if per_threat_averages:
                        average_dread_score = round(
                            sum(per_threat_averages) / len(per_threat_averages), 2
                        )
            except Exception as e:
                logging.warning(f"Could not parse DREAD data for {found_assessment_id}: {e}")

        # ── ASVS test case stats ─────────────────────────────────────────────
        asvs_test_cases_count = 0
        validated_test_cases_count = 0

        tc_path = os.path.join(storage_dir, found_assessment_id, 'test_cases.json')
        if os.path.exists(tc_path):
            try:
                with open(tc_path, 'r') as f:
                    tc_data = json.load(f)
                threat_entries = tc_data.get('result', {}).get('test_cases', [])
                for entry in threat_entries:
                    # Skip error placeholder entries (legacy or from failed batches)
                    if entry.get('asvs_requirement') == 'Error':
                        continue
                    asvs_test_cases_count += 1
                    if entry.get('validated') is True:
                        validated_test_cases_count += 1
            except Exception as e:
                logging.warning(f"Could not parse test cases for {found_assessment_id}: {e}")

        all_checks_passed = (
            asvs_test_cases_count > 0
            and validated_test_cases_count == asvs_test_cases_count
        )

        # ── Validation message ───────────────────────────────────────────────
        current_status = found_details.get('status', 'unknown')

        # Check whether any additional document was successfully fetched
        additional_docs = found_details.get('additionalDocuments') or {}
        has_fetched_doc = any(
            isinstance(doc, dict) and doc.get('fetched') is True
            for doc in additional_docs.values()
            if doc
        )

        if current_status == 'pending' and not has_fetched_doc:
            validation_message = "Document fetch failed. Trigger manually."
            validation_status = "error"
        elif current_status == 'cancelled':
            validation_message = "Cancelled by user."
            validation_status = "cancelled"
        elif current_status == 'queued':
            validation_message = "It is currently in queue."
            validation_status = "queued"
        elif current_status == 'failed':
            validation_message = "Threat model generation failed, please retry."
            validation_status = "error"
        elif current_status == 'processing':
            validation_message = "Threat modeling in progress."
            validation_status = "processing"
        elif current_status == 'completed' and asvs_test_cases_count == 0:
            validation_message = "Test cases not generated and validated."
            validation_status = "warning"
        elif current_status == 'completed' and asvs_test_cases_count > 0 and validated_test_cases_count < asvs_test_cases_count:
            validation_message = f"All test cases are required to be validated ({validated_test_cases_count}/{asvs_test_cases_count} validated)."
            validation_status = "warning"
        elif all_checks_passed:
            validation_message = "Threat model validation successful."
            validation_status = "success"
        else:
            validation_message = None
            validation_status = None

        # ── Build response ───────────────────────────────────────────────────
        queue_meta = found_details.get('queue') or {}
        resolved_sec_review_id = queue_meta.get('secreview_id') or sec_review_id or None
        project_name = (
            found_details.get('projectName')
            or queue_meta.get('service_name')
            or 'Unknown'
        )

        return jsonify({
            "assessment_id": found_assessment_id,
            "project_name": project_name,
            "sec_review_id": resolved_sec_review_id,
            "status": current_status,
            "activities_completed": activities_completed,
            "average_dread_score": average_dread_score,
            "high_issues_count": high_issues_count,
            "asvs_test_cases_count": asvs_test_cases_count,
            "validated_test_cases_count": validated_test_cases_count,
            "all_checks_passed": all_checks_passed,
            "validation_status": validation_status,
            "validation_message": validation_message,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })

    except Exception as e:
        logging.error(f"Error in get_threat_model_status: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ─── Feedback endpoints ───────────────────────────────────────────────────────

@app.route('/api/feedback', methods=['GET'])
def list_feedbacks():
    """
    List feedback entries for the authenticated user.
    On every call:
    - Backfills entries for completed assessments that pre-date the feature.
    - Corrects assessment_name on existing entries to always reflect
      projectName from details.json.
    No Slack DM is sent for backfilled entries.
    """
    user = _get_request_user()
    user_email = user.get('email', '') if user else ''

    with _feedback_lock:
        store = _load_feedback_store()
        dirty = False

        # Build a map of assessment_id -> store index for quick lookup
        id_to_idx = {e['assessment_id']: i for i, e in enumerate(store)}

        storage_dir = _STORAGE_DIR
        if os.path.exists(storage_dir):
            for entry_dir in os.listdir(storage_dir):
                details_path = os.path.join(storage_dir, entry_dir, 'details.json')
                if not os.path.exists(details_path):
                    continue
                try:
                    with open(details_path, 'r') as f:
                        details = json.load(f)
                except Exception:
                    continue

                if details.get('status') != 'completed':
                    continue

                queue_data = details.get('queue') or {}
                owner = queue_data.get('initiated_by') or details.get('created_by') or ''
                # Always use projectName as the canonical name
                canonical_name = details.get('projectName') or queue_data.get('service_name') or entry_dir
                canonical_methodology = details.get('threatModelingMethodology', '')
                canonical_department = details.get('department', '')

                if entry_dir in id_to_idx:
                    # Entry exists — correct any drifted fields
                    idx = id_to_idx[entry_dir]
                    if store[idx].get('assessment_name') != canonical_name:
                        store[idx]['assessment_name'] = canonical_name
                        dirty = True
                    if store[idx].get('threat_modeling_methodology') != canonical_methodology:
                        store[idx]['threat_modeling_methodology'] = canonical_methodology
                        dirty = True
                    if store[idx].get('department') != canonical_department:
                        store[idx]['department'] = canonical_department
                        dirty = True
                else:
                    # New entry — only create for the currently authenticated user
                    if owner != user_email:
                        continue
                    feedback_uuid = str(uuid.uuid4())
                    new_entry = {
                        "uuid": feedback_uuid,
                        "assessment_id": entry_dir,
                        "assessment_name": canonical_name,
                        "created_for": owner,
                        "created_at": details.get('timestamp', datetime.datetime.utcnow().isoformat()),
                        "threat_modeling_methodology": canonical_methodology,
                        "department": canonical_department,
                        "submitted": False,
                        "submitted_at": None,
                        "answers": {}
                    }
                    store.append(new_entry)
                    id_to_idx[entry_dir] = len(store) - 1
                    dirty = True
                    logging.info(f"[FEEDBACK] Backfilled feedback entry {feedback_uuid} for {entry_dir}")

        if dirty:
            _save_feedback_store(store)

    user_feedbacks = [e for e in store if e.get('created_for', '') == user_email]
    return jsonify({"feedbacks": user_feedbacks})


@app.route('/api/admin/feedback', methods=['GET'])
def admin_list_feedbacks():
    """Return all feedback entries across all users. Requires MCP admin access."""
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden"}), 403
    with _feedback_lock:
        store = _load_feedback_store()
    return jsonify({"feedbacks": store})


@app.route('/api/admin/logs', methods=['GET'])
def admin_list_logs():
    """List all assessments that have a logs.json file, with summary metadata."""
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden"}), 403

    storage_dir = _STORAGE_DIR
    result = []
    if not os.path.exists(storage_dir):
        return jsonify({"assessments": []})

    for assessment_id in os.listdir(storage_dir):
        assessment_dir = os.path.join(storage_dir, assessment_id)
        if not os.path.isdir(assessment_dir):
            continue
        details_path = os.path.join(assessment_dir, 'details.json')
        logs_path = os.path.join(assessment_dir, 'logs.json')

        details = {}
        if os.path.exists(details_path):
            try:
                with open(details_path, 'r') as f:
                    details = json.load(f)
            except Exception:
                pass

        has_logs = os.path.exists(logs_path)
        log_count = 0
        has_errors = False
        if has_logs:
            try:
                with open(logs_path, 'r') as f:
                    log_data = json.load(f)
                log_count = len(log_data.get('logs', []))
                has_errors = any(e.get('level') == 'ERROR' for e in log_data.get('logs', []))
            except Exception:
                pass

        result.append({
            "assessment_id": assessment_id,
            "name": details.get('projectName', f"Assessment {assessment_id[:8]}"),
            "status": details.get('status', 'unknown'),
            "current_step": details.get('current_step', ''),
            "timestamp": details.get('timestamp', ''),
            "department": details.get('department', ''),
            "has_logs": has_logs,
            "log_count": log_count,
            "has_errors": has_errors,
            "error_message": details.get('error_message', ''),
        })

    result.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify({"assessments": result})


@app.route('/api/admin/logs/<assessment_id>', methods=['GET'])
def admin_get_logs(assessment_id):
    """Return full logs.json for a specific assessment."""
    if not _is_mcp_admin():
        return jsonify({"error": "Forbidden"}), 403

    # Sanitize assessment_id — must be a valid UUID-like path component
    import re
    if not re.match(r'^[a-zA-Z0-9_-]+$', assessment_id):
        return jsonify({"error": "Invalid assessment_id"}), 400

    logs_data = storage_handler.get_logs(assessment_id)
    if logs_data is None:
        logs_data = {"assessment_id": assessment_id, "logs": []}

    # Also include current details for status context
    details = storage_handler.get_details_info(assessment_id) or {}
    return jsonify({
        "assessment_id": assessment_id,
        "name": details.get('projectName', f"Assessment {assessment_id[:8]}"),
        "status": details.get('status', 'unknown'),
        "current_step": details.get('current_step', ''),
        "error_message": details.get('error_message', ''),
        "logs": logs_data.get('logs', []),
    })


@app.route('/api/feedback/<feedback_uuid>', methods=['GET'])
def get_feedback(feedback_uuid):
    """
    Get a single feedback entry by UUID.
    This endpoint is intentionally unauthenticated so the Slack DM link works
    without requiring the recipient to be logged in.
    """
    with _feedback_lock:
        store = _load_feedback_store()
    entry = next((e for e in store if e['uuid'] == feedback_uuid), None)
    if not entry:
        return jsonify({"error": "Feedback not found"}), 404
    return jsonify({"feedback": entry})


@app.route('/api/feedback/<feedback_uuid>/submit', methods=['POST'])
def submit_feedback(feedback_uuid):
    """
    Submit answers for a feedback entry.
    Once submitted the entry is locked — re-submissions are rejected.
    No authentication required (same rationale as the GET endpoint).
    """
    data = request.get_json() or {}
    answers = data.get('answers')
    if not answers or not isinstance(answers, dict):
        return jsonify({"error": "answers object is required"}), 400

    with _feedback_lock:
        store = _load_feedback_store()
        idx = next((i for i, e in enumerate(store) if e['uuid'] == feedback_uuid), None)
        if idx is None:
            return jsonify({"error": "Feedback not found"}), 404
        if store[idx].get('submitted'):
            return jsonify({"error": "Feedback has already been submitted and cannot be edited"}), 409
        store[idx]['submitted'] = True
        store[idx]['submitted_at'] = datetime.datetime.utcnow().isoformat()
        store[idx]['answers'] = answers
        _save_feedback_store(store)
        entry = store[idx]

    logging.info(f"[FEEDBACK] Submitted feedback {feedback_uuid} for assessment {entry.get('assessment_id')}")
    return jsonify({"message": "Thank you for your feedback!", "feedback": entry})


def _recover_stuck_assessments():
    """
    On startup, mark any assessments that are still in 'processing' status as failed.
    This handles the case where the server was restarted mid-pipeline.
    """
    storage_dir = _STORAGE_DIR
    if not os.path.exists(storage_dir):
        return
    recovered = 0
    for entry in os.listdir(storage_dir):
        details_path = os.path.join(storage_dir, entry, 'details.json')
        if not os.path.exists(details_path):
            continue
        try:
            with open(details_path, 'r') as f:
                details = json.load(f)
            if details.get('status') == 'processing':
                stuck_step = details.get('current_step', 'unknown')
                details['status'] = 'failed'
                details['error_message'] = (
                    f"Processing was interrupted by a server restart "
                    f"(was stuck at step: {stuck_step}). Please re-trigger the threat model."
                )
                with open(details_path, 'w') as f:
                    json.dump(details, f, indent=2)
                logging.warning(f"[STARTUP] Marked stuck assessment {entry} as failed (was at step: {stuck_step})")
                recovered += 1
            elif details.get('status') == 'queued':
                # Re-enqueue assessments that were waiting when the server restarted
                _auto_trigger_queue.put(entry)
                logging.info(f"[STARTUP] Re-enqueued assessment {entry} (was queued before restart)")
                recovered += 1
        except Exception as e:
            logging.error(f"[STARTUP] Could not recover assessment {entry}: {e}")
    if recovered:
        logging.info(f"[STARTUP] Recovered {recovered} stuck assessment(s) → marked as failed")


_worker_thread = threading.Thread(target=_auto_trigger_worker, daemon=True, name="auto-trigger-worker")
_worker_thread.start()
_recover_stuck_assessments()


def _initialize_settings_from_env():
    """
    One-time migration: seed settings.json with values from .env if not already present.
    Runs at startup so the app immediately reads all config from settings.json.
    API keys are never written here — only method, model, endpoint, and admin list.
    """
    try:
        from utils.config import _get_settings, _save_settings as _cfg_save

        settings = _get_settings()
        changed = False

        # ── LLM config ──────────────────────────────────────────────────────────
        if 'llmConfig' not in settings:
            llm_method = os.getenv('LLM_METHOD', 'OPENAI')
            if llm_method == 'BEDROCK':
                llm_cfg = {
                    'method': 'BEDROCK',
                    'model': os.getenv('BEDROCK_MODEL', 'claude-3.7-sonnet'),
                    'large_output_model': (
                        os.getenv('BEDROCK_LARGE_OUTPUT_MODEL')
                        or os.getenv('BEDROCK_MODEL', 'claude-3.7-sonnet')
                    ),
                    'base_url': os.getenv('BEDROCK_BASE_URL', ''),
                }
            else:
                llm_cfg = {
                    'method': 'OPENAI',
                    'model': 'gpt-4o',
                    'large_output_model': 'gpt-4o',
                    'base_url': '',
                }
            settings['llmConfig'] = llm_cfg
            changed = True
            logging.info(f"[STARTUP] Seeded llmConfig in settings.json from .env (method={llm_cfg['method']})")

        # ── Admin list ───────────────────────────────────────────────────────────
        if 'admins' not in settings:
            raw = os.getenv('MCP_ADMINS', '')
            env_admins = [e.strip().lower() for e in raw.split(',') if e.strip()]
            settings['admins'] = env_admins
            changed = True
            logging.info(f"[STARTUP] Seeded {len(env_admins)} admin(s) in settings.json from MCP_ADMINS env var")

        if changed:
            _cfg_save(settings)

    except Exception as e:
        logging.error(f"[STARTUP] Failed to initialize settings from env: {e}")


_CUSTOM_THREAT_MODELS_DIR = os.path.join(_STORAGE_DIR, 'data', 'custom-threat-models')


def _custom_model_path(custom_id: str) -> str:
    return os.path.join(_CUSTOM_THREAT_MODELS_DIR, f'{custom_id}.json')


def _load_custom_model(custom_id: str) -> dict | None:
    path = _custom_model_path(custom_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def _save_custom_model(record: dict):
    os.makedirs(_CUSTOM_THREAT_MODELS_DIR, exist_ok=True)
    with open(_custom_model_path(record['id']), 'w') as f:
        json.dump(record, f, indent=2)


@app.route('/api/custom-threat-models', methods=['GET'])
def list_custom_threat_models():
    user = _get_request_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    records = []
    if os.path.isdir(_CUSTOM_THREAT_MODELS_DIR):
        for fname in os.listdir(_CUSTOM_THREAT_MODELS_DIR):
            if fname.endswith('.json'):
                rec = _load_custom_model(fname[:-5])
                if rec:
                    records.append(rec)
    records.sort(key=lambda r: r.get('created_at', ''), reverse=True)
    return jsonify({'records': records})


@app.route('/api/custom-threat-models', methods=['POST'])
def create_custom_threat_model():
    user = _get_request_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    body = request.get_json(silent=True) or {}
    assessment_ids = body.get('assessment_ids', [])
    name = body.get('name', 'Custom Analysis')
    if not assessment_ids:
        return jsonify({'error': 'assessment_ids required'}), 400
    custom_id = str(uuid.uuid4())
    record = {
        'id': custom_id,
        'name': name,
        'assessment_ids': assessment_ids,
        'created_by': user.get('email', ''),
        'created_at': datetime.datetime.utcnow().isoformat(),
    }
    _save_custom_model(record)
    return jsonify({'id': custom_id, 'record': record}), 201


@app.route('/api/custom-threat-models/<custom_id>', methods=['GET'])
def get_custom_threat_model(custom_id):
    user = _get_request_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    record = _load_custom_model(custom_id)
    if not record:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(record)


@app.route('/api/custom-threat-models/<custom_id>', methods=['DELETE'])
def delete_custom_threat_model(custom_id):
    user = _get_request_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if not _is_mcp_admin():
        return jsonify({'error': 'Forbidden'}), 403
    path = _custom_model_path(custom_id)
    if not os.path.exists(path):
        return jsonify({'error': 'Not found'}), 404
    os.remove(path)
    return jsonify({'deleted': custom_id})


_initialize_settings_from_env()


# ── AI DAST Verification ───────────────────────────────────────────────────────

def _ai_dast_mock_worker(assessment_id: str, storage: StorageHandler):
    """Background thread that simulates an async AI DAST tool call.

    In production, replace this with a real HTTP call to the external tool.
    Polls/waits for the tool to return results, then writes them to storage.
    """
    import random
    try:
        time.sleep(6)  # Simulate async processing delay

        record = storage.get_ai_dast_validation(assessment_id)
        if not record:
            return

        test_cases = record.get('request_payload', {}).get('test_cases', [])
        verdicts = ['not_vulnerable', 'needs_human_verification', 'vulnerable']
        mock_reasons = {
            'not_vulnerable': [
                'No exploitable path found during automated testing. Input validation and authentication controls are in place.',
                'Security controls are properly implemented. No attack vector identified.',
                'Tested against known attack patterns — all blocked by existing defenses.',
            ],
            'needs_human_verification': [
                'Potential indirect injection vector detected. Manual review recommended to confirm exploitability.',
                'Edge case in access control logic — automated test inconclusive. Requires manual verification.',
                'Suspicious response pattern observed. Confidence insufficient for automated verdict.',
            ],
            'vulnerable': [
                'Exploitable vulnerability confirmed. Insufficient input sanitization allows injection.',
                'Authentication bypass possible under specific conditions. Immediate remediation required.',
                'Sensitive data exposed in API response without proper authorization checks.',
            ],
        }

        results = []
        for tc in test_cases:
            verdict = random.choices(
                verdicts,
                weights=[0.55, 0.25, 0.20],
                k=1
            )[0]
            confidence = round(random.uniform(0.70, 0.99), 2)
            reason = random.choice(mock_reasons[verdict])
            results.append({
                'scenario': tc.get('scenario', ''),
                'threat_type': tc.get('threat_type', ''),
                'verdict': verdict,
                'confidence_score': confidence,
                'reason': reason,
            })

        record['status'] = 'completed'
        record['completed_at'] = datetime.datetime.utcnow().isoformat()
        record['results'] = results
        storage.save_ai_dast_validation(assessment_id, record)
        logging.info(f'[AI-DAST] Mock worker completed for assessment {assessment_id}: {len(results)} results')

    except Exception as e:
        logging.error(f'[AI-DAST] Mock worker error for {assessment_id}: {e}')
        try:
            record = storage.get_ai_dast_validation(assessment_id) or {}
            record['status'] = 'failed'
            record['error'] = str(e)
            storage.save_ai_dast_validation(assessment_id, record)
        except Exception:
            pass


@app.route('/api/ai-dast/start', methods=['POST'])
def ai_dast_start():
    """Start an AI DAST verification job for a given assessment."""
    user = _get_request_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    assessment_id = request.args.get('assessment_id')
    if not assessment_id:
        return jsonify({'error': 'assessment_id is required'}), 400

    storage = StorageHandler(_STORAGE_DIR)
    test_cases_data = storage.get_test_cases(assessment_id)
    if not test_cases_data:
        return jsonify({'error': 'No test cases found for this assessment'}), 404

    raw_tcs = test_cases_data.get('result', {}).get('test_cases', [])
    payload_tcs = [
        {
            'scenario': tc.get('Scenario', tc.get('scenario', '')),
            'threat_type': tc.get('Threat Type', tc.get('threat_type', '')),
            'asvs_requirement': tc.get('asvs_requirement', ''),
            'test_cases': tc.get('test_cases', tc.get('test_case', [])),
        }
        for tc in raw_tcs
        if not tc.get('skipped')
    ]

    job_id = str(uuid.uuid4())
    record = {
        'assessment_id': assessment_id,
        'job_id': job_id,
        'status': 'running',
        'started_at': datetime.datetime.utcnow().isoformat(),
        'completed_at': None,
        'request_payload': {'test_cases': payload_tcs},
        'results': [],
    }
    storage.save_ai_dast_validation(assessment_id, record)
    logging.info(f'[AI-DAST] Started job {job_id} for assessment {assessment_id} with {len(payload_tcs)} test cases')

    t = threading.Thread(target=_ai_dast_mock_worker, args=(assessment_id, storage), daemon=True)
    t.start()

    return jsonify({'job_id': job_id, 'status': 'running'})


@app.route('/api/ai-dast/status', methods=['GET'])
def ai_dast_status():
    """Poll the status of an AI DAST verification job."""
    user = _get_request_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    assessment_id = request.args.get('assessment_id')
    if not assessment_id:
        return jsonify({'error': 'assessment_id is required'}), 400

    storage = StorageHandler(_STORAGE_DIR)
    record = storage.get_ai_dast_validation(assessment_id)
    if not record:
        return jsonify({'status': 'idle'})

    return jsonify({
        'status': record.get('status', 'idle'),
        'job_id': record.get('job_id'),
        'started_at': record.get('started_at'),
        'completed_at': record.get('completed_at'),
        'results': record.get('results', []),
    })


@app.route('/api/ai-dast/submit', methods=['POST'])
def ai_dast_submit():
    """Submit AI DAST validation results — marks test cases as validated in test_cases.json."""
    user = _get_request_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    assessment_id = request.args.get('assessment_id')
    if not assessment_id:
        return jsonify({'error': 'assessment_id is required'}), 400

    body = request.get_json(silent=True) or {}
    validations = body.get('validations', [])
    if not validations:
        return jsonify({'error': 'validations array is required'}), 400

    storage = StorageHandler(_STORAGE_DIR)
    test_cases_data = storage.get_test_cases(assessment_id)
    if not test_cases_data:
        return jsonify({'error': 'No test cases found for this assessment'}), 404

    validation_map = {
        (v.get('scenario', '').strip(), v.get('threat_type', '').strip()): v
        for v in validations
    }

    updated_count = 0
    raw_tcs = test_cases_data.get('result', {}).get('test_cases', [])
    for tc in raw_tcs:
        scenario = tc.get('Scenario', tc.get('scenario', '')).strip()
        threat = tc.get('Threat Type', tc.get('threat_type', '')).strip()
        key = (scenario, threat)
        val = validation_map.get(key) or validation_map.get((scenario, ''))
        if val:
            tc['validated'] = val.get('validated', True)
            tc['validated_using_ai'] = True
            tc['reason'] = val.get('reason', '')
            tc['ai_dast_verdict'] = val.get('verdict', '')
            tc['ai_dast_confidence'] = val.get('confidence_score', None)
            for sub_tc in tc.get('test_cases', tc.get('test_case', [])):
                sub_tc['validated'] = val.get('validated', True)
                sub_tc['validated_using_ai'] = True
                sub_tc['reason'] = val.get('reason', '')
            updated_count += 1

    storage.save_test_cases(assessment_id, test_cases_data.get('result', {}))
    logging.info(f'[AI-DAST] Submit: updated {updated_count} test cases for assessment {assessment_id}')
    return jsonify({'updated_count': updated_count, 'message': 'Validations submitted successfully'})


@app.route('/api/tmbom', methods=['GET'])
def get_tmbom():
    user = _get_request_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    assessment_id = request.args.get('assessment_id')
    if not assessment_id:
        return jsonify({"error": "Assessment ID is required"}), 400
    if not storage_handler.get_details_info(assessment_id):
        return jsonify({"error": f"Assessment {assessment_id} not found"}), 404
    tmbom = storage_handler.get_tmbom(assessment_id)
    if not tmbom:
        return jsonify({"error": "TM-BOM not yet generated", "not_generated": True}), 404
    return jsonify(tmbom)


@app.route('/api/tmbom/generate', methods=['POST'])
def generate_tmbom():
    user = _get_request_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    assessment_id = request.args.get('assessment_id')
    if not assessment_id:
        return jsonify({"error": "Assessment ID is required"}), 400
    if not storage_handler.get_details_info(assessment_id):
        return jsonify({"error": f"Assessment {assessment_id} not found"}), 404
    if not storage_handler.get_threat_model(assessment_id):
        return jsonify({"error": "Threat model not found — run assessment pipeline first"}), 404
    try:
        from core.tmbom import TmBomGenerator
        tmbom = TmBomGenerator().generate(assessment_id, storage_handler)
        storage_handler.save_tmbom(assessment_id, tmbom)
    except Exception as e:
        logging.error(f"TM-BOM generation error for {assessment_id}: {e}")
        return jsonify({"error": f"Failed to generate TM-BOM: {str(e)}"}), 500
    return jsonify(tmbom)


@app.route('/api/tmbom/download', methods=['GET'])
def download_tmbom():
    """Always regenerates so all three download locations serve fresh data."""
    user = _get_request_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    assessment_id = request.args.get('assessment_id')
    if not assessment_id:
        return jsonify({"error": "Assessment ID is required"}), 400
    if not storage_handler.get_details_info(assessment_id):
        return jsonify({"error": f"Assessment {assessment_id} not found"}), 404
    if not storage_handler.get_threat_model(assessment_id):
        return jsonify({"error": "Threat model not found — run assessment pipeline first"}), 404
    try:
        from core.tmbom import TmBomGenerator
        tmbom = TmBomGenerator().generate(assessment_id, storage_handler)
        storage_handler.save_tmbom(assessment_id, tmbom)
    except Exception as e:
        logging.error(f"TM-BOM generation error for {assessment_id}: {e}")
        return jsonify({"error": f"Failed to generate TM-BOM: {str(e)}"}), 500
    return Response(
        json.dumps(tmbom, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=tmbom-{assessment_id}.json'}
    )


if __name__ == "__main__":
    deployment_type = os.environ.get('REACT_APP_DEPLOYMENT_TYPE', 'dev')
    if deployment_type != 'dev':
        os.execvp('gunicorn', ['gunicorn', '-w', '4', '-b', '0.0.0.0:5001', '--timeout', '300', 'app:app'])
    else:
        app.run(debug=True, host='127.0.0.1', port=5001, use_reloader=False)
