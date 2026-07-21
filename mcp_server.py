"""
ThreatShield MCP Server

Exposes ThreatShield security analysis capabilities to any MCP-compatible client
(Claude Desktop, Claude Code, custom agents, etc.) via HTTP/SSE transport.

Usage:
    python mcp_server.py

Environment variables:
    THREATSHIELD_BACKEND_URL   Flask backend URL (default: http://localhost:5001)
    MCP_HOST                   Host to bind (default: 0.0.0.0)
    MCP_PORT                   Port to listen on (default: 8765)
"""

import os
import base64
import json
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

BACKEND = os.environ.get("THREATSHIELD_BACKEND_URL", "http://localhost:5001")
MCP_HOST = os.environ.get("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.environ.get("MCP_PORT", "8765"))

# Disable DNS rebinding protection so external hostnames (prod domain) are accepted.
# The MCP server is intended to be accessed from remote clients, not just localhost.
mcp = FastMCP(
    "ThreatShield",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

# ---------------------------------------------------------------------------
# Shared HTTP client helper
# ---------------------------------------------------------------------------

async def _get(path: str, params: dict = None) -> dict:
    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.get(f"{BACKEND}{path}", params=params or {})
        r.raise_for_status()
        return r.json()


async def _post(path: str, json_body: dict = None, form_data: dict = None) -> dict:
    async with httpx.AsyncClient(timeout=120.0) as client:
        if form_data is not None:
            r = await client.post(f"{BACKEND}{path}", data=form_data)
        else:
            r = await client.post(f"{BACKEND}{path}", json=json_body or {})
        r.raise_for_status()
        return r.json()


async def _get_bytes(path: str, params: dict = None) -> bytes:
    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.get(f"{BACKEND}{path}", params=params or {})
        r.raise_for_status()
        return r.content


# ---------------------------------------------------------------------------
# TOOLS
# ---------------------------------------------------------------------------


@mcp.tool()
async def create_assessment(
    service_name: str,
    initiated_by: str,
    secreview_id: str,
    department: str = "",
    prd_url: str = "",
    slack_thread: str = "",
    app_type: str = "",
    sensitivity_level: str = "",
    internet_facing: str = "No",
    custom_prompt: str = "",
    methodology: str = "",
) -> dict:
    """
    Create a new threat assessment in the ThreatShield queue.

    The assessment is created with status 'pending'. If a prd_url or
    slack_thread is provided, the system attempts to fetch those documents
    automatically and, on success, advances the status to 'queued' for
    background processing.

    Args:
        service_name: Name of the service / feature being assessed.
        initiated_by: Email or name of the person requesting the assessment.
        secreview_id: Unique identifier for this security review (e.g. JIRA ticket ID).
        department: Department (e.g. "Payments", "Credit").
        prd_url: URL of the PRD document (Google Doc, Confluence, etc.).
        slack_thread: Slack thread URL containing design discussion.
        app_type: Application type (e.g. "API", "Web", "Mobile").
        sensitivity_level: Data sensitivity level (e.g. "High", "Medium", "Low").
        internet_facing: Whether the service is internet-facing ("Yes"/"No").
        custom_prompt: Additional context or instructions for the AI analysis.
        methodology: Threat modeling methodology (e.g. "STRIDE", "PASTA"). Provided by the caller.

    Returns:
        dict with assessment_id and status.
    """
    return await _post("/api/queue", {
        "secreview_id": secreview_id,
        "initiated_by": initiated_by,
        "service_name": service_name,
        "department": department,
        "prd_url": prd_url,
        "slack_thread": slack_thread,
        "app_type": app_type,
        "sensitivity_level": sensitivity_level,
        "internet_facing": internet_facing,
        "custom_prompt": custom_prompt,
        "methodology": methodology,
    })


@mcp.tool()
async def get_assessment_status(assessment_id: str) -> dict:
    """
    Get the current status and metadata for an assessment.

    Args:
        assessment_id: The UUID of the assessment.

    Returns:
        dict containing status, projectName, department, timestamps, etc.
    """
    return await _get("/api/details", {"assessment_id": assessment_id})


@mcp.tool()
async def cancel_assessment(assessment_id: str) -> dict:
    """
    Cancel a running or queued assessment.

    Args:
        assessment_id: The UUID of the assessment to cancel.

    Returns:
        dict with cancellation confirmation.
    """
    return await _post(f"/api/cancel-assessment/{assessment_id}")


@mcp.tool()
async def retry_fetch_doc(
    assessment_id: str,
    doc_type: str,
    url: str = "",
) -> dict:
    """
    Retry fetching a document that previously failed to load.

    Args:
        assessment_id: The UUID of the assessment.
        doc_type: One of 'prdDoc', 'confluenceDoc', or 'slackThread'.
        url: Optional new URL to use instead of the stored one.

    Returns:
        dict with fetch result and updated assessment info.
    """
    if doc_type not in ("prdDoc", "confluenceDoc", "slackThread"):
        return {"error": "doc_type must be one of: prdDoc, confluenceDoc, slackThread"}
    body = {}
    if url:
        body["url"] = url
    return await _post(f"/api/retry-fetch-doc/{assessment_id}/{doc_type}", body)


@mcp.tool()
async def generate_pdf_report(assessment_id: str) -> dict:
    """
    Generate a PDF report for a completed assessment and return it as a
    base64-encoded string along with a direct download URL.

    Args:
        assessment_id: The UUID of the assessment.

    Returns:
        dict with keys:
          - download_url: Direct URL to download the PDF from the backend.
          - pdf_base64: Base64-encoded PDF bytes (may be large).
          - filename: Suggested filename for the PDF.
    """
    pdf_bytes = await _get_bytes(
        "/api/report/download-pdf",
        {"assessment_id": assessment_id},
    )
    return {
        "download_url": f"{BACKEND}/api/report/download-pdf?assessment_id={assessment_id}",
        "filename": f"threat-shield-report-{assessment_id}.pdf",
        "pdf_base64": base64.b64encode(pdf_bytes).decode("utf-8"),
        "size_bytes": len(pdf_bytes),
    }


@mcp.tool()
async def chat_with_assessment(assessment_id: str, question: str) -> dict:
    """
    Ask a natural-language question about a completed assessment.

    The AI answers using the stored threat model, DREAD scores, mitigations,
    and other analysis results as context.

    Args:
        assessment_id: The UUID of the assessment to chat about.
        question: Your security question or follow-up query.

    Returns:
        dict with the AI answer.
    """
    return await _post("/api/query-ai", {
        "assessment_id": assessment_id,
        "user_query": question,
    })


# ---------------------------------------------------------------------------
# RESOURCES
# ---------------------------------------------------------------------------


@mcp.resource("threatshield://assessments")
async def list_assessments() -> str:
    """List all assessments in ThreatShield with their current status."""
    data = await _get("/api/storage")
    return json.dumps(data, indent=2)


@mcp.resource("threatshield://assessment/{assessment_id}/details")
async def get_assessment_details(assessment_id: str) -> str:
    """Assessment metadata: name, DEPARTMENT, status, timestamps, source URLs."""
    data = await _get("/api/details", {"assessment_id": assessment_id})
    return json.dumps(data, indent=2)


@mcp.resource("threatshield://assessment/{assessment_id}/threat_model")
async def get_threat_model(assessment_id: str) -> str:
    """Full STRIDE threat model for the assessment."""
    data = await _get("/api/threat-model", {"assessment_id": assessment_id})
    return json.dumps(data, indent=2)


@mcp.resource("threatshield://assessment/{assessment_id}/dread")
async def get_dread_assessment(assessment_id: str) -> str:
    """DREAD scores (Damage, Reproducibility, Exploitability, Affected users, Discoverability)."""
    data = await _get("/api/dread-assessment", {"assessment_id": assessment_id})
    return json.dumps(data, indent=2)


@mcp.resource("threatshield://assessment/{assessment_id}/mitigations")
async def get_mitigations(assessment_id: str) -> str:
    """Security control recommendations and mitigations for identified threats."""
    data = await _get("/api/mitigations", {"assessment_id": assessment_id})
    return json.dumps(data, indent=2)


@mcp.resource("threatshield://assessment/{assessment_id}/attack_tree")
async def get_attack_tree(assessment_id: str) -> str:
    """Attack tree showing paths an adversary could use to compromise the system."""
    data = await _get("/api/attack-tree", {"assessment_id": assessment_id})
    return json.dumps(data, indent=2)


@mcp.resource("threatshield://assessment/{assessment_id}/test_cases")
async def get_test_cases(assessment_id: str) -> str:
    """ASVS-based security test cases for the assessment."""
    data = await _get("/api/asvs-test-cases", {"assessment_id": assessment_id})
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# PROMPTS
# ---------------------------------------------------------------------------


@mcp.prompt()
def security_review_prompt(
    service_name: str,
    description: str,
    department: str = "",
    assessment_id: str = "",
) -> str:
    """
    A structured prompt to guide a comprehensive security review using ThreatShield.

    Generates step-by-step instructions for:
    1. Creating/finding the assessment
    2. Reviewing threat model results
    3. Evaluating DREAD scores
    4. Reviewing mitigations
    5. Producing a summary report
    """
    steps = [
        f"# Security Review: {service_name}",
        "",
        f"**Service**: {service_name}",
        f"**Description**: {description}",
    ]
    if department:
        steps.append(f"**Department**: {department}")
    if assessment_id:
        steps.append(f"**Assessment ID**: {assessment_id}")

    steps += [
        "",
        "## Review Steps",
        "",
        "1. **Fetch assessment status** — use `get_assessment_status` to confirm the"
        " assessment is completed.",
        "",
        "2. **Review threat model** — read `threatshield://assessment/{id}/threat_model`."
        " Identify the top 3 highest-risk threats.",
        "",
        "3. **Evaluate DREAD scores** — read `threatshield://assessment/{id}/dread`."
        " Flag any threats with a total score ≥ 7 (HIGH/CRITICAL).",
        "",
        "4. **Check mitigations** — read `threatshield://assessment/{id}/mitigations`."
        " Verify each HIGH/CRITICAL threat has at least one mitigation.",
        "",
        "5. **Review attack tree** — read `threatshield://assessment/{id}/attack_tree`."
        " Identify the most likely attack paths.",
        "",
        "6. **Summarise findings** — produce a concise report with:",
        "   - Overall risk rating (Critical/High/Medium/Low)",
        "   - Top 5 threats with DREAD scores",
        "   - Priority mitigations (must-fix before launch)",
        "   - Recommended security test cases",
        "",
        "7. **Generate PDF report** — call `generate_pdf_report` to produce a"
        " downloadable PDF for stakeholders.",
    ]
    return "\n".join(steps)


@mcp.prompt()
def create_assessment_prompt(
    service_name: str,
    initiated_by: str,
    prd_url: str = "",
    slack_thread: str = "",
    department: str = "",
) -> str:
    """
    Prompt to guide creation of a new ThreatShield assessment.
    """
    lines = [
        f"Create a new ThreatShield assessment for **{service_name}**.",
        "",
        "Use the `create_assessment` tool with the following parameters:",
        f"- service_name: {service_name}",
        f"- initiated_by: {initiated_by}",
        f"- secreview_id: (generate a unique ID, e.g. SEC-<timestamp>)",
    ]
    if department:
        lines.append(f"- department: {department}")
    if prd_url:
        lines.append(f"- prd_url: {prd_url}")
    if slack_thread:
        lines.append(f"- slack_thread: {slack_thread}")
    lines += [
        "",
        "After creation, monitor status with `get_assessment_status` until status is"
        " 'completed', then run a full security review.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    transport = "streamable-http"
    if "--stdio" in sys.argv:
        transport = "stdio"
    elif "--sse" in sys.argv:
        transport = "sse"

    print(f"[ThreatShield MCP] Starting on {MCP_HOST}:{MCP_PORT} (transport={transport})")
    print(f"[ThreatShield MCP] Backend: {BACKEND}")
    if transport == "streamable-http":
        print(f"[ThreatShield MCP] Endpoint: http://{MCP_HOST}:{MCP_PORT}/mcp")
    elif transport == "sse":
        print(f"[ThreatShield MCP] Endpoint: http://{MCP_HOST}:{MCP_PORT}/sse")

    mcp.settings.host = MCP_HOST
    mcp.settings.port = MCP_PORT
    mcp.run(transport=transport)
