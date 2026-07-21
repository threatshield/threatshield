import logging
from dotenv import load_dotenv, find_dotenv
import requests
import os

# Load environment variables — find_dotenv searches up the directory tree
load_dotenv(find_dotenv())

def fetch_jira_tickets(appsec_department: str) -> list:
    """
    Fetches and returns the open and resolved security vulnerabilities from a Jira project based on the application department.

    Args:
        appsec_department (str): The label of the AppSec Department to filter Jira tickets.

    Returns:
        list: A list of dictionaries containing metadata and details of the fetched Jira tickets, including the issue key, description, status, and priority.
    """

    jira_server = os.getenv('JIRA_URL')
    jira_user = os.getenv('JIRA_USERNAME')
    jira_token = os.getenv('JIRA_TOKEN')
    jira_project = os.getenv('JIRA_PROJECT')

    logging.info(f"[JIRA] Config — server={jira_server}, user={jira_user}, project={jira_project}, token_set={bool(jira_token)}")

    jql = f'project = {jira_project} AND "pod[Labels]"="{appsec_department}" and status in ("To Do","In Progress","Risk","POSSIBLE FUTURE RISK")'
    logging.info(f"[JIRA] Executing JQL: {jql}")

    url = f"{jira_server}/rest/api/3/search/jql"
    auth = (jira_user, jira_token)
    headers = {"Accept": "application/json"}

    ticket_data = []
    start_at = 0
    max_results = 100

    try:
        while True:
            params = {
                "jql": jql,
                "fields": "summary,status,priority",
                "startAt": start_at,
                "maxResults": max_results
            }
            response = requests.get(url, auth=auth, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            issues = data.get("issues", [])
            for issue in issues:
                fields = issue.get("fields", {})
                ticket_data.append({
                    "key": issue.get("key", ""),
                    "description": fields.get("summary", ""),
                    "status": fields.get("status", {}).get("name", ""),
                    "priority": fields.get("priority", {}).get("name", "")
                })

            total = data.get("total", 0)
            start_at += len(issues)
            if start_at >= total or not issues:
                break

        logging.info(f"[JIRA] Found {len(ticket_data)} tickets for DEPARTMENT: {appsec_department}")
        return ticket_data

    except requests.HTTPError as e:
        logging.error(f"[JIRA] HTTP error fetching tickets for DEPARTMENT '{appsec_department}': {e.response.status_code} {e.response.text}")
        return []
    except Exception as e:
        logging.error(f"[JIRA] Error fetching tickets for DEPARTMENT '{appsec_department}': {str(e)}")
        return []
