import json
import logging

from rag.rag_handler import PromptManager


class ThreatFilterEngine:
    def __init__(self, openai_handler, config: dict = None):
        self.openai_handler = openai_handler
        self.config = config or {}
        self.prompt_manager = PromptManager()

    def build_infra_context_block(self) -> str:
        controls = self.config.get('infrastructureControls', {})
        if not controls:
            return ""

        lines = ["INFRASTRUCTURE SECURITY CONTROLS (Pre-existing — do not generate threats these already prevent):"]

        gw = controls.get('apiGateway', {})
        if gw:
            vendor = gw.get('vendor', 'API Gateway')
            headers = ', '.join(gw.get('trustedHeaders', []))
            desc = gw.get('description', '')
            lines.append(f"- API Gateway ({vendor}): {desc} Trusted headers: {headers}")

        waf = controls.get('waf', {})
        if waf:
            vendor = waf.get('vendor', 'CDN/WAF')
            caps = ', '.join(waf.get('capabilities', []))
            desc = waf.get('description', '')
            lines.append(f"- CDN/WAF ({vendor}): {desc} Capabilities: {caps}")

        mesh = controls.get('serviceMesh', {})
        if mesh:
            protocol = mesh.get('protocol', 'mTLS')
            desc = mesh.get('description', '')
            lines.append(f"- Service Mesh ({protocol}): {desc}")

        return "\n".join(lines)

    def build_fp_filter_block(self) -> str:
        controls = self.config.get('infrastructureControls', {})
        gw = controls.get('apiGateway', {})
        waf = controls.get('waf', {})
        keywords = self.config.get('falsePositiveKeywords', [])

        trusted_headers = ', '.join(gw.get('trustedHeaders', [
            'x-user-id', 'x-device-id', 'x-tenant-id', 'x-request-id',
            'x-correlation-id', 'x-forwarded-for', 'x-real-ip', 'x-auth-token', 'x-service-name'
        ]))
        waf_vendor = waf.get('vendor', 'CDN/WAF')

        lines = [
            "FALSE POSITIVE FILTER — Before finalising each threat, verify it is genuinely exploitable given the stated infrastructure. OMIT any threat where:",
            f"1. The attack requires controlling, guessing, enumerating, spoofing, or forging any of these internal HTTP headers: ({trusted_headers}). These headers are stripped by the client request and re-injected by the API gateway after authentication — an external attacker has no ability to set them to an arbitrary value. This rule applies even if the scenario also mentions IDOR, user ownership, or access control failures. If the described attack path depends on the attacker influencing the value of one of these headers (e.g. 'guessing user_id values via the x-user-id header', 'if the endpoint does not validate the x-user-id header'), the threat MUST be suppressed. A genuine IDOR threat must instead describe manipulation of a URL path parameter, query parameter, or request body field — not a gateway-managed header.",
            f"2. The attack relies on bypassing rate limiting or volumetric DDoS protection — this is enforced at the {waf_vendor} layer upstream of the application.",
            "3. The attack requires access to internal service-to-service channels — internal microservice calls use mTLS or internal service tokens not reachable from the internet.",
            "4. The threat is already fully mitigated by a control explicitly stated in the ORGANIZATION SECURITY CONTEXT above.",
        ]

        if keywords:
            keyword_list = ', '.join(keywords)
            lines.append(f"5. The scenario matches any of these org-specific exclusion patterns: {keyword_list}")

        return "\n".join(lines)

    def build_quality_requirements_block(self) -> str:
        quality = self.config.get('qualityConfig', {})
        assets = self.config.get('sensitiveAssets', [])
        min_len = quality.get('minScenarioLength', 60)

        lines = ["THREAT QUALITY REQUIREMENTS — Each passing threat MUST:"]

        if quality.get('requireSpecificEntryPoint', True):
            lines.append("- Name a specific entry point (API path, UI action, file upload, webhook) — not just 'an API'.")

        lines.append("- Describe a step-by-step attack chain — not 'an attacker could exploit a misconfiguration'.")

        if quality.get('requireAssetSpecificity', True) and assets:
            asset_list = ', '.join(assets)
            lines.append(f"- Reference a specific sensitive asset where applicable: {asset_list}")

        lines.append("- Be unique — no near-duplicate scenarios differing only in surface wording.")
        lines.append(f"- Have a Scenario description of at least {min_len} characters.")

        return "\n".join(lines)

    def run_critic_pass(self, threats: list, methodology: str = 'STRIDE') -> dict:
        if not threats:
            return {"filtered_threats": [], "removed_threats": []}

        prompt_key = "pasta_threat_model_critic" if methodology == 'PASTA' else "threat_model_critic"
        try:
            prompt_data = self.prompt_manager.get_prompt(prompt_key)
        except Exception:
            logging.warning(f"[CRITIC] Prompt '{prompt_key}' not found — skipping critic pass")
            return {"filtered_threats": threats, "removed_threats": []}

        infra_block = self.build_infra_context_block()
        fp_block = self.build_fp_filter_block()
        quality_block = self.build_quality_requirements_block()

        critic_prompt = f"""{prompt_data.system_context}

{prompt_data.task}

{infra_block}

{fp_block}

{quality_block}

{prompt_data.instructions}

THREATS TO REVIEW:
{json.dumps(threats, indent=2)}

Respond ONLY with a valid JSON object matching this structure:
{json.dumps(prompt_data.format.get('example', {}), indent=2)}
"""

        method = self.openai_handler.method
        try:
            params = {
                "model": self.openai_handler.model,
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
                    {"role": "user", "content": critic_prompt},
                ],
                "max_tokens": 8000,
            }
            if method == 'OPENAI':
                params["response_format"] = {"type": "json_object"}

            logging.info(f"[CRITIC] Running critic pass on {len(threats)} threats using {method}")
            response = self.openai_handler.client.chat.completions.create(**params)
            raw = response.choices[0].message.content

            # Strip markdown fences if present
            raw = raw.replace("```json", "").replace("```", "").strip()

            try:
                result = json.loads(raw)
            except json.JSONDecodeError:
                from json_repair import repair_json
                result = json.loads(repair_json(raw))

            filtered = result.get("filtered_threats", threats)
            removed = result.get("removed_threats", [])
            logging.info(f"[CRITIC] Kept {len(filtered)}, removed {len(removed)} threats")
            return {"filtered_threats": filtered, "removed_threats": removed}

        except Exception as e:
            logging.error(f"[CRITIC] Critic pass failed: {e} — returning original threats")
            return {"filtered_threats": threats, "removed_threats": []}
