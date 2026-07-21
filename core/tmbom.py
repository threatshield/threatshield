"""
TM-BOM (Threat Model Bill of Materials) generator.

Follows OWASP Threat Modeling nomenclature and the CycloneDX TM-BOM draft spec.
Assembles all pipeline artifacts into a single structured document with
OWASP-style THREAT-NNN IDs cross-linked to DREAD scores, mitigations, and ASVS test cases.
"""

from datetime import datetime, timezone


class TmBomGenerator:

    def generate(self, assessment_id: str, storage_handler) -> dict:
        details = storage_handler.get_details_info(assessment_id) or {}
        threat_model = storage_handler.get_threat_model(assessment_id)
        dread = storage_handler.get_dread_assessment(assessment_id)
        mitigation = storage_handler.get_mitigation_result(assessment_id)
        test_cases = storage_handler.get_test_cases(assessment_id)
        attack_tree = storage_handler.get_attack_tree(assessment_id)

        raw_threats = self._extract_threats(threat_model)
        dread_index = self._build_dread_index(dread)
        mitigation_index = self._build_mitigation_index(mitigation)
        test_case_index = self._build_test_case_index(test_cases)

        threats = []
        for i, t in enumerate(raw_threats):
            threat_id = f"THREAT-{str(i + 1).zfill(3)}"
            scenario = t.get("Scenario", "")
            scenario_key = scenario.lower().strip()

            dread_scores = self._lookup(dread_index, scenario_key)
            mitigations = self._lookup(mitigation_index, scenario_key) or []
            tc_list = self._lookup(test_case_index, scenario_key) or []

            entry = {
                "id": threat_id,
                "type": t.get("Threat Type", ""),
                "scenario": scenario,
                "potential_impact": t.get("Potential Impact", ""),
                "confidence": t.get("Confidence", "Medium"),
                "mitigations": mitigations,
                "test_cases": tc_list,
            }

            if "Business Risk Type" in t:
                brt = t["Business Risk Type"]
                entry["business_risk_type"] = ", ".join(brt) if isinstance(brt, list) else brt
            if "PASTA Stage" in t:
                entry["pasta_stage"] = t["PASTA Stage"]

            if dread_scores:
                entry["dread_scores"] = dread_scores

            threats.append(entry)

        methodology = details.get("threatModelingMethodology", details.get("methodology", "STRIDE"))

        return {
            "bomFormat": "ThreatModelBOM",
            "specVersion": "1.0",
            "serialNumber": assessment_id,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "assessment_id": assessment_id,
                "project_name": details.get("projectName", details.get("name", "")),
                "lob": details.get("lineOfBusiness", details.get("lob", "")),
                "methodology": methodology,
                "app_type": details.get("applicationType", ""),
                "created_by": (details.get("queue") or {}).get("initiated_by", details.get("created_by", "")),
                "internet_facing": details.get("isInternetFacing", details.get("internetFacing", False)),
                "authentication": details.get("authenticationMethod", details.get("authentication", "")),
                "sensitive_data": details.get("dataSensitivityLevel", details.get("sensitiveData", "")),
            },
            "threats": threats,
            "attack_tree": self._extract_attack_tree(attack_tree),
            "improvement_suggestions": self._extract_improvement_suggestions(threat_model),
            "summary": self._compute_summary(threats),
        }

    # --- private helpers ---

    def _extract_threats(self, threat_model):
        if not threat_model:
            return []
        result = threat_model.get("result", {})
        raw = result.get("raw_response", result)
        return raw.get("threat_model", [])

    def _extract_improvement_suggestions(self, threat_model):
        if not threat_model:
            return []
        result = threat_model.get("result", {})
        raw = result.get("raw_response", result)
        return raw.get("improvement_suggestions", [])

    def _build_dread_index(self, dread):
        """Returns { scenario_key: dread_scores_dict }"""
        index = {}
        if not dread:
            return index
        result = dread.get("result", dread)
        # Navigate through raw_response if present
        raw = result.get("raw_response", result)
        items = raw.get("Risk Assessment", raw.get("risk_assessment", raw.get("dread_scores", [])))
        if not isinstance(items, list):
            return index
        for item in items:
            scenario = (item.get("Scenario") or item.get("scenario") or "").lower().strip()
            if not scenario:
                continue
            try:
                d = float(item.get("D", item.get("Damage Potential", item.get("Damage", 0))) or 0)
                r = float(item.get("R", item.get("Reproducibility", 0)) or 0)
                e = float(item.get("E", item.get("Exploitability", 0)) or 0)
                a = float(item.get("A", item.get("Affected Users", 0)) or 0)
                disc = float(item.get("Discoverability", item.get("D2", item.get("D ", 0))) or 0)
                avg = (d + r + e + a + disc) / 5 if (d + r + e + a + disc) > 0 else 0
                if avg >= 9:
                    priority = "Critical"
                elif avg >= 8:
                    priority = "High"
                elif avg >= 4:
                    priority = "Moderate"
                else:
                    priority = "Low"
                index[scenario] = {
                    "damage": d, "reproducibility": r, "exploitability": e,
                    "affected_users": a, "discoverability": disc,
                    "average": round(avg, 1), "priority": priority,
                }
            except (TypeError, ValueError):
                pass
        return index

    def _build_mitigation_index(self, mitigation):
        """Returns { scenario_key: [mitigation_strings] }"""
        index = {}
        if not mitigation:
            return index
        result = mitigation.get("result", mitigation)
        # Navigate through raw_response if present
        raw = result.get("raw_response", result)
        items = raw.get("mitigations", [])
        if not isinstance(items, list):
            return index
        for item in items:
            scenario = (item.get("Scenario") or item.get("scenario") or "").lower().strip()
            if not scenario:
                continue
            raw_mit = item.get("Suggested Mitigation(s)", item.get("mitigations", item.get("mitigation", "")))
            if isinstance(raw_mit, list):
                mits = [str(m).strip() for m in raw_mit if str(m).strip()]
            elif isinstance(raw_mit, str) and raw_mit.strip():
                mits = self._split_numbered_list(raw_mit)
            else:
                mits = []
            index[scenario] = mits
        return index

    def _build_test_case_index(self, test_cases):
        """Returns { scenario_key: [test_case_dicts] }"""
        index = {}
        if not test_cases:
            return index
        result = test_cases.get("result", test_cases)
        items = result.get("test_cases", [])
        if not isinstance(items, list):
            return index
        for group in items:
            scenario = (group.get("Scenario") or group.get("scenario") or "").lower().strip()
            if not scenario:
                continue
            tcs = group.get("test_cases", [])
            simplified = []
            for tc in tcs:
                simplified.append({
                    "description": tc.get("test_description", tc.get("description", "")),
                    "steps": tc.get("steps", tc.get("test_steps", [])),
                    "expected_result": tc.get("expected_result", tc.get("pass_condition", "")),
                    "validated": tc.get("validated", False),
                })
            index[scenario] = simplified
        return index

    @staticmethod
    def _normalize_scenario(scenario: str) -> str:
        """Normalize LLM scenario text for matching.

        Two malformed patterns appear when the LLM embeds the next JSON field inline:
          Pattern A (threat model): 'credpay:\\n      "Potential Impact": "impact text'
          Pattern B (test cases):   'credpay: Potential Impact: impact text'
        Both should normalize to:   'credpay: impact text'
        """
        import re
        s = scenario.lower().strip()
        # Pattern A: \n + whitespace + quoted "field name": "
        s = re.sub(r'\n\s*"[^"]+"\s*:\s*"', ' ', s)
        # Pattern B: plain "potential impact:" prefix after colon-space
        s = re.sub(r':\s+potential impact:\s+', ': ', s)
        # Collapse extra whitespace
        s = re.sub(r' {2,}', ' ', s)
        return s.strip()

    def _lookup(self, index: dict, scenario_key: str):
        """Exact match, then normalized match, then 100-char prefix match."""
        if scenario_key in index:
            return index[scenario_key]
        # Normalized match — strips embedded JSON artifacts from both sides
        norm_query = self._normalize_scenario(scenario_key)
        for k, v in index.items():
            if self._normalize_scenario(k) == norm_query:
                return v
        # Last resort: prefix match on first 100 chars
        prefix = scenario_key[:100]
        for k, v in index.items():
            if k[:100] == prefix:
                return v
        return None

    def _split_numbered_list(self, text: str) -> list:
        """Split a numbered list string ('1. foo\n2. bar') into individual items."""
        import re
        parts = re.split(r'\n\d+\.\s+', text.strip())
        cleaned = []
        for p in parts:
            p = re.sub(r'^\d+\.\s+', '', p).strip()
            if p:
                cleaned.append(p)
        return cleaned

    def _extract_attack_tree(self, attack_tree):
        if not attack_tree:
            return ""
        result = attack_tree.get("result", attack_tree)
        markdown = result.get("markdown", result.get("attack_tree", ""))
        if isinstance(markdown, str):
            if "```mermaid" in markdown:
                start = markdown.find("```mermaid") + len("```mermaid")
                end = markdown.rfind("```")
                if end > start:
                    return markdown[start:end].strip()
            return markdown.strip()
        return ""

    def _compute_summary(self, threats):
        critical = high = moderate = low = 0
        total_mitigations = total_test_cases = validated_test_cases = 0

        for t in threats:
            dread = t.get("dread_scores")
            if dread:
                p = dread.get("priority", "Low")
                if p == "Critical":
                    critical += 1
                elif p == "High":
                    high += 1
                elif p == "Moderate":
                    moderate += 1
                else:
                    low += 1
            else:
                low += 1

            total_mitigations += len(t.get("mitigations", []))
            tcs = t.get("test_cases", [])
            total_test_cases += len(tcs)
            validated_test_cases += sum(1 for tc in tcs if tc.get("validated"))

        return {
            "total_threats": len(threats),
            "critical_risk": critical,
            "high_risk": high,
            "moderate_risk": moderate,
            "low_risk": low,
            "total_mitigations": total_mitigations,
            "total_test_cases": total_test_cases,
            "validated_test_cases": validated_test_cases,
        }
