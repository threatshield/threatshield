import json
import logging
import os

_STORAGE_DIR = os.environ.get('STORAGE_PATH', 'storage')
import re
import time
import datetime
import math

logger = logging.getLogger(__name__)

# Batch size for hierarchical tree-merging — each LLM call sees at most this many sub-models
_BATCH_SIZE = 3

# Horizontal x-position per node type (left-to-right data flow layout)
_TYPE_X: dict = {
    'Client':                      0,
    'API Gateway':                 350,
    'Microservice':                700,
    'Database':                    1050,
    'Infrastructure':              1400,
    'External / Third-Party System': 1750,
}
_FALLBACK_X = 2100
_Y_STEP = 160
_MAX_PER_TYPE_COL = 5   # wrap to a new sub-column after this many nodes of the same type
_TYPE_COL_X_STEP  = 220 # x offset for each overflow sub-column within a type group


class ConsolidateDiagramGenerator:
    """
    Merges the ReactFlow DFDs from multiple sub-model assessments into a single
    consolidated architecture diagram via LLM calls.

    Strategy for large LOBs (many sub-models):
    - Compress each input to compact node/edge spec (strip positions, styles, animations)
    - LLM outputs compact nodes/edges only — no positions, no styles, no stringified JSON
    - Positions are assigned programmatically by node type (deterministic layout)
    - Hierarchical tree merging: batches of ≤_BATCH_SIZE sub-models per LLM call,
      then merged results are recursively merged until a single diagram remains
    - Truncation detection via finish_reason
    """

    CONSOLIDATED_DIR = os.path.join(_STORAGE_DIR, 'data', 'consolidated_diagrams')

    def __init__(self, openai_handler):
        self.openai_handler = openai_handler
        self.client = openai_handler.client

    # ── Input compression ──────────────────────────────────────────────────────

    def _compress_reactflow(self, reactflow_str: str) -> list[dict]:
        """
        Parse a ReactFlow JSON string and return a compact node/edge list.
        Strips positions, styles, animated flags, markerEnd — keeps only
        what the LLM needs to understand the architecture.
        Returns {"nodes": [...], "edges": [...]} as dicts.
        """
        try:
            data = json.loads(reactflow_str) if isinstance(reactflow_str, str) else reactflow_str
        except Exception:
            return {"nodes": [], "edges": []}

        nodes = []
        for n in data.get("nodes", []):
            node_type = (
                n.get("data", {}).get("type")
                or n.get("type")
                or "Microservice"
            )
            # Normalise custom node type used in the renderer
            if node_type == "dfd-component":
                node_type = "Microservice"
            nodes.append({
                "id":    n.get("id", ""),
                "label": n.get("data", {}).get("label") or n.get("id", ""),
                "type":  node_type,
            })

        edges = []
        for e in data.get("edges", []):
            edges.append({
                "id":     e.get("id", ""),
                "source": e.get("source", ""),
                "target": e.get("target", ""),
                "label":  e.get("label") or e.get("data", {}).get("label") or "",
            })

        return {"nodes": nodes, "edges": edges}

    # ── Position assignment (no LLM needed) ───────────────────────────────────

    def _assign_positions(self, nodes: list[dict]) -> list[dict]:
        """
        Assign x/y positions based on node type.
        Nodes of the same type are stacked vertically; after _MAX_PER_TYPE_COL rows
        they wrap into the next sub-column (shifted right by _TYPE_COL_X_STEP),
        keeping columns bounded in height.
        """
        type_counters: dict[str, int] = {}
        result = []
        for n in nodes:
            t = n.get("type", "Microservice")
            idx = type_counters.get(t, 0)
            type_counters[t] = idx + 1
            sub_col = idx // _MAX_PER_TYPE_COL
            row     = idx %  _MAX_PER_TYPE_COL
            result.append({
                **n,
                "position": {
                    "x": _TYPE_X.get(t, _FALLBACK_X) + sub_col * _TYPE_COL_X_STEP,
                    "y": row * _Y_STEP,
                },
            })
        return result

    # ── ReactFlow builder ──────────────────────────────────────────────────────

    def _build_reactflow_json(self, nodes: list[dict], edges: list[dict]) -> str:
        """Build the full ReactFlow JSON string from compact nodes + edges."""
        positioned = self._assign_positions(nodes)
        rf_nodes = [
            {
                "id":       n["id"],
                "type":     "dfd-component",
                "position": n["position"],
                "data":     {"label": n["label"], "type": n["type"]},
                "style":    {"width": 200, "height": "auto", "padding": 0, "border": "none", "background": "transparent"},
            }
            for n in positioned
        ]
        rf_edges = [
            {
                "id":        e.get("id") or f"e_{e['source']}_{e['target']}",
                "source":    e["source"],
                "target":    e["target"],
                "label":     e.get("label", ""),
                "animated":  True,
                "style":     {"stroke": "#94a3b8", "strokeWidth": 2},
                "markerEnd": {"type": "arrowclosed", "color": "#94a3b8"},
            }
            for e in edges
        ]
        return json.dumps({"nodes": rf_nodes, "edges": rf_edges})

    # ── LLM helpers ────────────────────────────────────────────────────────────

    def _llm_call_with_retry(self, params: dict):
        for attempt in range(1, 4):
            try:
                return self.client.chat.completions.create(**params)
            except Exception as e:
                if attempt == 3:
                    raise
                logger.warning(f"[consolidate] Attempt {attempt} failed: {e}. Retrying in {2**attempt}s…")
                time.sleep(2 ** attempt)

    def _clean_json(self, text: str) -> str:
        text = text.replace("```json", "").replace("```", "").strip()
        # Find the outermost {...}
        start = text.find('{')
        end   = text.rfind('}')
        if start >= 0 and end > start:
            text = text[start:end + 1]
        text = re.sub(r',\s*([}\]])', r'\1', text)   # trailing commas
        text = re.sub(r'//[^\n]*\n', '\n', text)      # JS comments
        return text

    def _system_message(self) -> str:
        return (
            "You are a security architect specialising in data flow diagrams.\n\n"
            "You will receive compact node/edge representations of several sub-model architecture diagrams "
            "for the SAME system. Merge them into ONE deduplicated diagram.\n\n"
            "Rules:\n"
            "1. DEDUPLICATE — nodes with the same label (case-insensitive) appear only ONCE. Keep the ID "
            "from its first occurrence.\n"
            "2. PRESERVE — every unique component and connection must appear in the output.\n"
            "3. CONNECT — where components from different sub-models logically interact, add an edge.\n"
            "4. IDs — use the original snake_case IDs; for new edges use 'eN' where N is sequential.\n"
            "5. TYPES — each node type must be exactly one of:\n"
            "   Client | API Gateway | Microservice | Database | Infrastructure | "
            "External / Third-Party System\n\n"
            "IMPORTANT: Do NOT include positions or styles — those are computed separately.\n\n"
            "Respond with ONLY a single compact JSON object (no markdown fences):\n"
            "{\n"
            '  "nodes": [{"id": "...", "label": "...", "type": "..."}],\n'
            '  "edges": [{"id": "...", "source": "...", "target": "...", "label": "..."}],\n'
            '  "summary": "One sentence describing the consolidated architecture.",\n'
            '  "components": ["NodeLabel1", "NodeLabel2"]\n'
            "}\n\n"
            "Keep edges minimal — only the most architecturally significant ones."
        )

    # ── Single-batch merge (≤ _BATCH_SIZE inputs) ─────────────────────────────

    def _pre_dedup_inputs(self, inputs: list[dict]) -> list[dict]:
        """
        Algorithmically deduplicate nodes with identical labels (case-insensitive)
        across all inputs before sending to the LLM.  The first occurrence wins;
        subsequent inputs that reference a deduplicated node-ID have their edges
        rewritten to point at the surviving ID.
        """
        label_to_id: dict[str, str] = {}   # canonical label → winning ID
        id_remap:    dict[str, str] = {}    # original ID → winning ID

        deduped = []
        for item in inputs:
            new_nodes = []
            for n in item.get("nodes", []):
                key = n["label"].strip().lower()
                if key not in label_to_id:
                    label_to_id[key] = n["id"]
                    id_remap[n["id"]] = n["id"]
                    new_nodes.append(n)
                else:
                    id_remap[n["id"]] = label_to_id[key]

            new_edges = []
            for e in item.get("edges", []):
                src = id_remap.get(e["source"], e["source"])
                tgt = id_remap.get(e["target"], e["target"])
                if src != tgt:
                    new_edges.append({**e, "source": src, "target": tgt})

            deduped.append({**item, "nodes": new_nodes, "edges": new_edges})

        return deduped

    def _merge_batch(self, inputs: list[dict], source_count: int, _retry_halved: bool = False) -> dict:
        """
        Call LLM once to merge a small batch of compact node/edge dicts.
        inputs: [{"assessment_id": str, "nodes": [...], "edges": [...]}]
        Returns: {"nodes": [...], "edges": [...], "summary": str, "components": [...]}

        On truncation (finish_reason=length), splits the batch in half and merges
        each half separately, then merges the two results — one retry level only.
        """
        # Algorithmic pre-deduplication reduces LLM output size
        inputs = self._pre_dedup_inputs(inputs)

        sections = []
        for i, item in enumerate(inputs, 1):
            compact = json.dumps({"nodes": item["nodes"], "edges": item["edges"]}, separators=(',', ':'))
            sections.append(f"--- Sub-model {i} (id: {item['assessment_id']}) ---\n{compact}")

        prompt = (
            f"Merge {len(inputs)} sub-model diagram(s) into one deduplicated diagram.\n\n"
            + "\n\n".join(sections)
            + "\n\nReturn the merged result as specified."
        )

        # Use the model's full output capacity — never cap below what it supports
        max_out = self.openai_handler.max_output_tokens

        params = {
            "model":       self.openai_handler.model,
            "messages":    [
                {"role": "system", "content": self._system_message()},
                {"role": "user",   "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens":  max_out,
            "timeout":     180,
        }
        if self.openai_handler.method == 'OPENAI':
            params["response_format"] = {"type": "json_object"}

        raw = None
        try:
            resp = self._llm_call_with_retry(params)
            raw  = resp.choices[0].message.content

            finish = getattr(resp.choices[0], "finish_reason", None)
            if finish == "length":
                if _retry_halved or len(inputs) == 1:
                    logger.error("[consolidate] LLM response truncated even on a single sub-model — giving up")
                    raise RuntimeError(
                        "LLM response was truncated on a single sub-model. "
                        "The diagram is too large — contact an admin."
                    )

                logger.warning(
                    f"[consolidate] Truncation on batch of {len(inputs)} — splitting in half and retrying"
                )
                mid  = len(inputs) // 2
                half1 = self._merge_batch(inputs[:mid],  source_count, _retry_halved=True)
                half2 = self._merge_batch(inputs[mid:],  source_count, _retry_halved=True)
                # Merge the two halves with a fresh LLM call
                return self._merge_batch(
                    [
                        {"assessment_id": "half_1", "nodes": half1["nodes"], "edges": half1["edges"]},
                        {"assessment_id": "half_2", "nodes": half2["nodes"], "edges": half2["edges"]},
                    ],
                    source_count,
                    _retry_halved=True,
                )

            parsed = json.loads(self._clean_json(raw))
            return {
                "nodes":      parsed.get("nodes", []),
                "edges":      parsed.get("edges", []),
                "summary":    parsed.get("summary", ""),
                "components": parsed.get("components", []),
            }

        except RuntimeError:
            raise
        except Exception as e:
            logger.error(f"[consolidate] Batch merge failed: {e}")
            raise RuntimeError(f"Batch merge failed: {e}") from e

    # ── Hierarchical tree merge ────────────────────────────────────────────────

    def _tree_merge(self, inputs: list[dict]) -> dict:
        """
        Recursively merge inputs in batches of _BATCH_SIZE until one result remains.
        inputs: list of {"assessment_id": str, "nodes": [...], "edges": [...]}
        """
        source_count = len(inputs)

        while len(inputs) > 1:
            batches = [inputs[i:i + _BATCH_SIZE] for i in range(0, len(inputs), _BATCH_SIZE)]
            logger.info(f"[consolidate] Tree level: {len(inputs)} → {len(batches)} batch(es) of ≤{_BATCH_SIZE}")
            next_level = []
            for idx, batch in enumerate(batches):
                logger.info(f"[consolidate] Merging batch {idx+1}/{len(batches)} ({len(batch)} sub-models)")
                merged = self._merge_batch(batch, source_count)
                next_level.append({
                    "assessment_id": f"batch_{idx}",
                    "nodes":         merged["nodes"],
                    "edges":         merged["edges"],
                    "_summary":      merged.get("summary", ""),
                    "_components":   merged.get("components", []),
                })
            inputs = next_level

        return inputs[0]

    # ── Public API ─────────────────────────────────────────────────────────────

    def consolidate(self, reactflow_inputs: list, group_id: str) -> dict:
        """
        Merge N reactflow JSON strings into a single consolidated diagram.

        reactflow_inputs: list of {"assessment_id": str, "reactflow": str}
        group_id:         storage key, e.g. "department_wealth"

        Returns: {"reactflow": str, "summary": str, "components": [...], "source_count": int}
        """
        if not reactflow_inputs:
            raise ValueError("No reactflow inputs provided for consolidation")

        logger.info(f"[consolidate] Starting consolidation of {len(reactflow_inputs)} sub-models "
                    f"(group={group_id}, batch_size={_BATCH_SIZE})")

        # Compress all inputs up front
        compact_inputs = []
        for item in reactflow_inputs:
            compressed = self._compress_reactflow(item["reactflow"])
            if compressed["nodes"]:
                compact_inputs.append({
                    "assessment_id": item["assessment_id"],
                    "nodes":         compressed["nodes"],
                    "edges":         compressed["edges"],
                })
            else:
                logger.warning(f"[consolidate] Skipping {item['assessment_id']}: no nodes after compression")

        if not compact_inputs:
            raise ValueError("All reactflow inputs were empty after compression")

        # Hierarchical merge
        final = self._tree_merge(compact_inputs)

        nodes    = final.get("nodes", [])
        edges    = final.get("edges", [])
        summary  = final.get("_summary") or final.get("summary", "Consolidated architecture diagram")
        comps    = final.get("_components") or final.get("components") or [n["label"] for n in nodes]

        reactflow_str = self._build_reactflow_json(nodes, edges)

        logger.info(f"[consolidate] Done — {len(nodes)} nodes, {len(edges)} edges (group={group_id})")

        return {
            "reactflow":    reactflow_str,
            "summary":      summary,
            "components":   comps,
            "source_count": len(reactflow_inputs),
        }

    # ── Storage helpers ────────────────────────────────────────────────────────

    def _group_dir(self, group_id: str) -> str:
        return os.path.join(self.CONSOLIDATED_DIR, group_id)

    def _store_error(self, group_id: str, raw_response, error):
        if not raw_response:
            return
        try:
            error_path = os.path.join(self._group_dir(group_id), 'error.json')
            os.makedirs(os.path.dirname(error_path), exist_ok=True)
            with open(error_path, 'w') as f:
                json.dump({
                    "error":        str(error),
                    "raw_response": raw_response[:4000],   # cap stored size
                    "timestamp":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }, f, indent=2)
        except Exception as store_err:
            logger.error(f"[consolidate] Failed to store error: {store_err}")
