"""FastAPI Backend API for Log-Fusion (ULPF), Normalization Engine, Auto-Mapping Assistant, and AI Analytics."""

import os
import sys
import re
import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
from fastapi import FastAPI, HTTPException, UploadFile, File, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import httpx

# Add project root and subpackages to sys.path if needed
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.engine.pipeline import NormalizationPipeline
from src.assistant.service import AutoMappingAssistant

# Try importing anomaly detection module
try:
    from anomaly_detection.anomaly_detection import analyze as analyze_anomalies
except ImportError:
    analyze_anomalies = None

logger = logging.getLogger("ulpf.engine_api")

pipeline: Optional[NormalizationPipeline] = None
assistant: Optional[AutoMappingAssistant] = None
STORAGE_API_URL = os.getenv("STORAGE_API_URL", "http://storage-api:8000")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi4-mini")
CHATBOT_FORCE_OLLAMA = os.getenv("CHATBOT_FORCE_OLLAMA", "false").lower() in ("true", "1", "yes")


def get_pipeline() -> NormalizationPipeline:
    global pipeline
    if pipeline is None:
        mappings_path = os.getenv("MAPPINGS_DIR", None)
        pipeline = NormalizationPipeline(mappings_dir_or_loader=mappings_path)
    return pipeline


def get_assistant() -> AutoMappingAssistant:
    global assistant
    if assistant is None:
        assistant = AutoMappingAssistant()
    return assistant


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pipeline, assistant
    pipeline = get_pipeline()
    assistant = get_assistant()
    logger.info("ULPF Normalization Pipeline, Auto-Mapping Assistant, and Unified AI Gateway initialized.")
    yield


app = FastAPI(
    title="Log-Fusion (ULPF) Normalization & Unified AI Gateway API",
    description="Universal Log Pre-processing Framework with declarative YAML mapping, Auto-Mapping Assistant, and AI analytics",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware to support local and docker frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------------------------------------------
# Pydantic Request Models
# -------------------------------------------------------------

class LineIn(BaseModel):
    raw_line: str
    forward_to_storage: Optional[bool] = False


class BatchIn(BaseModel):
    raw_lines: List[str]
    forward_to_storage: Optional[bool] = False


class AssistantAnalyzeRequest(BaseModel):
    source_name: str = Field(..., description="Human-readable name of the log source (e.g. 'SonicWall Firewall')")
    raw_lines: List[str] = Field(..., min_length=1, description="Sample raw log lines from the unknown device")
    device_type: Optional[str] = Field(default=None, description="Optional device hint (firewall, ids, vpn, router, proxy)")
    use_llm: Optional[bool] = Field(default=False, description="Enable local Ollama fallback for ambiguous fields")


class AssistantSaveRequest(BaseModel):
    source_name: str = Field(..., description="Source name used to slugify mapping directory")
    yaml_content: str = Field(..., description="Complete YAML draft content")
    raw_lines: List[str] = Field(..., description="Raw sample lines saved verbatim to synthetic_sample.log")


class ChatRequest(BaseModel):
    prompt: str = Field(..., description="User question or security query")
    context_events: Optional[List[Dict[str, Any]]] = Field(default=None, description="Optional normalized events for grounding")
    force_ollama: Optional[bool] = Field(default=None, description="Force response from Ollama; disable fallback to grounded telemetry engine")
    disable_fallback: Optional[bool] = Field(default=None, description="Alias for force_ollama to disable grounded telemetry engine fallback")


class AnomalyRequest(BaseModel):
    events: Optional[List[Dict[str, Any]]] = Field(default=None, description="Optional list of normalized OCSF events to analyze")


# -------------------------------------------------------------
# Storage Forwarding Helper
# -------------------------------------------------------------

async def _forward_events_to_storage(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Helper to send normalized events to the Storage API."""
    if not events:
        return {"forwarded": 0, "status": "no_events"}
    
    payload = {
        "events": [
            {
                "event_id": ev.get("metadata", {}).get("uid") or ev.get("event_uid") or f"gen-{uuid4()}",
                "normalized_event": ev,
                "raw_event": {"raw_data": ev.get("raw_data")} if isinstance(ev.get("raw_data"), str) else (ev.get("raw_data") or {}),
                "provenance": {
                    "source": "engine_api",
                    "vendor": ev.get("device", {}).get("vendor_name") or ev.get("device", {}).get("vendor") or "unknown",
                },
            }
            for ev in events
            if ev
        ]
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"{STORAGE_API_URL}/events/bulk", json=payload)
            if resp.status_code in (200, 201):
                return resp.json()
            return {"status": "storage_error", "code": resp.status_code, "detail": resp.text}
    except Exception as e:
        logger.warning(f"Failed to forward to storage API: {e}")
        return {"status": "storage_unreachable", "error": str(e)}


# -------------------------------------------------------------
# Health Check Endpoint
# -------------------------------------------------------------

@app.get("/health")
async def health():
    pipe = get_pipeline()
    asst = get_assistant()
    return {
        "status": "ok",
        "pipeline_loaded": pipe is not None,
        "assistant_loaded": asst is not None,
        "storage_api_url": STORAGE_API_URL,
        "version": "1.0.0",
    }


# -------------------------------------------------------------
# Core Ingestion Endpoints
# -------------------------------------------------------------

@app.post("/api/v1/ingest/line")
async def ingest_line(payload: LineIn):
    pipe = get_pipeline()
    ev = pipe.process_line(payload.raw_line)
    if not ev:
        return {"status": "skipped_or_unrecognized"}
    
    result: Dict[str, Any] = {
        "status": "success",
        "uid": ev.get("metadata", {}).get("uid"),
        "event": ev,
    }
    
    if payload.forward_to_storage:
        result["storage_response"] = await _forward_events_to_storage([ev])
        
    return result


@app.post("/api/v1/ingest/batch")
async def ingest_batch(payload: BatchIn):
    pipe = get_pipeline()
    events = pipe.process_lines(payload.raw_lines)
    result: Dict[str, Any] = {
        "status": "success",
        "total_lines": len(payload.raw_lines),
        "normalized_events": len(events),
        "events": events,
    }
    
    if payload.forward_to_storage:
        result["storage_response"] = await _forward_events_to_storage(events)
        
    return result


@app.post("/api/v1/ingest/file")
async def ingest_file(
    file: UploadFile = File(...),
    forward_to_storage: bool = Query(default=False),
):
    pipe = get_pipeline()
    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1")
        
    lines = text.splitlines()
    events = pipe.process_lines(lines)
    
    result: Dict[str, Any] = {
        "status": "success",
        "filename": file.filename,
        "total_lines": len(lines),
        "normalized_events": len(events),
        "events": events,
    }
    
    if forward_to_storage:
        result["storage_response"] = await _forward_events_to_storage(events)
        
    return result


@app.post("/api/v1/events/reset")
@app.delete("/api/v1/events")
async def reset_events_endpoint():
    """Forward reset/wipe request to Storage API."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.delete(f"{STORAGE_API_URL}/events")
            if resp.status_code in (200, 204):
                return resp.json()
            return {"status": "storage_error", "detail": resp.text}
    except Exception as e:
        return {"status": "storage_unreachable", "error": str(e)}


# -------------------------------------------------------------
# Auto-Mapping Assistant Endpoints
# -------------------------------------------------------------

@app.post("/api/v1/assistant/analyze")
async def analyze_unknown_log(payload: AssistantAnalyzeRequest):
    """
    Analyze sample log lines from an unknown perimeter device, infer format & semantics,
    generate draft YAML mapping, validate against live pipeline, and return preview.
    """
    asst = get_assistant()
    try:
        result = asst.analyze(
            source_name=payload.source_name,
            raw_lines=payload.raw_lines,
            device_type_hint=payload.device_type,
            use_llm=payload.use_llm,
        )
        return {"status": "success", "data": result}
    except Exception as e:
        logger.exception("Error in assistant analysis")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/assistant/save")
async def save_draft_mapping(payload: AssistantSaveRequest):
    """
    Save the draft mapping configuration and synthetic sample log under mappings/<slug>/.
    Guards against overwriting reviewed production configs.
    """
    asst = get_assistant()
    try:
        save_result = asst.save_draft(
            source_name=payload.source_name,
            yaml_content=payload.yaml_content,
            raw_lines=payload.raw_lines,
        )
        return {"status": "success", "data": save_result}
    except Exception as e:
        logger.exception("Error saving draft mapping")
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/assistant/drafts")
async def list_draft_mappings():
    """
    List all draft mapping configurations that are pending human review.
    """
    asst = get_assistant()
    try:
        drafts = asst.list_drafts()
        return {"status": "success", "count": len(drafts), "drafts": drafts}
    except Exception as e:
        logger.exception("Error listing draft mappings")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/assistant/approve/{slug}")
async def approve_draft_mapping(slug: str):
    """
    Approve an auto-generated draft configuration: updates status to 'reviewed'
    and replaces the draft warning banner with the approved production header.
    """
    asst = get_assistant()
    pipe = get_pipeline()
    try:
        approval_result = asst.approve_draft(slug)
        # Reload pipeline mapping configs so approved source is immediately active
        pipe.loader.reload()
        pipe.detector = pipe.detector.__class__(pipe.loader)
        pipe._components_cache.clear()
        return {"status": "success", "data": approval_result}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception(f"Error approving draft mapping '{slug}'")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/reload")
async def reload_mappings():
    """Reload all mapping configurations and clear component caches."""
    pipe = get_pipeline()
    configs = pipe.loader.reload()
    pipe.detector = pipe.detector.__class__(pipe.loader)
    pipe._components_cache.clear()
    return {"status": "success", "active_configs": len(configs)}


# -------------------------------------------------------------
# RAG Chatbot & AI Query Endpoint
# -------------------------------------------------------------

def is_denied_event(e: Dict[str, Any]) -> bool:
    act_name = str(e.get("activity_name", "") or "").lower()
    act_id = e.get("activity_id")
    raw = str(e.get("raw_data", "") or "").lower()
    act_obj = e.get("activity")
    action = str(act_obj.get("action", "") if isinstance(act_obj, dict) else (e.get("action") or "")).lower()
    disposition = str(e.get("disposition", "") or "").lower()

    if act_name in ("deny", "drop", "block", "reject", "reset"):
        return True
    if act_id in (5, 6):
        return True
    if action in ("deny", "drop", "block", "reject", "reset"):
        return True
    if disposition in ("blocked", "dropped", "denied"):
        return True
    if any(k in raw for k in (" drop ", " deny ", " blocked ", ",drop,", ",deny,")):
        return True
    return False


def is_allowed_event(e: Dict[str, Any]) -> bool:
    act_name = str(e.get("activity_name", "") or "").lower()
    act_id = e.get("activity_id")
    raw = str(e.get("raw_data", "") or "").lower()
    act_obj = e.get("activity")
    action = str(act_obj.get("action", "") if isinstance(act_obj, dict) else (e.get("action") or "")).lower()
    disposition = str(e.get("disposition", "") or "").lower()

    if act_name in ("allow", "permit", "pass", "accept"):
        return True
    if act_id in (1, 2, 3):
        return True
    if action in ("allow", "permit", "pass", "accept"):
        return True
    if disposition in ("allowed", "permitted", "passed"):
        return True
    if any(k in raw for k in (" allow ", " permit ", " pass ", ",allow,")):
        return True
    return False


STOPWORDS = {
    "was", "is", "are", "were", "any", "the", "a", "an", "detected", "detection",
    "in", "on", "at", "to", "for", "from", "by", "with", "there", "did", "we",
    "see", "show", "me", "tell", "about", "what", "which", "where", "who", "how",
    "many", "please", "can", "you", "find", "get", "give", "of", "and", "or",
    "not", "have", "been", "has", "it", "they", "this", "that", "event", "events",
    "log", "logs", "traffic", "request", "requests", "question", "answer", "check"
}


def is_finding_event(e: Dict[str, Any]) -> bool:
    """Check if an event represents a security finding, detection, or IDS alert."""
    class_name = str(e.get("class_name", "")).lower()
    class_uid = e.get("class_uid")
    raw = str(e.get("raw_data", "")).lower()

    if class_name in ("detection finding", "security finding", "network detection", "incident finding"):
        return True
    if class_uid in (2001, 2004, 2005):
        return True
    if "detection" in e and isinstance(e["detection"], dict) and e["detection"]:
        return True
    if "finding_info" in e and isinstance(e["finding_info"], dict) and e["finding_info"]:
        return True
    if '"event_type":"alert"' in raw or '"event_type": "alert"' in raw or '"alert":{' in raw:
        return True
    return False


def normalize_token(t: str) -> str:
    """Stem common plurals and suffixes for robust threat and entity matching."""
    t = t.lower().strip()
    if t.endswith("ies") and len(t) > 4:
        return t[:-3] + "y"
    if t.endswith("es") and len(t) > 4 and t not in ("cves", "bytes"):
        return t[:-2]
    if t.endswith("s") and len(t) > 3 and not t.endswith("ss") and t not in ("cves", "c2s"):
        return t[:-1]
    if t.endswith("ing") and len(t) > 5:
        return t[:-3]
    if t.endswith("ed") and len(t) > 4:
        return t[:-2]
    return t


def extract_search_terms(prompt: str) -> List[str]:
    """Extract semantic search terms from analyst prompt by filtering stop words and stemming plurals."""
    tokens = re.findall(r'[a-zA-Z0-9_\.\-]+', prompt.lower())
    terms: List[str] = []
    for t in tokens:
        if t in STOPWORDS or len(t) <= 2:
            continue
        stem = normalize_token(t)
        if stem in STOPWORDS:
            continue
        terms.append(stem)
        if stem != t:
            terms.append(t)
    return list(dict.fromkeys(terms))


def event_matches_terms(event: Dict[str, Any], terms: List[str]) -> bool:
    """Checks if any search term or its stem appears in the event's raw or normalized fields."""
    if not terms:
        return False

    raw = str(event.get("raw_data", "")).lower()
    detection = event.get("detection", {})
    finding = event.get("finding_info", {})
    policy = event.get("policy", {}) or event.get("firewall_rule", {})
    src_ip = str(event.get("src_endpoint", {}).get("ip", "")).lower()
    dst_ip = str(event.get("dst_endpoint", {}).get("ip", "")).lower()
    src_port = str(event.get("src_endpoint", {}).get("port", ""))
    dst_port = str(event.get("dst_endpoint", {}).get("port", ""))
    msg = str(event.get("message", "")).lower()
    class_name = str(event.get("class_name", "")).lower()
    act_name = str(event.get("activity_name", "")).lower()

    search_corpus = " ".join([
        raw,
        str(detection).lower(),
        str(finding).lower(),
        str(policy).lower(),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        msg,
        class_name,
        act_name
    ])

    for term in terms:
        stem = normalize_token(term)
        if term in search_corpus or stem in search_corpus:
            return True
        for word in re.findall(r'[a-zA-Z0-9_\.\-]+', search_corpus):
            if normalize_token(word) == stem or stem in word:
                if len(stem) >= 3:
                    return True

    return False


def extract_threat_info(e: Dict[str, Any]) -> Dict[str, Any]:
    """Extract forensic incident details from a normalized or raw security event."""
    detection = e.get("detection") or {}
    finding = e.get("finding_info") or {}
    raw = str(e.get("raw_data", ""))

    # Category
    category = detection.get("category") or finding.get("category")
    if not category and "category" in raw:
        m = re.search(r'"category"\s*:\s*"([^"]+)"', raw)
        if m:
            category = m.group(1)
    if not category:
        category = e.get("class_name", "Security Alert")

    # Signature / Title
    title = detection.get("signature") or finding.get("title")
    if not title and "signature" in raw:
        m = re.search(r'"signature"\s*:\s*"([^"]+)"', raw)
        if m:
            title = m.group(1)
    if not title:
        title = e.get("message") or e.get("activity_name") or "Threat Finding"

    # Severity
    sev = detection.get("severity") or e.get("severity") or e.get("severity_id")
    if not sev and "severity" in raw:
        m = re.search(r'"severity"\s*:\s*([0-9]+)', raw)
        if m:
            sev = m.group(1)
    if str(sev) == "1":
        sev_label = "Critical (Severity 1)"
    elif str(sev) == "2":
        sev_label = "High (Severity 2)"
    elif str(sev) == "3":
        sev_label = "Medium (Severity 3)"
    else:
        sev_label = str(sev or "High")

    # Signature ID
    sig_id = detection.get("signature_id") or finding.get("uid")
    if not sig_id and "signature_id" in raw:
        m = re.search(r'"signature_id"\s*:\s*([0-9]+)', raw)
        if m:
            sig_id = m.group(1)

    # Source & Dest
    src_ip = e.get("src_endpoint", {}).get("ip") or "Unknown"
    src_port = e.get("src_endpoint", {}).get("port")
    src_str = f"{src_ip}:{src_port}" if src_port else src_ip

    dst_ip = e.get("dst_endpoint", {}).get("ip") or "Unknown"
    dst_port = e.get("dst_endpoint", {}).get("port")
    dst_str = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

    # Vendor / Sensor & Action
    vendor = e.get("device", {}).get("vendor_name") or e.get("device", {}).get("vendor") or "IDS/Firewall"
    action = e.get("activity_name") or detection.get("action") or ("Allowed" if is_allowed_event(e) else "Blocked")
    proto = e.get("connection_info", {}).get("protocol_name") or "TCP"

    return {
        "title": title,
        "category": category,
        "severity": sev_label,
        "sig_id": sig_id,
        "src": src_str,
        "dst": dst_str,
        "vendor": vendor,
        "action": action,
        "protocol": proto,
    }


def _build_citation(e: Dict[str, Any]) -> Dict[str, Any]:
    uid = e.get("metadata", {}).get("uid") or e.get("event_uid") or str(uuid4())
    vendor = e.get("device", {}).get("vendor_name") or e.get("device", {}).get("vendor") or "Security Gateway"
    class_name = e.get("class_name", "Network Activity")
    act_name = e.get("activity_name") or e.get("severity") or "Activity"
    src_ip = e.get("src_endpoint", {}).get("ip") or "unknown"
    dst_ip = e.get("dst_endpoint", {}).get("ip") or "unknown"
    dst_port = e.get("dst_endpoint", {}).get("port")
    port_str = f":{dst_port}" if dst_port else ""

    return {
        "event_uid": uid,
        "vendor": vendor,
        "class_name": class_name,
        "summary": f"{class_name} · {act_name} ({src_ip} -> {dst_ip}{port_str})",
        "timestamp": e.get("time", ""),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "activity_name": act_name,
    }


async def _query_ollama(
    user_prompt: str,
    context_summary: str,
    timeout_seconds: float = 25.0,
    connect_timeout: float = 1.0,
) -> Tuple[Optional[str], Optional[str]]:
    """Query local or containerized Ollama server if available, returning (response_text, error_detail)."""
    candidate_urls = [OLLAMA_BASE_URL]
    for url in ("http://ollama:11434", "http://host.docker.internal:11434", "http://localhost:11434"):
        if url not in candidate_urls:
            candidate_urls.append(url)

    prompt = (
        "You are Joi, an expert AI Security Operations Analyst grounded in normalized OCSF v1.1.0 telemetry.\n"
        "Analyze the following security telemetry context and use your cybersecurity expertise to answer the analyst's question.\n"
        "Guidelines:\n"
        "- Base specific telemetry facts (counts, IPs, ports, alerts, rules) strictly on the context provided below.\n"
        "- If the analyst asks for incident response advice, remediation steps, or how to handle a threat (e.g. 'how to deal with a trojan'), provide actionable, structured SOC guidance.\n"
        "- Be concise, direct, professional, and well-structured using markdown.\n\n"
        f"--- REAL OCSF TELEMETRY CONTEXT ---\n{context_summary}\n-----------------------------------\n\n"
        f"Analyst Question: {user_prompt}\n\nAnswer:"
    )

    req_timeout = httpx.Timeout(timeout=timeout_seconds, connect=connect_timeout)
    last_error: Optional[str] = None

    for base_url in candidate_urls:
        endpoint = f"{base_url.rstrip('/')}/api/generate"
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
        }
        try:
            async with httpx.AsyncClient(timeout=req_timeout) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    res_text = data.get("response", "").strip()
                    if res_text:
                        return res_text, None
                    last_error = f"{endpoint} returned HTTP 200 but empty response content."
                else:
                    last_error = f"{endpoint} returned HTTP {resp.status_code}: {resp.text}"
        except Exception as exc:
            last_error = f"Failed connecting to {endpoint}: {exc}"
            continue

    return None, (last_error or f"Unable to reach any Ollama endpoint in {candidate_urls}")


@app.post("/api/v1/chat")
async def chat_rag(payload: ChatRequest):
    """
    Unified RAG AI Security Assistant endpoint for Joi AI.
    Queries local Ollama/LangGraph model or grounds against provided context events.
    """
    prompt = payload.prompt.lower().strip()
    events = payload.context_events or []

    # If no context events provided in payload, attempt fetch from Storage API (OpenSearch)
    if not events:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{STORAGE_API_URL}/events/search?limit=500")
                if resp.status_code == 200:
                    data = resp.json()
                    raw_hits = data.get("events", [])
                    events = [h.get("normalized_event", h) for h in raw_hits]
        except Exception:
            pass

    total_events = len(events)
    denied = [e for e in events if is_denied_event(e)]
    allowed = [e for e in events if is_allowed_event(e)]
    findings = [e for e in events if is_finding_event(e)]

    # Compute vendor distribution
    vendor_counts: Dict[str, int] = {}
    for e in events:
        v = e.get("device", {}).get("vendor_name") or e.get("device", {}).get("vendor") or "Unknown"
        vendor_counts[v] = vendor_counts.get(v, 0) + 1

    # Compute top blocked source IPs
    blocked_src_counts: Dict[str, int] = {}
    for e in denied:
        ip = e.get("src_endpoint", {}).get("ip") or "Unknown"
        blocked_src_counts[ip] = blocked_src_counts.get(ip, 0) + 1

    # Compute top allowed destinations
    allowed_dst_counts: Dict[str, int] = {}
    for e in allowed:
        dst = f"{e.get('dst_endpoint', {}).get('ip', 'Host')}:{e.get('dst_endpoint', {}).get('port', '')}"
        allowed_dst_counts[dst] = allowed_dst_counts.get(dst, 0) + 1

    pct_allow = round((len(allowed) / max(total_events, 1)) * 100, 1)
    pct_deny = round((len(denied) / max(total_events, 1)) * 100, 1)

    # ---------------------------------------------------------
    # 1. Targeted Entity / Threat Search Query Detection
    # ---------------------------------------------------------
    search_terms = extract_search_terms(prompt)
    threat_search_terms = [
        t for t in search_terms
        if t not in ("allowed", "permit", "blocked", "denied", "dropped", "total", "summary", "overview", "volume", "active", "threat", "threats", "alert", "alerts", "finding", "findings")
    ]

    is_volumetric_query = any(w in prompt for w in ("how many", "total", "count of", "overview", "summary", "volume")) and not any(
        w in prompt for w in ("trojan", "malware", "botnet", "virus", "ransomware", "worm", "c2", "exploit", "cve", "password", "leak")
    )
    is_general_finding_query = any(w in prompt for w in ("finding", "findings", "alert", "alerts", "threat alert")) and not threat_search_terms

    matching_threat_events = [e for e in events if event_matches_terms(e, threat_search_terms)] if (threat_search_terms and not is_general_finding_query) else []

    # Format telemetry summary for Ollama
    context_summary = (
        f"Total Ingested Events: {total_events}\n"
        f"Allowed Requests: {len(allowed)} ({pct_allow}%)\n"
        f"Denied/Dropped Requests: {len(denied)} ({pct_deny}%)\n"
        f"Detection Findings / Alerts: {len(findings)}\n"
        f"Active Vendors: {vendor_counts}\n"
        f"Top Blocked Source IPs: {dict(sorted(blocked_src_counts.items(), key=lambda x: x[1], reverse=True)[:5])}\n"
        f"Top Allowed Destinations: {dict(sorted(allowed_dst_counts.items(), key=lambda x: x[1], reverse=True)[:5])}\n"
    )

    if threat_search_terms:
        if matching_threat_events:
            match_summaries = []
            for ev in matching_threat_events[:5]:
                ti = extract_threat_info(ev)
                match_summaries.append(
                    f"- Threat Incident: {ti['category']} | Signature: {ti['title']} | Severity: {ti['severity']} | "
                    f"Src: {ti['src']} -> Dst: {ti['dst']} | Action: {ti['action']} | Sensor: {ti['vendor']}"
                )
            context_summary += "\nMatching Threat Telemetry:\n" + "\n".join(match_summaries)
        else:
            context_summary += f"\nNote: Zero events in the OCSF datastore matched search terms: {threat_search_terms}"

    effective_force_ollama = (
        payload.force_ollama
        if payload.force_ollama is not None
        else (payload.disable_fallback if payload.disable_fallback is not None else CHATBOT_FORCE_OLLAMA)
    )

    # Try querying local Ollama LLM if reachable (5.0s connect timeout in forced mode, 1.0s in fallback mode)
    conn_timeout = 5.0 if effective_force_ollama else 1.0
    llm_answer, llm_error = await _query_ollama(
        payload.prompt, context_summary, timeout_seconds=25.0, connect_timeout=conn_timeout
    )
    if llm_answer:
        cite_events = matching_threat_events if matching_threat_events else (
            findings if any(w in prompt for w in ("finding", "alert", "threat")) else (
                denied if any(w in prompt for w in ("deny", "block", "drop")) else (
                    allowed if any(w in prompt for w in ("allow", "permit", "pass")) else events
                )
            )
        )
        return {
            "status": "success",
            "source": "ollama_llm",
            "text": llm_answer,
            "citations": [_build_citation(ev) for ev in cite_events[:4]],
            "structuredData": {
                "totalAnalyzed": total_events,
                "matchedCount": len(matching_threat_events),
                "allowedCount": len(allowed),
                "deniedCount": len(denied),
                "findingsCount": len(findings),
                "vendors": vendor_counts,
            }
        }

    # If fallback to grounded telemetry is disabled and Ollama was forced, fail fast with 503
    if effective_force_ollama:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Ollama LLM generation failed or service unreachable",
                "details": llm_error or "All candidate Ollama endpoints failed to respond.",
                "model": OLLAMA_MODEL,
                "fallback_disabled": True,
                "source": "ollama_llm",
            },
        )

    # ---------------------------------------------------------
    # 2. Grounded Threat Search Engine Fallback
    # ---------------------------------------------------------
    # If the user asked a targeted threat / signature / entity question (not a pure volumetric count)
    if threat_search_terms and not is_volumetric_query:
        if matching_threat_events:
            lines = [
                f"### 🚨 Security Telemetry Analysis: Detected Threats matching '{', '.join(threat_search_terms)}'",
                f"**Yes**, I detected **{len(matching_threat_events)} matching security event(s)** in the normalized OCSF datastore:\n",
            ]
            for idx, ev in enumerate(matching_threat_events[:3], 1):
                ti = extract_threat_info(ev)
                sig_note = f" (Signature ID: `{ti['sig_id']}`)" if ti['sig_id'] else ""
                lines.append(f"**Incident #{idx}: {ti['category']}**")
                lines.append(f"- **Signature**: **{ti['title']}**{sig_note}")
                lines.append(f"- **Severity**: {ti['severity']}")
                lines.append(f"- **Connection**: `{ti['src']}` $\\rightarrow$ `{ti['dst']}` ({ti['protocol']})")
                lines.append(f"- **Perimeter Sensor**: {ti['vendor']}")
                lines.append(f"- **Policy Action**: `{ti['action']}`\n")

            # Targeted Threat Guidance
            if any(k in " ".join(threat_search_terms) for k in ("trojan", "botnet", "c2", "malware", "virus")):
                lines.append("**SOC Forensics & Assessment**:")
                lines.append("- An internal endpoint initiated communications matching a known Trojan/Botnet Command and Control signature.")
                lines.append("- If the policy action was **allowed**, this indicates malware beaconing that bypassed perimeter drops.")
                lines.append("- **Recommended Action**: Isolate the internal source host, review endpoint process trees, and block destination C2 IP/Port at upstream firewalls.")

            return {
                "status": "success",
                "source": "grounded_telemetry",
                "text": "\n".join(lines),
                "citations": [_build_citation(ev) for ev in matching_threat_events[:4]],
                "structuredData": {
                    "totalAnalyzed": total_events,
                    "matchedCount": len(matching_threat_events),
                    "searchTerms": threat_search_terms,
                    "findingsCount": len(findings),
                }
            }
        else:
            # Explicit negative match
            lines = [
                f"### 🔍 Threat Telemetry Analysis: '{', '.join(threat_search_terms)}'",
                f"**No**, no events or alerts matching **'{', '.join(threat_search_terms)}'** were found across the **{total_events} normalized events** currently in the OCSF datastore.\n",
                f"- **Total Inspected Events**: {total_events}",
                f"- **Active Detection Findings**: {len(findings)}",
                f"- **Active Perimeter Sources**: {', '.join(vendor_counts.keys()) or 'Multi-vendor'}\n",
                "You can query active perimeter threats like:",
                '- *"Show all active detection findings"*',
                '- *"Any repeated SSH brute force scans?"*',
                '- *"How many blocked requests?"*',
            ]
            return {
                "status": "success",
                "source": "grounded_telemetry",
                "text": "\n".join(lines),
                "citations": [_build_citation(ev) for ev in findings[:4]],
                "structuredData": {
                    "totalAnalyzed": total_events,
                    "matchedCount": 0,
                    "searchTerms": threat_search_terms,
                    "findingsCount": len(findings),
                }
            }

    # ---------------------------------------------------------
    # 3. Volumetric & Aggregation Engine
    # ---------------------------------------------------------
    lines = [
        "**Security Telemetry Analysis & RAG Answer:**",
        f"I inspected **{total_events} normalized events** currently in the OCSF datastore.",
    ]
    relevant_events = events

    if any(w in prompt for w in ("deny", "block", "drop", "reject")):
        lines.append(f"- **Denied / Blocked Activity**: **{len(denied)} connection attempts ({pct_deny}%)** were dropped by perimeter rules.")
        if blocked_src_counts:
            top_blocks = sorted(blocked_src_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            top_str = ", ".join(f"`{ip}` ({cnt} blocks)" for ip, cnt in top_blocks)
            lines.append(f"- **Top Blocked Sources**: {top_str}")
        relevant_events = denied

    elif any(w in prompt for w in ("allow", "permit", "pass", "accept")):
        lines.append(f"- **Allowed Activity**: **{len(allowed)} connection requests ({pct_allow}%)** were permitted by perimeter firewall policies.")
        if allowed_dst_counts:
            top_allowed = sorted(allowed_dst_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            top_str = ", ".join(f"`{dst}` ({cnt} sessions)" for dst, cnt in top_allowed)
            lines.append(f"- **Top Permitted Destinations**: {top_str}")
        relevant_events = allowed

    elif any(w in prompt for w in ("finding", "alert", "threat", "vuln", "attack")):
        lines.append(f"- **Detection Findings**: **{len(findings)} security finding(s)** flagged across perimeter IDS sensors.")
        for f in findings[:3]:
            ti = extract_threat_info(f)
            lines.append(f"- Alert: **{ti['title']}** [{ti['severity']}] on `{ti['src']}` $\\rightarrow$ `{ti['dst']}`.")
        relevant_events = findings

    elif any(w in prompt for w in ("vendor", "source", "coverage", "device")):
        lines.append(f"- **Vendor Coverage**: Telemetry is actively ingested across **{len(vendor_counts)} vendor source(s)**:")
        for v, cnt in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  - **{v}**: {cnt} normalized events")
        lines.append("- **Lossless Audit**: All events retain full `raw_data` for forensic traceability.")

    elif any(w in prompt for w in ("how many", "total", "count", "summary", "overview", "all")):
        lines.append(f"- **Allowed Traffic**: **{len(allowed)}** requests ({pct_allow}%)")
        lines.append(f"- **Blocked / Dropped**: **{len(denied)}** requests ({pct_deny}%)")
        lines.append(f"- **Security Findings**: **{len(findings)}** alert(s)")
        lines.append(f"- **Active Sources**: {', '.join(vendor_counts.keys())}")

    else:
        # Balanced overview
        lines.append(f"- **Allowed Requests**: **{len(allowed)}** ({pct_allow}%)")
        lines.append(f"- **Denied / Dropped**: **{len(denied)}** ({pct_deny}%)")
        lines.append(f"- **Security Findings**: **{len(findings)}** active alerts")
        lines.append(f"- **Vendor Coverage**: {', '.join(vendor_counts.keys()) or 'Multi-vendor'}")

    return {
        "status": "success",
        "source": "grounded_telemetry",
        "text": "\n".join(lines),
        "citations": [_build_citation(ev) for ev in relevant_events[:4]],
        "structuredData": {
            "totalAnalyzed": total_events,
            "allowedCount": len(allowed),
            "deniedCount": len(denied),
            "findingsCount": len(findings),
            "vendors": vendor_counts,
        }
    }


# -------------------------------------------------------------
# Anomaly Detection Endpoint
# -------------------------------------------------------------

@app.post("/api/v1/anomalies/run")
async def run_anomaly_detection(payload: AnomalyRequest):
    """
    Execute rule-based and statistical threat analytics across normalized events.
    """
    if analyze_anomalies is None:
        return {"status": "error", "message": "Anomaly detection module not installed."}

    events = payload.events
    if not events:
        # Generate default sample set from pipeline
        pipe = get_pipeline()
        sample_path = os.path.join(ROOT_DIR, "mappings", "windows_firewall", "samples", "windows_firewall_sample.log")
        if os.path.exists(sample_path):
            events = pipe.process_file(sample_path)
        else:
            events = []

    try:
        anomalies = analyze_anomalies(events)
        return {
            "status": "success",
            "count": len(anomalies),
            "anomalies": anomalies,
        }
    except Exception as e:
        logger.exception("Error running anomaly detection")
        raise HTTPException(status_code=400, detail=str(e))
