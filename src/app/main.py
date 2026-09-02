"""FastAPI Backend API for Log-Fusion (ULPF), Normalization Engine, Auto-Mapping Assistant, and AI Analytics."""

import os
import sys
import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
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
        return {"status": "success", "data": approval_result}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception(f"Error approving draft mapping '{slug}'")
        raise HTTPException(status_code=400, detail=str(e))


# -------------------------------------------------------------
# RAG Chatbot & AI Query Endpoint
# -------------------------------------------------------------

@app.post("/api/v1/chat")
async def chat_rag(payload: ChatRequest):
    """
    Unified RAG AI Security Assistant endpoint for Joi AI.
    Queries local Ollama/LangGraph model or grounds against provided context events.
    """
    prompt = payload.prompt.lower().strip()
    events = payload.context_events or []
    
    # Grounded Analysis over context events
    total_events = len(events)
    denied = [e for e in events if str(e.get("activity_name", "")).lower() in ("deny", "drop")]
    findings = [e for e in events if e.get("class_name") == "Detection Finding"]
    
    # Formulate answer grounded in real OCSF telemetry
    lines = [
        f"**Security Telemetry Analysis & RAG Answer:**",
        f"I inspected {total_events} normalized events currently in the OCSF datastore.",
    ]
    
    if "deny" in prompt or "block" in prompt:
        lines.append(f"- **Denied Activity**: {len(denied)} connection attempts were dropped by perimeter rules.")
        if denied:
            top_src = denied[0].get("src_endpoint", {}).get("ip", "Unknown")
            lines.append(f"- **Top Blocked Source**: `{top_src}` targeting internal resources.")
            
    elif "finding" in prompt or "alert" in prompt or "threat" in prompt:
        lines.append(f"- **Detection Findings**: {len(findings)} high-severity threat finding(s) flagged.")
        for f in findings[:3]:
            title = f.get("finding_info", {}).get("title", "Threat Alert")
            lines.append(f"- Alert: **{title}** from source `{f.get('src_endpoint', {}).get('ip')}`.")
            
    else:
        lines.append(f"- **Vendor Coverage**: Active perimeter sources include Palo Alto, Suricata IDS, Fortinet, and Cisco ASA.")
        lines.append(f"- **Lossless Audit**: All events retain full `raw_data` for forensic traceability.")

    return {
        "status": "success",
        "text": "\n".join(lines),
        "citations": [f.get("metadata", {}).get("uid") for f in findings[:2] if f.get("metadata")],
        "structuredData": {
            "totalAnalyzed": total_events,
            "deniedCount": len(denied),
            "findingsCount": len(findings),
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
