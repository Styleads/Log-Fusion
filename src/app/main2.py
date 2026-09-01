"""FastAPI Backend API for Log-Fusion (ULPF) and Auto-Mapping Assistant."""

import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.engine.pipeline import NormalizationPipeline
from src.assistant.service import AutoMappingAssistant

logger = logging.getLogger(__name__)

pipeline: Optional[NormalizationPipeline] = None
assistant: Optional[AutoMappingAssistant] = None


def get_pipeline() -> NormalizationPipeline:
    global pipeline
    if pipeline is None:
        pipeline = NormalizationPipeline()
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
    logger.info("ULPF Normalization Pipeline and Auto-Mapping Assistant initialized.")
    yield


app = FastAPI(
    title="Log-Fusion (ULPF) Normalization & Auto-Mapping API",
    description="Universal Log Pre-processing Framework with declarative YAML mapping and Auto-Mapping Assistant",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware to support local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LineIn(BaseModel):
    raw_line: str


class AssistantAnalyzeRequest(BaseModel):
    source_name: str = Field(..., description="Human-readable name of the log source (e.g. 'SonicWall Firewall')")
    raw_lines: List[str] = Field(..., min_length=1, description="Sample raw log lines from the unknown device")
    device_type: Optional[str] = Field(default=None, description="Optional device hint (firewall, ids, vpn, router, proxy)")
    use_llm: Optional[bool] = Field(default=False, description="Enable local Ollama fallback for ambiguous fields")


class AssistantSaveRequest(BaseModel):
    source_name: str = Field(..., description="Source name used to slugify mapping directory")
    yaml_content: str = Field(..., description="Complete YAML draft content")
    raw_lines: List[str] = Field(..., description="Raw sample lines saved verbatim to synthetic_sample.log")


@app.get("/health")
async def health():
    pipe = get_pipeline()
    asst = get_assistant()
    return {
        "status": "ok",
        "pipeline_loaded": pipe is not None,
        "assistant_loaded": asst is not None,
        "version": "1.0.0",
    }


# ==========================================
# Core Ingestion Endpoints
# ==========================================

@app.post("/api/v1/ingest/line")
async def ingest_line(payload: LineIn):
    pipe = get_pipeline()
    ev = pipe.process_line(payload.raw_line)
    if not ev:
        return {"status": "skipped_or_unrecognized"}
    return {"status": "success", "uid": ev.get("metadata", {}).get("uid"), "event": ev}


# ==========================================
# Auto-Mapping Assistant Endpoints
# ==========================================

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