import os
import logging
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from pydantic import BaseModel
import httpx

from src.engine.pipeline import NormalizationPipeline

logger = logging.getLogger("ulpf.engine_api")

app = FastAPI(
    title="ULPF Log Normalization Engine API",
    version="1.0.0",
    description="Universal Log Pre-processing & OCSF Normalization API",
)

pipeline: Optional[NormalizationPipeline] = None
STORAGE_API_URL = os.getenv("STORAGE_API_URL", "http://storage-api:8000")


class LineIn(BaseModel):
    raw_line: str
    forward_to_storage: Optional[bool] = False


class BatchIn(BaseModel):
    raw_lines: List[str]
    forward_to_storage: Optional[bool] = False


async def _forward_events_to_storage(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Helper to send normalized events to the Storage API."""
    if not events:
        return {"forwarded": 0, "status": "no_events"}
    
    payload = {
        "events": [
            {
                "event_id": ev.get("metadata", {}).get("uid") or ev.get("event_uid", "unknown"),
                "normalized_event": ev,
                "raw_event": ev.get("raw_data", {}),
                "provenance": {
                    "source": "engine_api",
                    "vendor": ev.get("device", {}).get("vendor"),
                },
            }
            for ev in events
            if ev and (ev.get("metadata", {}).get("uid") or ev.get("event_uid"))
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


@app.on_event("startup")
async def startup_event():
    global pipeline
    mappings_path = os.getenv("MAPPINGS_DIR", None)
    pipeline = NormalizationPipeline(mappings_dir_or_loader=mappings_path)
    logger.info("NormalizationPipeline initialized successfully.")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "pipeline_loaded": pipeline is not None,
        "storage_api_url": STORAGE_API_URL,
    }


@app.post("/api/v1/ingest/line")
async def ingest_line(payload: LineIn):
    if pipeline is None:
        raise HTTPException(status_code=500, detail="Pipeline not initialized.")
    ev = pipeline.process_line(payload.raw_line)
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
    if pipeline is None:
        raise HTTPException(status_code=500, detail="Pipeline not initialized.")
    
    events = pipeline.process_lines(payload.raw_lines)
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
    if pipeline is None:
        raise HTTPException(status_code=500, detail="Pipeline not initialized.")
    
    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1")
        
    lines = text.splitlines()
    events = pipeline.process_lines(lines)
    
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