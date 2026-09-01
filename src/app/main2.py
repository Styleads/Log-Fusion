# app/main.py
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Optional
import logging

# Import the pipeline used by your CLI
from src.engine.pipeline import NormalizationPipeline

app = FastAPI(title="Log-Fusion Ingest API")
pipeline: Optional[NormalizationPipeline] = None

class LineIn(BaseModel):
    raw_line: str

@app.on_event("startup")
async def startup_event():
    global pipeline
    pipeline = NormalizationPipeline()

@app.get("/health")
async def health():
    return {"status": "ok", "pipeline_loaded": pipeline is not None}

@app.post("/api/v1/ingest/line")
async def ingest_line(payload: LineIn):
    if pipeline is None:
        raise HTTPException(status_code=500, detail="Pipeline not initialized.")
    ev = pipeline.process_line(payload.raw_line)
    if not ev:
        return {"status": "skipped_or_unrecognized"}
    return {"status": "success", "uid": ev.get("metadata", {}).get("uid"), "event": ev}