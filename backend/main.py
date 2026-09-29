from __future__ import annotations
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .engine import DefenseEngine, RAG_DOCUMENTS, CANARY_TOKEN, DEFAULT_CONFIG

ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="DEFEND-LLM Security Engine", version="3.0.0", description="Educational prompt-injection defense testbench")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
engine = DefenseEngine()

class ScanRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=6000)
    document: str = "clean_expense"
    defenses: bool = True

class ConfigRequest(BaseModel):
    input_regex: str | None = None
    secret_regex: str | None = None
    max_prompt_chars: int | None = Field(default=None, ge=100, le=20000)
    enable_base64_detection: bool | None = None

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "DEFEND-LLM", "version": app.version}

@app.get("/api/config")
def config():
    safe = dict(engine.config)
    safe["canary_token"] = "[HIDDEN]"
    return safe

@app.post("/api/config")
def update_config(req: ConfigRequest):
    data = req.model_dump(exclude_none=True)
    engine.config.update(data)
    return {"status": "updated", "config": {**engine.config, "canary_token": "[HIDDEN]"}}

@app.get("/api/documents")
def documents():
    return {k: {"title": v["title"], "status": v["status"], "content": v["content"]} for k, v in RAG_DOCUMENTS.items()}

@app.post("/api/scan")
def scan(req: ScanRequest):
    try:
        return engine.run(req.prompt, req.document, req.defenses)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/api/benchmark")
def benchmark():
    return engine.benchmark()

@app.get("/api/metrics")
def metrics():
    return {**engine.metrics, "incident_count": len(engine.incidents)}

@app.get("/api/incidents")
def incidents():
    return {"incidents": [i.__dict__ for i in engine.incidents]}

@app.get("/api/about")
def about():
    return {"project": "DEFEND-LLM", "version": app.version, "layers": ["Input Filter", "Prompt Isolation", "Model Simulation", "Canary & Secret Monitor"], "canary": "[HIDDEN]", "scope": "Local educational security simulation"}

app.mount("/", StaticFiles(directory=str(ROOT / "frontend"), html=True), name="frontend")
