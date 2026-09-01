# Work Report — FastAPI integration for Log‑Fusion (ULPF)



## Executive summary
This work integrates a small FastAPI-based ingestion API that wraps the existing NormalizationPipeline in `src.engine.pipeline`. The API exposes a health endpoint and an endpoint to ingest single raw log lines. The service runs with Uvicorn in development and initializes the pipeline at application startup. The work included environment setup guidance, dependency fixes, packaging/import fixes so imports resolve, and step-by-step troubleshooting notes.

Current API (as committed locally)
- src/app/main2.py
  - GET /health
  - POST /api/v1/ingest/line  (expects JSON {"raw_line": "<log-line>"})

## Files created / changed
- Created (local dev)
  - src/app/main2.py
  - src/app/__init__.py (required to make `src.app` a package)
- No other repo source files were modified by this integration during local work (unless you commit these new files).

Content summary of src/app/main2.py
- Imports `NormalizationPipeline` from `src.engine.pipeline` (this is the same pipeline the CLI uses in `src/main.py`).
- Creates a FastAPI app.
- On startup initializes a single pipeline instance:
  pipeline = NormalizationPipeline()
- Exposes:
  - GET /health -> reports whether pipeline_loaded is True
  - POST /api/v1/ingest/line -> calls pipeline.process_line(raw_line) and returns the normalized event (or a skipped response if None)

(Full source of `src/app/main2.py` is available in the repository at src/app/main2.py.)

## Environment setup performed (and recommended)
1. Create a virtual environment:
   - Linux/macOS:
     - python3 -m venv .venv
     - source .venv/bin/activate
   - Windows (PowerShell):
     - python -m venv .venv
     - .\.venv\Scripts\Activate.ps1

2. Install project dependencies:
   - pip install -r requirements.txt
   - (requirements.txt in repo contains pyyaml, pytest and others.)

3. Install local package in editable mode so `from src.engine.pipeline import ...` resolves cleanly:
   - pip install -e .

4. If not using pip install -e ., set PYTHONPATH:
   - export PYTHONPATH="$(pwd):$PYTHONPATH" (Linux/macOS)
   - $env:PYTHONPATH = "${PWD};$env:PYTHONPATH" (PowerShell)

## How I ran the API during development
From the repository root with the `.venv` activated, run:

- Start server:
  - python -m uvicorn src.app.main2:app --reload --host 0.0.0.0 --port 8000

(Using `python -m uvicorn` ensures the venv interpreter is used, avoiding import mismatches.)

## How to use the API (examples)

1. Health
- curl http://127.0.0.1:8000/health
- Expected:
  - {"status": "ok", "pipeline_loaded": true}

2. Ingest a single line
- curl -X POST "http://127.0.0.1:8000/api/v1/ingest/line" \
  -H "Content-Type: application/json" \
  -d '{"raw_line":"<SAMPLE_RAW_LOG_LINE>"}'

- Expected responses:
  - If pipeline returns an event:
    - {"status":"success","uid":"<uid>","event": { ...normalized event... }}
  - If the raw line doesn't match any mapping:
    - {"status":"skipped_or_unrecognized"}

Notes:
- Use the interactive docs at http://127.0.0.1:8000/docs to try the POST operation and confirm payload format.

## Direct pipeline tests (useful to isolate API vs pipeline issues)
Run these from the same venv:

- Quick import and call:
  python -c "from src.engine.pipeline import NormalizationPipeline; p=NormalizationPipeline(); print(p.process_line('YOUR_SAMPLE_LOG_LINE'))"

- Run CLI to process a file:
  python -m src.main mappings/windows_firewall/samples/windows_firewall_sample.log --pretty

## Troubleshooting log of issues encountered and how they were resolved
1. ModuleNotFoundError: No module named 'app' or module not found for FastAPI app
   - Cause: The `app` module path given to uvicorn did not match the file location or the module was not a package.
   - Fixes applied:
     - Created `src/app/__init__.py` so `src.app` is an importable package.
     - Used the module path `src.app.main2:app` and started uvicorn via `python -m uvicorn ...` to ensure the same interpreter is used.

2. ModuleNotFoundError: No module named 'yaml'
   - Cause: PyYAML was not installed in the active venv. `src.engine.config_loader` loads YAML mappings and imports `yaml`.
   - Fix: pip install -r requirements.txt (or pip install PyYAML).
   - Verified by running `python -c "import yaml; print(yaml.__version__)"`.

3. HTTP 405 Method Not Allowed when testing the endpoint
   - Cause: Using GET in browser address bar or wrong method/path. The ingest endpoint expects POST with JSON.
   - Fix: Use POST with JSON body. Confirmed via curl and /docs.

4. pipeline.process_line returned None
   - Cause: The pipeline returns None for raw lines it does not recognize according to mapping rules. This is expected behavior for some inputs.
   - Fix: Use a sample line known to be supported by mappings or add new mapping YAML under /mappings.

5. Import-time errors while running uvicorn
   - Used a helper import test command to print the full traceback:
     - python -c "import importlib,traceback; try: importlib.import_module('src.app.main2'); print('OK') ; except Exception: traceback.print_exc()"

## What I validated
- The FastAPI app starts up and the NormalizationPipeline instance is created at startup.
- The /health endpoint returns the expected pipeline_loaded flag.
- POST /api/v1/ingest/line triggers the pipeline and returns either the normalized event or skipped status.
- Requirements include PyYAML (pyyaml>=6.0), fastapi, uvicorn, pydantic, python-multipart, aiofiles etc. Installing requirements removes import errors.

## Known limitations & outstanding items
- Only single-line ingestion endpoint implemented in src/app/main2.py. The file upload endpoint that was discussed earlier is not present in the committed file. If bulk ingestion is needed, add a multipart file endpoint and a streaming processor.
- No storage integration is implemented. The API returns normalized events but does not persist them. A `store_event()` integration (Elasticsearch/Opensearch, Kafka, S3, DB) should be added.
- No authentication, rate-limiting, CORS, or input throttling is in place — add for production readiness.
- No CI/CD or Dockerfile committed as part of this change. A sample Dockerfile and docker-compose can be added to facilitate deployments.
- Logging is minimal; consider structured logs and error reporting.

## Recommendations / next steps
1. Add persistence:
   - Implement store_event() to push normalized events to Elasticsearch/Kafka/DB; consider async I/O for scalability.

2. Bulk ingestion and streaming:
   - Add POST /api/v1/ingest/file accepting multipart upload and streaming processing (line-by-line).
   - Add a background job queue for heavy workloads: Celery, RQ, Kafka consumers, or worker pool.

3. Production deployment:
   - Add Dockerfile and docker-compose for local dev and staging.
   - Use Gunicorn with Uvicorn workers:
     - gunicorn -k uvicorn.workers.UvicornWorker -w 4 src.app.main2:app
   - Add health/liveness/readiness endpoints for orchestration.
   - Add an NGINX reverse proxy in front of the app for TLS and static handling if needed.

4. Security:
   - Add authentication (API key, JWT, OAuth).
   - Add input validation, rate-limiting (fastapi-limiter or a proxy rate limiter), and proper CORS settings.

5. Tests:
   - Add FastAPI TestClient tests to exercise the API endpoints (unit tests for pipeline usage).
   - Add integration tests that validate full pipeline + storage.

6. Observability:
   - Add structured logging and optionally metrics (Prometheus exporter) and error monitoring (Sentry).

7. Package & release:
   - Ensure the packaging metadata (pyproject.toml/setup.cfg) is present so `pip install -e .` behaves predictably.
   - Pin production dependency versions.

## Exact commands run during development (recap)
- Create venv and activate:
  - python -m venv .venv
  - .\.venv\Scripts\Activate.ps1  (Windows PowerShell)
- Install deps:
  - pip install -r requirements.txt
  - pip install -e .
- Make package importable:
  - New-Item -Path .\src\app\__init__.py -ItemType File -Force
- Start server:
  - python -m uvicorn src.app.main2:app --reload --host 0.0.0.0 --port 8000
- Direct pipeline debug:
  - python -c "from src.engine.pipeline import NormalizationPipeline; p=NormalizationPipeline(); print(p.process_line('SAMPLE LOG'))"
- Test API:
  - curl -X POST "http://127.0.0.1:8000/api/v1/ingest/line" -H "Content-Type: application/json" -d '{"raw_line":"<LOG>"}'

## How to commit this report & the new API files
- Add the new package and API file:
  - git add src/app/__init__.py src/app/main2.py WORK_REPORT.md
  - git commit -m "Add FastAPI ingest API (src.app.main2) and WORK_REPORT.md"
  - git push origin <branch>
- Open a Pull Request describing the change, link this WORK_REPORT.md, and request review from the team.

## Contact & provenance
- This work was guided by the ENGINE_REPORT.md that documents the pipeline API (`NormalizationPipeline`, `process_line`, `process_file`). The API implementation intentionally mirrors the CLI usage in `src/main.py` so the same pipeline and mappings are used.


