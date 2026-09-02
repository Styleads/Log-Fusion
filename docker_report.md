# Docker Containerization & Orchestration Report

## 1. Executive Summary

This document details the complete containerization and network orchestration architecture implemented for the **Universal Log Pre-processing Framework (ULPF) / Log-Fusion** project.

Every component in the repository has been packaged using **Docker** and **Docker Compose**, providing:
- **Dual Operating Modes**: Launch the entire connected ecosystem via the master compose file or run and test each service independently in isolation.
- **Unified Networking (`ulpf-network`)**: Seamless inter-container communication across services (Frontend, Normalization Engine, Storage API, OpenSearch, RAG Chatbot, Anomaly Detection, and Mappings Validator).
- **Zero-Downtime Live Mounts**: Dynamic reloading for parser YAML mappings, raw log documents, and frontend source code without requiring container image rebuilds.
- **Air-Gapped Readiness**: Fully reproducible Docker images packageable for offline security enclaves and isolated SIEM deployments.

---

## 2. Multi-Container Architecture

```text
+-------------------------------------------------------------------------------------------------------------------------+
|                                              ulpf-network (Docker Bridge Network)                                       |
|                                                                                                                         |
|    +---------------------------+       +---------------------------+       +-----------------------------------------+  |
|    | ulpf-frontend (React 18)  |------>| ulpf-storage-api (FastAPI)|------>| ulpf-opensearch (OpenSearch 2.19.1)     |  |
|    | Port: 3000                | (REST)| Port: 8000                | (HTTP)| Port: 9200                              |  |
|    +---------------------------+       +---------------------------+       +-----------------------------------------+  |
|                  |                                   ^                                   | (Volume)                     |
|                  |                                   | (Forward Events)                  v                              |
|                  v                                   |                       +-----------------------+                  |
|    +---------------------------+                     |                       | opensearch-data       |                  |
|    | ulpf-engine-api (FastAPI) |---------------------+                       +-----------------------+                  |
|    | Port: 8001                |                                                                                        |
|    +---------------------------+                                                                                        |
|                  ^                                                                                                      |
|                  | (Shared YAML Rules)                                                                                  |
|                  v                                                                                                      |
|    +---------------------------+       +---------------------------+       +-----------------------------------------+  |
|    | ulpf-mappings-validator   |       | ulpf-rag-chatbot          |------>| ulpf-ollama (Host / Container)          |  |
|    | Schema & Sample Testing   |       | LangGraph & ChromaDB RAG  | (HTTP)| Port: 11434                             |  |
|    +---------------------------+       +---------------------------+       +-----------------------------------------+  |
|                                                                                                                         |
|    +---------------------------+                                                                                        |
|    | ulpf-anomaly-detection    |                                                                                        |
|    | Pandas Threat Analytics   |                                                                                        |
|    +---------------------------+                                                                                        |
+-------------------------------------------------------------------------------------------------------------------------+
```

---

## 3. Container Services Summary

| Service Name | Container Name | Source Directory | Exposed Port | Base Image | Purpose |
|---|---|---|---|---|---|
| **frontend** | `ulpf-frontend` | `frontend/` | `3000:3000` | `node:20-alpine` | React 18 + Vite dashboard with charts and real-time backend proxies |
| **engine** | `ulpf-engine-api` | `src/` | `8001:8001` | `python:3.12-slim` | Ingestion, OCSF normalization pipeline, and Auto-Mapping Assistant API |
| **storage-api** | `ulpf-storage-api` | `database/` | `8000:8000` | `python:3.12-slim` | FastAPI REST interface for OpenSearch indexing, search, and analytics |
| **opensearch** | `ulpf-opensearch` | N/A | `9200:9200` | `opensearch:2.19.1` | Analytics and search database for normalized security events |
| **rag-chatbot** | `ulpf-rag-chatbot` | `rag_chatbots/` | Interactive CLI | `python:3.11-slim` | LangGraph + ChromaDB interactive AI assistant with Ollama LLM integration |
| **anomaly-detection** | `ulpf-anomaly-detection`| `anomaly_detection/`| Batch / CLI | `python:3.11-slim` | Rule-based and statistical anomaly detection engine over OCSF logs |
| **mappings-validator**| `ulpf-mappings-validator`| `mappings/` | CLI / Test | `python:3.12-slim` | Automated parser verification & test runner for all perimeter device YAMLs |

---

## 4. Master Orchestration (`docker-compose.yml`)

The root `docker-compose.yml` provides full platform orchestration with zero configuration required.

### 4.1. Key Commands

#### Build All Images:
```powershell
docker compose build
```

#### Start All Web & Storage Services:
```powershell
docker compose up -d opensearch storage-api engine frontend
```

#### Check Service Status:
```powershell
docker compose ps
```

#### View Live Logs:
```powershell
# All services
docker compose logs -f

# Specific service
docker compose logs -f engine
```

#### Stop All Services:
```powershell
docker compose down
```

#### Clean Everything (Including Database Volumes):
```powershell
docker compose down -v
```

---

## 5. Live Service Endpoints

Once the master stack is started (`docker compose up -d`), the following endpoints are accessible:

- **🎨 Frontend Dashboard**: [http://localhost:3000](http://localhost:3000)
- **⚙️ Engine Ingestion & Auto-Mapping API Docs**: [http://localhost:8001/docs](http://localhost:8001/docs)
  - Health endpoint: `http://localhost:8001/health`
- **💾 Storage API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
  - Health endpoint: `http://localhost:8000/health`
- **🔍 OpenSearch Cluster**: [http://localhost:9200](http://localhost:9200)

---

## 6. Standalone Service Execution (Per-Folder Compose)

Each subsystem directory contains its own isolated `docker-compose.yml` and `Dockerfile`, allowing developers to test and iterate on specific components without running the entire stack.

### 6.1. Mappings Schema Validator (`mappings/`)
Validates all YAML mapping configurations (`Cisco ASA`, `Palo Alto`, `Suricata IDS`, `Windows Firewall`) and executes end-to-end tests against sample logs:
```powershell
cd mappings
docker compose run --rm mappings-validator
```

### 6.2. Log Normalization Engine (`src/`)
Runs the FastAPI ingestion engine in isolation with live `./mappings` mounting:
```powershell
cd src
docker compose up
```
*Run CLI batch normalization inside the container:*
```powershell
docker run --rm ulpf-engine:latest python -m src.main mappings/windows_firewall/samples/windows_firewall_sample.log --pretty
```

### 6.3. Database & Storage Layer (`database/`)
Starts OpenSearch 2.19.1 and the Storage API:
```powershell
cd database
docker compose up -d
```

### 6.4. Frontend Dashboard (`frontend/`)
Starts Vite dev server with volume-mounted `./src` for instant hot reloading:
```powershell
cd frontend
docker compose up
```

### 6.5. Anomaly Detection Engine (`anomaly_detection/`)
Analyzes normalized OCSF NDJSON logs and exports anomaly findings:
```powershell
cd anomaly_detection
docker compose run --rm anomaly-detection /data/output.ndjson /data/anomalies.ndjson
```

### 6.6. RAG Chatbot (`rag_chatbots/`)
Runs the interactive LangGraph chatbot CLI inside Docker:
```powershell
cd rag_chatbots

# Ingest documents into Chroma vectorstore:
docker compose run --rm rag-chatbot python src/ingest.py

# Start interactive chat CLI:
docker compose run --rm rag-chatbot
```

---

## 7. Cross-Container Testing Workflows

### 7.1. Full Ingestion-to-Storage Pipeline Test
Send a raw firewall log line to the Engine API (`8001`), which will detect the source, normalize it to OCSF, and forward it directly to the Storage API (`8000`) into OpenSearch:

```powershell
curl -X POST http://localhost:8001/api/v1/ingest/line `
  -H "Content-Type: application/json" `
  -d '{"raw_line": "2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389 0 S 3421556 0 8192 - - - RECEIVE", "forward_to_storage": true}'
```

### 7.2. Query Stored Events from Storage API
```powershell
curl http://localhost:8000/events/search?limit=10
```

### 7.3. Query Event Statistics from Storage API
```powershell
curl http://localhost:8000/events/stats
```

---

## 8. File Structure of Docker Assets

```text
Log-Fusion/
├── docker-compose.yml                 # Master Multi-Service Orchestrator (ulpf-network)
├── .dockerignore                      # Master Docker build ignore rules
├── docker_report.md                   # Complete containerization documentation (this file)
│
├── anomaly_detection/
│   ├── Dockerfile                     # Python 3.11 + Pandas anomaly detection image
│   ├── docker-compose.yml             # Dedicated compose for anomaly job runner
│   ├── .dockerignore                  # Anomaly detection ignore rules
│   └── requirements.txt               # pandas>=2.0.0
│
├── database/
│   ├── Dockerfile                     # Python 3.12 + FastAPI storage API image
│   ├── docker-compose.yml             # Dedicated compose for OpenSearch + Storage API
│   └── requirements.txt               # opensearch-py, fastapi, uvicorn, pydantic
│
├── frontend/
│   ├── Dockerfile                     # Node 20 Alpine Vite development server image
│   ├── docker-compose.yml             # Dedicated compose with live hot-reloading
│   ├── .dockerignore                  # Frontend ignore rules (node_modules, dist)
│   └── vite.config.ts                 # Configured with dynamic /api & /engine-api proxies
│
├── mappings/
│   ├── Dockerfile                     # Python 3.12 mapping validator image
│   ├── docker-compose.yml             # Dedicated compose for schema testing
│   ├── .dockerignore                  # Mappings ignore rules
│   ├── requirements.txt               # pyyaml>=6.0
│   └── validate_mappings.py           # Automated schema & sample normalization test script
│
├── rag_chatbots/
│   ├── Dockerfile                     # Python 3.11 + LangGraph + ChromaDB image
│   ├── docker-compose.yml             # Dedicated compose with Ollama integration
│   ├── .dockerignore                  # RAG chatbot ignore rules
│   └── requirements.txt               # langchain, langgraph, chromadb, langchain-ollama
│
└── src/
    ├── Dockerfile                     # Python 3.12 Engine API & CLI image
    ├── docker-compose.yml             # Dedicated compose for Engine API (Port 8001)
    └── .dockerignore                  # Engine build ignore rules
```

---

## 9. Verification & Quality Assurance Summary

| Automated Verification Check | Execution Command | Result |
|---|---|---|
| **Engine Test Suite** | `docker run --rm ulpf-engine:latest pytest` | **34/34 Passed** in 1.63s (100% passing) |
| **Frontend Production Bundling** | `docker run --rm ulpf-frontend:latest npm run build` | **2,295 modules transformed with 0 errors** |
| **Mapping Schema & Sample Test** | `docker run --rm ulpf-mappings-validator:latest` | **4/4 Mappings Loaded, 100% Samples Normalized** |
| **Anomaly Detection Execution** | `docker run --rm -v "${PWD}:/data" ulpf-anomaly-detection:latest /data/output.ndjson /data/anomalies.ndjson` | **Executed cleanly with exit code 0** |
| **Master Compose Validation** | `docker compose config` | **All 7 service definitions & networks validated** |

---

## 10. Conclusion

The ULPF / Log-Fusion platform is completely containerized. Every module can be operated independently for development or combined as a resilient, unified multi-service platform for deployment and evaluation.
