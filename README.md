# Universal Log Pre-processing Framework (ULPF / LogFusion)

[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](frontend/)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-2.19.1-005EB8?logo=opensearch&logoColor=white)](https://opensearch.org)
[![OCSF](https://img.shields.io/badge/OCSF-v1.1.0-FF6F00)](https://schema.ocsf.io/)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)](frontend/)
[![Pytest](https://img.shields.io/badge/Tests-59%20Passed-4E9A06?logo=pytest&logoColor=white)](tests/)

> **A high-performance, modular log normalization, vendor auto-mapping, and security analytics platform.**  
> Ingests heterogeneous perimeter security logs (CSV, Key-Value, Syslog, JSON, space-delimited text), normalizes them into **Open Cybersecurity Schema Framework (OCSF v1.1.0)** nested JSON, preserves 100% forensic data, indexes into **OpenSearch**, and provides an AI-powered SOC dashboard.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Key Capabilities & Features](#key-capabilities--features)
3. [Supported Perimeter Device Formats](#supported-perimeter-device-formats)
4. [Quickstart: Launching with Docker Compose](#quickstart-launching-with-docker-compose)
5. [Local Development & Run Guide](#local-development--run-guide)
   - [Backend Gateway & Engine](#1-backend-normalization-engine--gateway)
   - [Storage API & OpenSearch](#2-storage-api--opensearch)
   - [Frontend SOC Dashboard](#3-frontend-soc-dashboard)
   - [AI RAG Chatbot ("Ask Joi AI")](#4-ai-rag-chatbot-ask-joi-ai)
   - [Anomaly Detection Runner](#5-anomaly-detection-runner)
6. [Core Workflows & User Guide](#core-workflows--user-guide)
   - [Live Ingest Lab](#workflow-1-live-ingest-lab)
   - [Auto-Mapping Assistant Studio](#workflow-2-auto-mapping-assistant-studio)
   - [SOC Dashboard & Telemetry Analytics](#workflow-3-soc-dashboard--telemetry-analytics)
   - [Forensic Raw vs. OCSF Drilldown](#workflow-4-forensic-raw-vs-ocsf-drilldown)
   - [AI Threat Hunting & RAG Chatbot](#workflow-5-ai-threat-hunting--rag-chatbot)
7. [API Reference & Route Map](#api-reference--route-map)
8. [Testing & Quality Assurance](#testing--quality-assurance)
9. [Project Directory Layout](#project-directory-layout)
10. [Git & Repository Policy](#git--repository-policy)

---

## System Architecture

```
                                  +-----------------------------+
                                  |     Raw Perimeter Logs      |
                                  | CSV / KV / Syslog / JSON /  |
                                  |  Native Space-Delimited     |
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |   1. Log Detector Engine    |
                                  |  Regex / Header / JSON Match|
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |    2. Parser Execution      |
                                  | CSV / KV / Syslog / JSON    |
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |   3. Value Transformers     |
                                  | IANA Protocol / Port Casts  |
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |    4. Timestamp Parser      |
                                  | Composite / Epoch -> ISO8601|
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |    5. OCSF Classifier       |
                                  | Class UID & Activity Action |
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |      6. Nested Mapper       |
                                  | Dotted Path JSON + Statics  |
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  | 7. Lossless Raw Preservation|
                                  | UUIDv4 + raw_data + unmapped|
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |    Normalized OCSF v1.1.0   |
                                  |        JSON Document        |
                                  +-----------------------------+
                                                 |
                        +------------------------+------------------------+
                        |                        |                        |
                        v                        v                        v
         +----------------------------+ +------------------+ +---------------------------+
         | OpenSearch Storage Layer   | | RAG AI Layer     | | React SOC Frontend        |
         | (Index: ulpf-events :9200) | | (ChromaDB Vector | | (Port: 3000)              |
         | Storage API (Port: 8000)   | | + Ollama Models) | | Real-time Feed & Drilldown|
         +----------------------------+ +------------------+ +---------------------------+
```

---

## Key Capabilities & Features

- **Multi-Vendor Declarative Parsing**: Normalize raw perimeter security telemetry across diverse vendors with declarative YAML configurations in `mappings/`—zero C/Python code modifications needed to support a new vendor.
- **100% Lossless Forensic Traceability**: Every event preserves the untouched raw log line in `raw_data`, is assigned a unique deterministic UUID in `metadata.uid`, and preserves unmapped vendor fields in an `unmapped` sub-object.
- **Auto-Mapping Assistant Studio**: Automatically analyzes unknown log samples, identifies data boundaries, predicts IP/port/protocol semantics, and generates production-ready draft YAML configs with one-click live deployment.
- **Full OCSF v1.1.0 Taxonomy**: Normalizes logs into standardized classes such as `4001: Network Activity` and `4002: HTTP Activity`, mapping action states (`Allow`, `Deny`, `Drop`) and IANA protocol definitions.
- **OpenSearch 2.19.1 Integration**: High-throughput indexing, full-text forensic search, CIDR IP filtering, and analytical aggregations through a dedicated Storage API.
- **Dynamic SOC Analytics Dashboard**: Concentric progress rings for volume and denial ratios, live traffic velocity graphs, and dynamic vendor source distribution cards.
- **Explainable Anomaly Detection**: Pure rule-based detection engine in Pandas to identify burst denials, brute-force attempts, and port-scan sweeps with zero black-box uncertainty.
- **Grounded AI RAG Assistant ("Ask Joi AI")**: LangGraph state machine with ChromaDB vectorstore and local Ollama (`phi4-mini` / `nomic-embed-text`) providing cited threat investigations.

---

## Supported Perimeter Device Formats

| Vendor & Device | Format Type | Example Source File | OCSF Class |
|---|---|---|---|
| **Palo Alto Networks (PAN-OS)** | Comma-Separated Values (CSV) | `mappings/Palo_Alto/` | `Network Activity (4001)` |
| **Cisco ASA Security Gateway** | Perimeter Syslog (`%ASA-` prefix) | `mappings/CISCO_ASA/` | `Network Activity (4001)` |
| **Fortinet FortiGate (FortiOS)** | Key-Value Pairs (`key=value`) | `mappings/Fortinet/` | `Network Activity (4001)` |
| **Suricata IDS / IPS** | EVE JSON Telemetry | `mappings/Suricata_IDS/` | `Network Activity (4001)` |
| **Microsoft Windows Firewall** | Space-Delimited Log (`pfirewall.log`) | `mappings/windows_firewall/` | `Network Activity (4001)` |
| **Squid Proxy** | Native Access Log (Whitespace-Delimited) | `unkownlogs/squid_proxy_sample.log` | `HTTP Activity (4002)` |

---

## Quickstart: Launching with Docker Compose

The fastest way to run the entire interconnected multi-service ecosystem is with Docker Compose.

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) (v24.0+)
- [Docker Compose](https://docs.docker.com/compose/) (v2.20+)
- At least 4GB of free RAM allocated to Docker

### 1. Clone the Repository
```bash
git clone https://github.com/your-org/logflash.git
cd logflash
```

### 2. Start the Core Services
Run the core services in the background:
```bash
docker compose up -d --build opensearch storage-api engine frontend
```

### 3. Verify Container Health
```bash
docker compose ps
```
You should see:
- `ulpf-opensearch` (Port `9200`) — OpenSearch database
- `ulpf-storage-api` (Port `8000`) — Storage API service
- `ulpf-engine-api` (Port `8001`) — Normalization engine gateway
- `ulpf-frontend` (Port `3000`) — Web application UI

### 4. Access the SOC Web Application
Open your browser to:
```
http://localhost:3000
```

### 5. (Optional) Run the AI & Model Services
To start local Ollama and the RAG Chatbot:
```bash
docker compose up -d ollama ollama-pull rag-chatbot
```

---

## Local Development & Run Guide

If you prefer to run services natively on your host machine for development:

### 1. Backend Normalization Engine & Gateway
```bash
# From workspace root
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run the Engine API server on port 8001
uvicorn src.app.main:app --host 0.0.0.0 --port 8001 --reload
```
API Documentation will be available at `http://localhost:8001/docs`.

### 2. Storage API & OpenSearch
```bash
# Start OpenSearch via Docker if running locally
docker compose up -d opensearch

# Run the Storage API on port 8000
cd database
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Storage API Documentation will be available at `http://localhost:8000/docs`.

### 3. Frontend SOC Dashboard
```bash
cd frontend
npm install
npm run dev
```
The Vite development server will open at `http://localhost:3000`.

### 4. AI RAG Chatbot ("Ask Joi AI")
```bash
cd rag_chatbots
pip install -r requirements.txt

# Initialize the vector store from documents
python src/ingest.py

# Launch the interactive terminal chatbot
python src/main.py
```

### 5. Anomaly Detection Runner
```bash
cd anomaly_detection
pip install -r requirements.txt
python anomaly_detection.py --input /path/to/events.json --output anomalies.ndjson
```

---

## Core Workflows & User Guide

### Workflow 1: Live Ingest Lab
1. Navigate to the **Instant Ingest Modal** (click **"⚡ Ingest"** on the floating dock or header).
2. Choose a preset perimeter sample (Palo Alto, Cisco ASA, Suricata, Fortinet, Windows Firewall) or upload a custom file.
3. Click **"Execute Normalization Pipeline"**.
4. Observe the live 6-stage visualization:
   - `Ingest` -> `Detect` -> `Parse` -> `Classify` -> `Map` -> `Preserve`
5. Inspect the generated field lineage mapping and click through to the live SOC feed. All normalized events are automatically persisted into OpenSearch.

### Workflow 2: Auto-Mapping Assistant Studio
For previously unseen or custom log formats (e.g. `unkownlogs/squid_proxy_sample.log`):
1. In the Ingest Lab, drop your unknown log file.
2. The system automatically triggers the **Auto-Mapping Assistant**:
   - Detects grammar delimiters and syntax (space-delimited, CSV, KV, Syslog).
   - Extracts semantic tokens (Client IP, HTTP URL, status code, bytes, timestamp).
   - Generates a valid draft YAML mapping configuration.
   - Computes a confidence score and live OCSF validation preview.
3. Click **"Approve & Deploy Draft Live"**:
   - The mapping is saved to `mappings/<slug>/mapping.yaml`.
   - The engine hot-reloads its active configuration.
   - The entire log batch is re-ingested, normalized, and synced to OpenSearch.

### Workflow 3: SOC Dashboard & Telemetry Analytics
Navigate to the **Statistics** tab (`Statistics & Concentric Rings`):
- **Concentric Progress Rings**: Displays overall event volume, deny mitigation percentage, and lossless traceability.
- **Perimeter Device Sources Grid**: Dynamically displays each active vendor (e.g. Squid Proxy, Palo Alto, Suricata) with real-time event counts and volume percentages. Click any vendor card to filter the entire feed.
- **Traffic Velocity Spline**: Tracks event volume across hours of the day (`Days`), days of the week (`Weeks`), or months of the year.

### Workflow 4: Forensic Raw vs. OCSF Drilldown
1. On any event card in the main feed, click **"Inspect OCSF JSON"** or the event row.
2. The **Forensic Drilldown Modal** provides:
   - **Original Raw Stream**: Untouched forensic raw string.
   - **Normalized OCSF v1.1.0 JSON**: Complete structured document.
   - **Provenance Metadata**: Parser execution time, matched YAML rule, and event UUID.
   - One-click copy buttons for SIEM incident ticketing.

### Workflow 5: AI Threat Hunting & RAG Chatbot
Navigate to the **Chat** tab:
- Ask natural language questions about your logs:
  - *"Which source IPs experienced the highest denial rates?"*
  - *"Show me HTTP requests directed at malicious domains."*
  - *"What firewall rules blocked traffic on port 22?"*
- Joi AI retrieves verified events from the vector database and cites exact event UUIDs.
- **Strict Ollama Mode vs. Auto-Fallback**:
  - By default, Joi AI uses **Auto-Fallback**: if Ollama is unreachable or offline, queries gracefully fall back to the deterministic, zero-dependency **Grounded Telemetry Engine** (`source: grounded_telemetry`).
  - To force LLM reasoning and disable the grounded telemetry fallback, toggle **"Strict Ollama"** in the chat header, set `force_ollama: true` (or `disable_fallback: true`) in `/api/v1/chat`, or set the container environment variable `CHATBOT_FORCE_OLLAMA=true`. If Ollama is offline in this mode, an explicit HTTP 503 error is returned detailing the connection diagnostic rather than falling back.

---

## API Reference & Route Map

### Engine Gateway API (Port `8001`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | System health check and component status |
| `POST` | `/api/v1/ingest/line` | Ingest single raw line with storage forwarding |
| `POST` | `/api/v1/ingest/batch` | Bulk normalize raw lines with OpenSearch sync |
| `POST` | `/api/v1/ingest/file` | Multipart file upload normalization |
| `POST` | `/api/v1/assistant/analyze` | Run format heuristics and generate draft YAML |
| `POST` | `/api/v1/assistant/save` | Save draft YAML to `mappings/<slug>/` |
| `GET` | `/api/v1/assistant/drafts` | List all pending draft mappings |
| `POST` | `/api/v1/assistant/approve/{slug}` | Promote draft to `reviewed` and reload engine |
| `POST` | `/api/v1/reload` | Hot-reload all mappings from disk |
| `POST` | `/api/v1/chat` | Grounded RAG security query handler (supports `force_ollama` / `disable_fallback` to enforce Ollama generation) |
| `POST` | `/api/v1/anomalies` | Fast statistical anomaly scanner |
| `DELETE` | `/api/v1/events` | Forward database wipe request to Storage API |

### Storage API (Port `8000`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | OpenSearch cluster connectivity check |
| `POST` | `/events` | Insert a single normalized OCSF event |
| `POST` | `/events/bulk` | Bulk index events into OpenSearch (`refresh=true`) |
| `GET` | `/events/search` | Query events with filters (`limit`, `vendor`, `source_ip`, `activity_id`) |
| `GET` | `/events/stats` | Aggregated severity, activity, and vendor breakdown |
| `GET` | `/events/{event_id}` | Retrieve normalized document by UUID |
| `DELETE` | `/events` | Purge index and recreate clean schema |

---

## Testing & Quality Assurance

### Run Automated Backend Test Suite
The repository includes a comprehensive 59-test suite covering parsers, classifiers, transforms, detector heuristics, and mapping validation:
```bash
# Inside engine container:
docker exec ulpf-engine-api pytest tests/ -v

# Or locally:
python -m pytest tests/ -v
```
**Status: 59 / 59 Passed (100%)**

### Verify YAML Mapping Schemas
Validate all declarative vendor configs against the canonical 10-section ULPF specification:
```bash
python mappings/validate_mappings.py
```

### Validate Frontend TypeScript & Production Build
```bash
cd frontend
npm run build
```

---

## Project Directory Layout

```text
logflash/
├── docker-compose.yml              # Master container orchestrator (ulpf-network)
├── requirements.txt                # Root Python dependencies
├── README.md                       # Master project documentation & guide
├── .gitignore                      # Git exclusion rules (Node, Python, Vectorstores)
│
├── mappings/                       # Declarative YAML Vendor Mappings
│   ├── CISCO_ASA/                  # Cisco ASA syslog configuration
│   ├── Fortinet/                   # Fortinet FortiOS KV configuration
│   ├── Palo_Alto/                  # Palo Alto PAN-OS CSV configuration
│   ├── Suricata_IDS/               # Suricata EVE JSON configuration
│   ├── windows_firewall/           # Windows Firewall space-delimited config
│   └── validate_mappings.py        # YAML schema validation script
│
├── unkownlogs/                     # Unknown Log Samples for Auto-Mapping Demo
│   ├── squid_proxy_sample.log      # Raw Squid access logs
│   └── squid_proxy_ground_truth_mapping.yaml # Reference mapping
│
├── src/                            # Normalization Engine & Gateway
│   ├── app/
│   │   └── main.py                 # FastAPI unified gateway server (:8001)
│   ├── assistant/                  # Auto-Mapping Assistant Studio
│   │   ├── detector_heuristics.py  # Grammar & syntax inference
│   │   ├── generator.py            # Draft YAML config generator
│   │   ├── llm_fallback.py         # 1-shot local Ollama fallback
│   │   ├── semantic_analyzer.py    # IP/Port/Timestamp/Action role inference
│   │   ├── service.py              # Save & human approval lifecycle
│   │   └── validator.py            # Pipeline test execution & validation
│   └── engine/                     # Normalization Pipeline Engine
│       ├── classifier.py           # OCSF class & activity classification
│       ├── config_loader.py        # YAML config parser & validator
│       ├── detector.py             # Format signature matcher
│       ├── mapper.py               # Nested dotted path mapper
│       ├── parsers.py              # CSV, KV, JSON, Syslog, Delimited parsers
│       ├── pipeline.py             # End-to-end normalization pipeline
│       ├── timestamp.py            # Composite date/time & epoch parser
│       └── transforms.py           # Data type casting & protocol lookup
│
├── database/                       # OpenSearch Data Layer
│   ├── app/
│   │   └── main.py                 # Storage API service (:8000)
│   ├── Dockerfile
│   └── index_mapping.json          # OpenSearch ulpf-events index schema
│
├── frontend/                       # React 18 + Vite SOC Dashboard (:3000)
│   ├── src/
│   │   ├── App.tsx                 # Core application controller
│   │   ├── components/
│   │   │   ├── assistant/          # AutoMappingStudio & DraftsDrawer
│   │   │   ├── common/             # Header, BottomDock, StatCard
│   │   │   ├── dashboard/          # ConcentricProgressRing, VendorProjectGrid, VisualAnalytics
│   │   │   ├── drilldown/          # Forensic Raw vs. OCSF Modal
│   │   │   ├── ingest/             # LiveIngestLab & stage visualizer
│   │   │   └── chat/               # SecurityChatbot UI
│   │   ├── services/
│   │   │   ├── apiService.ts       # OpenSearch & Engine API client
│   │   │   └── assistantService.ts # Draft mapping service
│   │   └── types/                  # TypeScript OCSF & Event definitions
│   ├── Dockerfile
│   └── vite.config.ts              # API reverse proxies (/api & /engine-api)
│
├── rag_chatbots/                   # Grounded RAG Chatbot (Joi AI)
│   ├── src/
│   │   ├── graph.py                # LangGraph state machine
│   │   ├── ingest.py               # Vectorstore document indexer
│   │   └── main.py                 # Interactive CLI chat runner
│   ├── documents/                  # Reference documents for vectorstore
│   └── vectorstore/                # Local ChromaDB directory (.gitkeep)
│
├── anomaly_detection/              # Rule-Based Threat Anomaly Engine
│   ├── anomaly_detection.py        # Groupby rolling window anomaly scanner
│   └── Dockerfile
│
└── tests/                          # Automated Pytest Test Suite
    ├── test_auto_mapping_assistant.py
    ├── test_classifier.py
    ├── test_config_loader.py
    ├── test_detector.py
    ├── test_mapper.py
    ├── test_parsers.py
    ├── test_pipeline.py
    ├── test_timestamp.py
    └── test_transforms.py
```

---

## Git & Repository Policy

### Vector Store Policy (`rag_chatbots/vectorstore/`)
- **Do NOT push vector database files to Git**: ChromaDB generates binary SQLite databases (`chroma.sqlite3`) and HNSW index graphs (`*.bin`). Committing these files causes merge conflicts, binary churn, and repository bloat.
- The `.gitignore` excludes all files in `rag_chatbots/vectorstore/*` while preserving `.gitkeep`.
- When cloning the repository fresh, populate the vectorstore by running:
  ```bash
  python rag_chatbots/src/ingest.py
  ```
  or by running the `ollama` and `rag-chatbot` Docker services.

### Contributing New Mappings
1. Place raw log samples in `mappings/<vendor_name>/samples/sample.log`.
2. Author your declarative YAML config in `mappings/<vendor_name>/mapping.yaml` or generate it via the **Auto-Mapping Assistant Studio**.
3. Run `python mappings/validate_mappings.py` to confirm schema compliance.
4. Run `pytest tests/` to confirm all existing pipeline regressions pass.
