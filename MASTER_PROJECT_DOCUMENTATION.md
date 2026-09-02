# Master Technical Documentation & Architecture Reference
## Universal Log Pre-processing Framework (ULPF / LogFusion / Rosetta)

> **Complete Project Synthesis**: Combining Core Normalization Engine, Vendor Mapping Specifications, Auto-Mapping Assistant, Storage & OpenSearch Data Layer, FastAPI Backend Gateway, AI/RAG Chatbot, Rule-Based Anomaly Detection, Modern SOC Frontend Dashboard, and Docker Orchestration.

---

## Table of Contents
1. [Executive Summary & Problem Statement](#1-executive-summary--problem-statement)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [Core Log Normalization Engine (`src/engine/`)](#3-core-log-normalization-engine)
4. [Declarative YAML Mapping Specification (`mappings/`)](#4-declarative-yaml-mapping-specification)
5. [Auto-Mapping Assistant Studio (`src/assistant/`)](#5-auto-mapping-assistant-studio)
6. [Database & Storage Layer (`database/` & OpenSearch)](#6-database--storage-layer)
7. [Unified Backend Gateway API (`src/app/main.py`)](#7-unified-backend-gateway-api)
8. [AI Layer: RAG Chatbot & Anomaly Detection](#8-ai-layer-rag-chatbot--anomaly-detection)
9. [Modern SOC Frontend Web Application (`frontend/`)](#9-modern-soc-frontend-web-application)
10. [Docker Containerization & Orchestration (`docker-compose.yml`)](#10-docker-containerization--orchestration)
11. [Verification, Quality Assurance & Test Suites](#11-verification-quality-assurance--test-suites)
12. [Complete Project File & Directory Inventory](#12-complete-project-file--directory-inventory)
13. [Repository Cleanup Guide: Safely Removing Redundant Markdown Files](#13-repository-cleanup-guide)

---

## 1. Executive Summary & Problem Statement

### 1.1. The Enterprise Problem
Enterprises collect vast amounts of telemetry from perimeter network devices (firewalls, IDS/IPS, VPN gateways, routers, proxies/WAFs) in diverse, vendor-specific formats such as Syslog, JSON, XML, CSV, Key-Value pairs, CEF, LEEF, and proprietary formats (e.g., Palo Alto PAN-OS CSV, Cisco ASA Syslog, Fortinet FortiOS Key-Value, Suricata EVE JSON, Windows Firewall space-delimited text).

This heterogeneity causes significant issues:
* **Ingestion Bottlenecks**: Security operations teams must hand-craft separate parsers for every vendor format.
* **Corrupted Field Semantics**: Inconsistent field names (e.g., `srcip`, `saddr`, `source_ip`, `c_ip`) prevent cross-source correlation in SIEMs and Data Lakes.
* **Information Loss**: Ad-hoc transformations discard unmapped vendor attributes, breaking forensic auditability.
* **Slow Incident Response**: Threat hunters cannot execute unified queries across multi-vendor perimeter infrastructure.

### 1.2. The Solution: Universal Log Pre-processing Framework (ULPF)
ULPF (codename: **Rosetta / LogFusion**) is a high-performance, modular system designed to:
1. **Ingest arbitrary perimeter logs** across CSV, Key-Value, Syslog, JSON, and space-delimited formats.
2. **Automatically detect log formats and vendor origins** using declarative YAML rules with zero application code modification.
3. **Normalize all fields into Open Cybersecurity Schema Framework (OCSF v1.1.0)** nested JSON documents (e.g., Class 4001: *Network Activity*, Class 2004: *Detection Finding*).
4. **Guarantee 100% lossless forensic traceability** by preserving the untouched original raw log line (`raw_data`), generating a deterministic event UUID (`metadata.uid`), and bucketing unmapped attributes into an `unmapped` sub-object.
5. **Accelerate source onboarding** via an integrated **Auto-Mapping Assistant** that infers field boundaries and generates draft YAML configs.
6. **Support air-gapped deployments** through containerization and local LLM/heuristic fallbacks without mandatory external cloud dependencies.

---

## 2. End-to-End System Architecture

```
                                  +-----------------------------+
                                  |     Raw Perimeter Logs      |
                                  | CSV / KV / Syslog / JSON /  |
                                  |       Space-Delimited       |
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
                                  | Protocol Name / Type Casts  |
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |    4. Timestamp Parser      |
                                  |  Composite -> ISO-8601 UTC  |
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
                                  |  Dotted Path JSON & Statics |
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
                                  |   Normalized OCSF v1.1.0    |
                                  |        JSON Document        |
                                  +-----------------------------+
                                                 |
                       +-------------------------+-------------------------+
                       |                         |                         |
                       v                         v                         v
        +----------------------------+ +-------------------+ +---------------------------+
        | OpenSearch Storage Layer   | | RAG & AI Layer    | | React SOC Frontend        |
        | (Index: ulpf-events :9200) | | (ChromaDB + Ollama| | (Port: 3000)              |
        | Storage API (Port: 8000)   | | / Grounded RAG)   | | Forensic Raw vs OCSF View |
        +----------------------------+ +-------------------+ +---------------------------+
```

---

## 3. Core Log Normalization Engine

The engine lives in `src/engine/` and implements the pure data transformation pipeline.

### 3.1. Modules Breakdown

| Module File | Component Name | Description |
|---|---|---|
| [`src/engine/config_loader.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/engine/config_loader.py) | `ConfigLoader` | Recursively scans `/mappings` for `*.yaml` files, parses them into strongly-typed `MappingConfig` models, validates required sections, and caches them for fast lookups. |
| [`src/engine/detector.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/engine/detector.py) | `LogDetector` | Inspects incoming raw log lines and matches them to a vendor YAML configuration using regex signatures, JSON schema keys, or CSV header/value heuristics. |
| [`src/engine/parsers.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/engine/parsers.py) | `DelimitedParser`, `JSONParser`, `KeyValueParser`, `SyslogParser` | Extracts flat raw field dictionaries from lines based on the matched vendor configuration rules. |
| [`src/engine/transforms.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/engine/transforms.py) | `ValueTransformer` | Transforms raw strings: maps protocol numbers to IANA names (`6` -> `TCP`), casts data types (`integer`, `float`, `boolean`), parses duration strings (`0:00:44` -> `44`), and maps severity strings. |
| [`src/engine/timestamp.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/engine/timestamp.py) | `TimestampParser` | Extracts single or composite date/time fields (`date` + `time`), parses format strings (e.g., `%Y-%m-%d %H:%M:%S`), and outputs standardized ISO-8601 UTC strings. |
| [`src/engine/classifier.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/engine/classifier.py) | `OCSFClassifier` | Evaluates rule predicates (e.g., `when: { raw_action: "DROP" }`) to determine `class_uid`, `class_name`, `activity_id`, and `activity_name`. |
| [`src/engine/mapper.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/engine/mapper.py) | `NestedMapper` | Maps parsed keys to dotted OCSF JSON paths (`src_endpoint.ip`, `dst_endpoint.port`, `connection_info.protocol_name`) and injects static metadata. |
| [`src/engine/pipeline.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/engine/pipeline.py) | `NormalizationPipeline` | Orchestrates the end-to-end execution flow for single lines (`process_line`) or bulk files (`process_file`). |

### 3.2. Standard Output Shape (OCSF v1.1.0)

```json
{
  "class_name": "Network Activity",
  "class_uid": 4001,
  "activity_name": "Deny",
  "activity_id": 6,
  "time": "2026-08-27T09:14:02Z",
  "src_endpoint": {
    "ip": "203.0.113.45",
    "port": 51322,
    "zone": "untrust"
  },
  "dst_endpoint": {
    "ip": "10.0.4.12",
    "port": 22,
    "zone": "trust"
  },
  "connection_info": {
    "protocol_name": "TCP",
    "direction": "inbound"
  },
  "firewall_rule": {
    "name": "rule-block-ssh-external"
  },
  "device": {
    "name": "edge-fw-01",
    "vendor_name": "Palo Alto Networks",
    "type": "Firewall"
  },
  "metadata": {
    "uid": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "product": {
      "vendor_name": "Palo Alto Networks",
      "name": "PAN-OS"
    },
    "version": "1.1.0"
  },
  "unmapped": {
    "session_id": "992144",
    "nat_src_port": "0"
  },
  "raw_data": "2026/08/27 09:14:02,001801000001,TRAFFIC,drop,1,2026/08/27 09:14:02,203.0.113.45,10.0.4.12,0.0.0.0,0.0.0.0,rule-block-ssh-external,..."
}
```

---

## 4. Declarative YAML Mapping Specification

Adding support for any perimeter device requires only adding a declarative YAML file under `/mappings/<vendor>/` without touching code.

### 4.1. Canonical 10-Section Schema

1. `source_identity`: Vendor name, product name, format type, schema version, and review status (`draft` / `reviewed`).
2. `detection`: Matching rules (regex patterns, JSON field matches, or CSV header/value conditions).
3. `parsing`: Field boundary specifications (delimiters, column indices, syslog header templates, or key-value regex).
4. `classification`: Rules mapping parsed fields to OCSF classes (e.g. `4001: Network Activity`, `2004: Detection Finding`) and activity IDs.
5. `field_map`: Key-to-dotted-path mapping rules (e.g., `srcip -> src_endpoint.ip`).
6. `static_fields`: Constant key-value pairs injected into every event (e.g., `device.vendor_name`, `device.type`).
7. `transforms`: Data type conversions and categorical lookups (e.g., protocol numbers, port casting).
8. `timestamp`: Source fields, time format strings, and timezone specifications.
9. `unmapped_policy`: Configured to `bucket` (stores non-mapped fields in `unmapped` sub-object) ensuring zero data loss.
10. `raw_preservation`: Attaches untouched original line string and unique UUIDv4.

### 4.2. Shipped Vendor Configurations

* **Palo Alto Networks (PAN-OS)**: [`mappings/Palo_Alto/Palto_Altoconfig.yaml`](file:///c:/Users/Kruthik/Desktop/coding/logflash/mappings/Palo_Alto/Palto_Altoconfig.yaml)
* **Cisco ASA Firewall**: [`mappings/CISCO_ASA/cisco_asaconfig.yaml`](file:///c:/Users/Kruthik/Desktop/coding/logflash/mappings/CISCO_ASA/cisco_asaconfig.yaml)
* **Suricata EVE IDS**: [`mappings/Suricata_IDS/suricata_idsconfig.yaml`](file:///c:/Users/Kruthik/Desktop/coding/logflash/mappings/Suricata_IDS/suricata_idsconfig.yaml)
* **Windows Security Firewall**: [`mappings/windows_firewall/windows_firewallconfig.yaml`](file:///c:/Users/Kruthik/Desktop/coding/logflash/mappings/windows_firewall/windows_firewallconfig.yaml)
* **Fortinet FortiOS**: [`mappings/Fortinet/fortinet_config.yaml`](file:///c:/Users/Kruthik/Desktop/coding/logflash/mappings/Fortinet/fortinet_config.yaml)

---

## 5. Auto-Mapping Assistant Studio

The Auto-Mapping Assistant (`src/assistant/`) automatically bootstraps mapping rules for previously unseen log formats.

### 5.1. Workflow
1. **Format Ingestion**: Ingests 5–20 sample log lines from an unknown source.
2. **Format Detection (`detector_heuristics.py`)**: Automatically determines format (JSON, Key-Value, CSV, Space-Delimited, Syslog).
3. **Semantic Role Inference (`semantic_analyzer.py`)**: Deterministically identifies IP addresses, port numbers, protocols, action keywords (`ALLOW`, `DENY`, `DROP`), and timestamps.
4. **1-Shot Local LLM Fallback (`llm_fallback.py`)**: For ambiguous or complex fields, sends a single structured query to local Ollama (fails gracefully to `unmapped` bucket if offline).
5. **Config Generation (`generator.py`)**: Emits valid 10-section ULPF YAML tagged with `# ⚠️ AUTO-GENERATED DRAFT` and `status: "draft"`.
6. **Live Validation (`validator.py`)**: Passes the draft configuration through `NormalizationPipeline` in real-time and computes mapping fidelity metrics.
7. **Approval Lifecycle (`service.py`)**: Manages collision-safe persistence under `mappings/<slug>/` and supports one-click human promotion to `status: "reviewed"`.

---

## 6. Database & Storage Layer

Located in `database/`, providing persistent storage and querying via OpenSearch 2.19.1 and a FastAPI REST service.

### 6.1. Endpoints & Operations

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Verifies OpenSearch cluster connectivity and health state. |
| `POST` | `/events` | Stores a single normalized event. |
| `POST` | `/events/bulk` | Bulk ingestion endpoint for batch events (`refresh=true`). |
| `GET` | `/events/search` | Search and filter events by keyword, severity, activity, IP, or vendor. |
| `GET` | `/events/stats` | Aggregates severity, activity, and vendor breakdown metrics. |
| `GET` | `/events/{event_id}` | Retrieves a specific normalized document by its UUID. |
| `DELETE` | `/events` | **Wipes all records from the OpenSearch index** and recreates a clean schema. |

### 6.2. Schema Definition (`index_mapping.json`)
The OpenSearch index `ulpf-events` enforces explicit mapping types:
* `metadata.uid`: `keyword` (Primary Identifier)
* `time`: `date` (ISO-8601 UTC timestamp)
* `src_endpoint.ip`, `dst_endpoint.ip`: `ip` (Network search enabled)
* `class_uid`, `activity_id`, `severity_id`: `integer`
* `raw_data`: `text` (Full-text forensic search)
* `unmapped`: `object` (Dynamic attributes)

---

## 7. Unified Backend Gateway API

The gateway server (`src/app/main.py`) unifies ingestion, auto-mapping, anomaly analysis, and chatbot querying on port `8001`.

### 7.1. Key Route Handlers
* **`POST /api/v1/ingest/line`**: Ingests a single raw string, runs the normalization pipeline, and automatically forwards the resulting OCSF document to the OpenSearch Storage API.
* **`POST /api/v1/ingest/file`**: Multipart file upload accepting `.log`, `.csv`, `.json`, and `.txt` files for streaming batch ingestion.
* **`POST /api/v1/assistant/analyze`**: Runs format detection, semantic labeling, YAML generation, and live validation over unknown sample lines.
* **`POST /api/v1/assistant/save` & `POST /api/v1/assistant/approve/{slug}`**: Manages draft saving and human approval workflows.
* **`POST /api/v1/chat`**: Grounded RAG threat hunting assistant answering analyst queries.
* **`POST /api/v1/anomalies`**: Fast statistical anomaly detection scanning for high-frequency source IP denial bursts.
* **`DELETE /api/v1/events`**: Forwards database wipe requests to the Storage API.

---

## 8. AI Layer: RAG Chatbot & Anomaly Detection

### 8.1. Grounded RAG Chatbot ("Ask Joi AI")
Located in `rag_chatbots/` and exposed via the Web UI:
* **Architecture**: LangGraph conversational state machine with ChromaDB vectorstore.
* **Model Integration**: Local Ollama running `phi4-mini` (or `llama3`) and `nomic-embed-text`.
* **Grounded Retrieval**: Queries the normalized OCSF event store by IP, rule name, timestamp, or vendor, retrieving exact `raw_data` citations to eliminate hallucination.
* **Tools**: `list_files`, `find_files`, `read_file`, `search_documents`.

### 8.2. Rule-Based Threat Anomaly Detection
Located in `anomaly_detection/`:
* **Engine**: Python + Pandas (zero black-box ML, 100% explainable).
* **Technique**: Groupby aggregations over rolling time windows evaluating connection failure spikes, port scans, and brute-force patterns.

---

## 9. Modern SOC Frontend Web Application

Built with React 18, Vite, Tailwind CSS, Lucide React, and Recharts, hosted at `http://localhost:3000`.

### 9.1. Core Capabilities & Views
1. **Overview & SOC Feed (`dashboard`)**:
   * **Dynamic Hero Incident Cards**: Live data-driven card reflecting the latest perimeter event and critical security alerts with direct *"Inspect OCSF JSON"* action.
   * **KPI Stat Cards**: Total Ingested Events, Active Sources, Lossless Preservation Rate (100%), and Events Per Second.
   * **Dynamic Traffic Velocity Chart**: Recharts area spline plotting real event distribution across Hours (`Days`), Days of Week (`Weeks`), and Months.
   * **Filter & Search Bar**: Free-text search, OCSF class filter, vendor filter, action filter, severity filter, **Sort by Date (Newest/Oldest)**, and **Custom Date Range (From/To Pickers)**.
   * **Unified Event Stream with Pagination**: Chunks records into **30 items per page** with full navigation (`<<`, `<`, numbered pills, `>`, `>>`), card view, and compact table view.
2. **Telemetry & Analytics (`analytics`)**:
   * Concentric progress rings representing volume, deny mitigations, and lossless traceability.
   * Vendor distribution grid.
3. **Auto-Mapping Assistant Studio (`assistant` / Ingest Modal)**:
   * Drag-and-drop log upload, real-time pipeline stage stepper (`ingest` -> `detect` -> `parse` -> `classify` -> `map` -> `preserve` -> `store`), field lineage tables, and draft YAML editor.
4. **Forensic Drilldown Modal**:
   * Side-by-side comparison of **Original Raw Log Stream** vs. **Normalized OCSF v1.1.0 JSON Document** with one-click JSON clipboard copying.
5. **Settings & Data Management Modal**:
   * **Real Data Only Mode**: Strips away demo mock telemetry so the dashboard displays only real logs stored in OpenSearch.
   * **Wipe OpenSearch Database & Reset**: Purges all stored logs and resets in-memory buffers.
   * **Seed Demo Multi-Vendor Logs**: Re-populates demo datasets for testing.

---

## 10. Docker Containerization & Orchestration

The master `docker-compose.yml` launches the entire interconnected multi-service ecosystem on a dedicated bridge network (`ulpf-network`).

### 10.1. Container Services Map

| Service | Container Name | Port | Description |
|---|---|---|---|
| `frontend` | `ulpf-frontend` | `3000:3000` | React 18 + Vite UI with reverse proxies for `/api` and `/engine-api`. |
| `engine` | `ulpf-engine-api` | `8001:8001` | FastAPI normalization pipeline and Auto-Mapping Assistant gateway. |
| `storage-api` | `ulpf-storage-api` | `8000:8000` | FastAPI interface to OpenSearch with search and aggregation routes. |
| `opensearch` | `ulpf-opensearch` | `9200:9200` | OpenSearch 2.19.1 single-node document datastore. |
| `rag-chatbot` | `ulpf-rag-chatbot` | CLI | LangGraph + ChromaDB interactive AI assistant. |
| `anomaly-detection` | `ulpf-anomaly-detection` | CLI | Batch threat detection runner. |
| `mappings-validator` | `ulpf-mappings-validator` | CLI | Automated test runner verifying all YAML mapping files. |

### 10.2. Essential Docker Commands

```bash
# 1. Build and start core platform services:
docker compose up -d --build opensearch storage-api engine frontend

# 2. View live logs:
docker compose logs -f engine

# 3. Check service health:
docker compose ps

# 4. Stop all services:
docker compose down

# 5. Stop services and wipe all OpenSearch database volumes:
docker compose down -v
```

---

## 11. Verification, Quality Assurance & Test Suites

### 11.1. Pytest Test Suite Results
Run from the workspace root:
```bash
python -m pytest tests/ -v
```
**Status: 47 / 47 Passed (100% Passing in ~6.6 seconds)**

* `tests/test_auto_mapping_assistant.py` (13 tests): Format detection heuristics, semantic analysis, YAML generation, live validator execution, draft approval lifecycle, collision protection, and API endpoints.
* `tests/test_config_loader.py` (6 tests): YAML mapping parsing, schema validation, and error handling.
* `tests/test_detector.py` (4 tests): Format detection across Cisco ASA, Windows Firewall, Suricata, and Palo Alto.
* `tests/test_parsers.py` (5 tests): Delimited, Key-Value, Syslog, and JSON parsing.
* `tests/test_classifier.py` (5 tests): OCSF class and activity classification logic.
* `tests/test_transforms.py` (4 tests): Type casting, duration conversions, and protocol mappings.
* `tests/test_timestamp.py` (4 tests): Composite date/time parsing into UTC ISO-8601.
* `tests/test_mapper.py` (2 tests): Dotted-path nested dictionary construction.
* `tests/test_pipeline.py` (4 tests): End-to-end normalization pipelines for all supported vendors.

### 11.2. Frontend Production Bundling
Run inside `frontend/`:
```bash
npm run build
```
**Status: 2,301 modules transformed with 0 compilation errors.**

---

## 12. Complete Project File & Directory Inventory

```text
logflash/
├── docker-compose.yml                 # Master Multi-Service Orchestrator (ulpf-network)
├── requirements.txt                   # Root Python dependencies (FastAPI, PyYAML, pytest, httpx)
├── MASTER_PROJECT_DOCUMENTATION.md    # This complete master documentation file
├── README.md                          # Repository quickstart readme
│
├── mappings/                          # Declarative Vendor Mapping Rules (Person B)
│   ├── CISCO_ASA/
│   │   ├── cisco_asaconfig.yaml
│   │   └── samples/
│   ├── Fortinet/
│   │   ├── fortinet_config.yaml
│   │   └── samples/
│   ├── Palo_Alto/
│   │   ├── Palto_Altoconfig.yaml
│   │   └── samples/
│   ├── Suricata_IDS/
│   │   ├── suricata_idsconfig.yaml
│   │   └── samples/
│   └── windows_firewall/
│       ├── windows_firewallconfig.yaml
│       └── samples/
│
├── src/                               # Engine & Unified Gateway (Person A)
│   ├── main.py                        # CLI entry point (--auto-map, --pretty)
│   ├── app/
│   │   ├── __init__.py
│   │   └── main.py                    # Unified FastAPI gateway server (:8001 / :8000)
│   ├── assistant/                     # Auto-Mapping Assistant package
│   │   ├── detector_heuristics.py
│   │   ├── generator.py
│   │   ├── llm_fallback.py
│   │   ├── semantic_analyzer.py
│   │   ├── service.py
│   │   └── validator.py
│   └── engine/                        # Core parsing & normalization pipeline
│       ├── classifier.py
│       ├── config_loader.py
│       ├── detector.py
│       ├── mapper.py
│       ├── parsers.py
│       ├── pipeline.py
│       ├── timestamp.py
│       └── transforms.py
│
├── database/                          # Storage & OpenSearch Data Layer (Person C)
│   ├── app/
│   │   ├── __init__.py
│   │   └── main.py                    # Storage API service (OpenSearch CRUD & resets)
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── index_mapping.json             # OpenSearch ulpf-events schema definition
│   ├── sample_event.json
│   └── requirements.txt
│
├── frontend/                          # React 18 + Vite SOC Dashboard (Person D)
│   ├── src/
│   │   ├── App.tsx                    # Main application state & screen composition
│   │   ├── main.tsx
│   │   ├── components/
│   │   │   ├── assistant/             # Auto-Mapping Studio components
│   │   │   ├── common/                # Header, BottomDock, StatCard
│   │   │   ├── dashboard/             # HeroCarouselCard, VisualAnalytics, FilterBar, EventFeed
│   │   │   ├── docs/                  # Architecture & YAML docs viewer
│   │   │   ├── drilldown/             # Forensic Raw vs OCSF Modal
│   │   │   ├── ingest/                # Drag-and-drop live ingest lab
│   │   │   ├── chat/                  # Ask Joi AI Chatbot panel
│   │   │   └── settings/              # Settings modal with Real Data Only toggle & DB wipe
│   │   ├── data/                      # Sample raw logs, mock events, and YAML configs
│   │   ├── services/                  # apiService.ts & ocsfEngine.ts
│   │   └── types/                     # TypeScript contracts for OCSF & events
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.ts                 # Configured with /api & /engine-api proxy routes
│
├── rag_chatbots/                      # AI Layer: RAG Chatbot (Person E)
│   ├── graph.py                       # LangGraph routing pipeline
│   ├── ingest.py                      # Vectorstore embedding generator
│   ├── main.py                        # Interactive chat entry point
│   ├── tools.py                       # LangGraph tools (read_file, search_documents)
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── requirements.txt
│
├── anomaly_detection/                 # AI Layer: Threat Anomaly Detection (Person F)
│   ├── src/
│   │   └── detector.py                # Pandas rule-based anomaly detection
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── requirements.txt
│
└── tests/                             # Automated Test Suite (47 tests)
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

## 13. Repository Cleanup Guide

Because all project reports, specifications, and guides have been consolidated into this single master document (`MASTER_PROJECT_DOCUMENTATION.md`), you can safely remove the fragmented `.md` files that are cluttering your root and subfolders.

### 13.1. PowerShell Command (Windows)
Run the following PowerShell command in your terminal from the `logflash` root directory:

```powershell
Remove-Item -Path AUTO_MAPPING_ASSISTANT_SPEC.md, Backend_report.md, database_report.md, docker_report.md, ENGINE_REPORT.md, mapping_assistant.md, PROJECT_BRIEF.md, database/README.md, frontend/FRONTEND.md, frontend/QUICKSTART.md, frontend/README.md, rag_chatbots/Read.md -Force -ErrorAction SilentlyContinue
```

### 13.2. Bash / Linux Command
```bash
rm -f AUTO_MAPPING_ASSISTANT_SPEC.md Backend_report.md database_report.md docker_report.md ENGINE_REPORT.md mapping_assistant.md PROJECT_BRIEF.md database/README.md frontend/FRONTEND.md frontend/QUICKSTART.md frontend/README.md rag_chatbots/Read.md
```

> **Note**: Keeping only `README.md` and `MASTER_PROJECT_DOCUMENTATION.md` in your repository will ensure your workspace remains clean, organized, and easy for any human or AI agent to navigate.
