# Project Brief: Universal Log Pre-processing Framework (ULPF)

> This document is written for an AI coding agent (e.g. Claude Code) to load as
> context before working on this codebase. It explains the problem, the scope
> boundaries, the architecture, the resources/stack in use, and the team
> structure, so an agent can make consistent decisions without re-deriving
> intent from scratch.

## 1. What this project is

A hackathon submission that ingests logs from **perimeter network devices**
(firewalls, IDS/IPS, VPN gateways, routers, proxies/WAFs) in whatever
vendor-specific format they arrive in, and normalizes them into a single,
lossless, analytics-ready schema — **OCSF (Open Cybersecurity Schema
Framework)** — while preserving the original raw event for forensic and
compliance traceability.

Working name under consideration: **Rosetta** (metaphor: a Rosetta Stone that
translates every vendor's log "language" into one common schema). Repo/config
names may still reference `ulpf` internally.

## 2. Problem statement (source)

Enterprises collect logs from network devices, servers, OS, applications,
databases, cloud, containers, IAM, IoT, and other platforms, in formats like
Syslog, JSON, XML, CSV, CEF, LEEF, and proprietary vendor schemas. This
diversity slows down SIEM ingestion, correlation, compliance reporting, and ML
applications, because security teams must hand-write a parser per source
before the data is usable.

The official deliverable asks for a **Universal Log Pre-processing Framework**
that can ingest, parse, normalize, and standardize logs from *any* hardware or
software system, while:

- (a) preserving complete raw event data without information loss
- (b) extracting and parsing source-specific attributes
- (c) normalizing fields into a common event taxonomy
- (d) maintaining traceability between normalized and original events
- (e) supporting plug-and-play onboarding of new log sources
- (f) providing unified visibility across enterprise environments
- (g) enabling efficient SIEM and data lake integration
- (h) producing AI/ML-ready output for security and operational analytics
- (i) reducing parser development effort
- (j) supporting air-gapped deployment
- (k) being packageable as a container for platform independence

## 3. Scope — what we ARE and ARE NOT building

The problem statement's background section mentions a very broad range of
sources (network devices, IoT, cloud, containers, IAM, etc.) to motivate *why*
a universal framework matters. Its **"Current Scope" section**, which is the
part actually graded, narrows this explicitly to:

> "Convert any perimeter network device-generated log or event — regardless
> of source, format, vendor, or technology — into a standardized, lossless,
> analytics-ready representation."

**In scope:**
- Perimeter network device logs only: firewalls, IDS/IPS, VPN gateways,
  routers, proxies/WAFs.
- Input formats: CSV, key=value syslog, JSON, plain syslog text, XML.
- Vendors targeted for demo mapping configs: Palo Alto Networks (PAN-OS),
  Fortinet (FortiOS), Cisco ASA, Suricata IDS, plus one more if time permits.
- OCSF as the normalization schema (adopted, not invented).
- A declarative, YAML-driven mapping/plugin system for onboarding new
  vendors without code changes.
- A unified dashboard, rule-based anomaly detection, a RAG chatbot grounded
  in the normalized event store, and SIEM/data lake export.
- Docker/Compose packaging suitable for air-gapped deployment.

**Explicitly out of scope for this build** (design should remain
extensible toward these, but do not implement them):
- IoT sensor/device log ingestion.
- Raw packet capture (.pcap) parsing — would require packet-level tooling
  (Scapy/tshark) and roughly triples scope.
- Training or fine-tuning any ML model. Normalization is schema mapping
  (config-driven), not machine learning. "AI/ML-ready" means the *output* is
  clean enough for someone else's ML pipeline to consume — it does not mean
  we train a model ourselves.
- Full production-grade SIEM connectors (e.g. a real Splunk HEC integration).
  A credible stand-in (NDJSON export + writing into OpenSearch/Elasticsearch)
  is sufficient.
- Cloud-hosted LLM dependency as a hard requirement — the chatbot should be
  runnable against a local model (Ollama) to respect the air-gapped
  deployment requirement; a cloud API may be used only as a demo-time
  fallback, clearly noted as such.

## 4. Architecture / pipeline

```
Raw log (CSV / kv-syslog / JSON / XML)
        │
        ▼
  [Detect]  — match against per-vendor YAML mapping configs
        │
        ▼
  [Parse]   — extract fields per that config's rules
        │        (CSV split / kv regex / JSON path / syslog regex)
        ▼
  [Classify] — assign OCSF class_uid (e.g. Network Activity, Detection Finding)
        │
        ▼
  [Map + Transform] — raw fields → nested OCSF paths (src_endpoint.ip, etc.),
        │              with value transforms (protocol number → name, etc.)
        ▼
  [Preserve] — attach untouched raw_data + a UUID linking raw ↔ normalized
        │
        ▼
  [Store]   — normalized JSON documents in a nested-JSON-capable store
        │
        ├──▶ [Unified Dashboard] — filterable event feed across all vendors
        ├──▶ [Anomaly Detection] — rule-based (pandas), no trained model
        ├──▶ [RAG Chatbot] — retrieval over the store + local LLM (Ollama)
        └──▶ [SIEM / Data Lake Export] — NDJSON or OpenSearch/Kafka write
```

### OCSF output shape

OCSF events are **nested JSON, not flat/tabular** — related fields are
grouped into reusable sub-objects. Example shape (illustrative, not literal
code):

```json
{
  "class_name": "Network Activity",
  "class_uid": 4001,
  "activity_name": "Deny",
  "activity_id": 6,
  "time": "2026-08-27T09:14:02Z",
  "src_endpoint": { "ip": "203.0.113.45", "port": 51322 },
  "dst_endpoint": { "ip": "10.0.4.12", "port": 22 },
  "connection_info": { "protocol_name": "TCP" },
  "firewall_rule": { "name": "rule-block-ssh-external" },
  "device": { "name": "edge-fw-01", "vendor_name": "Palo Alto Networks", "type": "Firewall" },
  "metadata": { "uid": "998812", "product": { "vendor_name": "Palo Alto Networks", "name": "PAN-OS" } },
  "unmapped": { "zone_in": "untrust", "zone_out": "trust" },
  "raw_data": "<the full original raw log line, untouched>"
}
```

- `unmapped` holds vendor-specific fields with no home in the standard OCSF
  schema yet — nothing is silently dropped.
- `raw_data` plus a shared event UUID is the traceability mechanism (source
  requirement d).

### YAML mapping config format (plug-and-play onboarding)

Each vendor/product is one YAML file. Adding a new source = adding a new
file to a watched `/mappings` directory; no application code changes.

Top-level sections a mapping config must define:
- `source_identity` — vendor, product, format, version
- `detection` — how the engine recognizes this format (regex, field
  presence, or JSON path existence) among all onboarded configs
- `parsing` — how to split the raw line into a field dict (delimiter +
  positional indices for CSV; kv regex pattern for key=value; JSON paths
  for JSON)
- `classification` — rules mapping parsed field values to an OCSF
  `class_uid` / `activity_id` / `activity_name`
- `field_map` — parsed field name → dotted OCSF path
- `static_fields` — constants this vendor always contributes (e.g. device
  vendor name/type)
- `transforms` — value lookups/casts applied during mapping (protocol
  number → name, severity level → OCSF severity string, etc.)
- `timestamp` — source field(s) and format string for event time
- `unmapped_policy` — what happens to fields not covered by `field_map`
  (should always be `bucket`, never `drop`)
- `raw_preservation` — whether/where to attach the untouched raw event

## 5. Tech stack / resources in use

Chosen to be realistically buildable by a 6-person team within a hackathon
timeframe — deliberately avoiding heavier infra that would need days to
provision.

| Layer | Choice | Notes |
|---|---|---|
| Parsing / normalization engine | Python + PyYAML + `re` | Config-driven mapper; no ML |
| API layer | FastAPI | REST endpoints for ingestion, query, export, chatbot |
| Storage | Elasticsearch or OpenSearch (single node), alternative MongoDB | Must support nested JSON natively; NDJSON + pandas is an acceptable minimal fallback for a demo dataset |
| Frontend | React + Recharts | Unified dashboard: stat cards, filters, event feed, drill-down raw/OCSF view, chatbot panel |
| Anomaly detection | Rule-based Python/pandas (groupby on IP / rule / time window) | Explainable, offline, no trained model |
| RAG chatbot | LangChain + LangGraph orchestrating retrieval over the normalized store, generation via a local LLM served through **Ollama** (e.g. Llama 3 8B) | LangChain/LangGraph chosen because the assigned team member already has experience with them; retrieval logic queries the datastore, not a vector-only store, unless embeddings are added later as a stretch goal |
| Packaging | Docker + docker-compose | Single-command startup of backend, store, and frontend; supports air-gapped deployment |

No component in this stack requires training a model from scratch. The only
place "AI" appears is (1) rule-based anomaly detection — not ML — and (2) the
RAG chatbot, which orchestrates a pre-trained, off-the-shelf LLM plus
retrieval code that the team writes.

## 6. Team structure (for context on ownership, not for the agent to manage)

| Person | Role(s) | Difficulty | Notes |
|---|---|---|---|
| A | Parsing Engine (core pipeline) → Backend API (ingestion + query endpoints) | High → Medium | Highest-dependency role; most other work depends on the engine being usable early |
| B | OCSF Mapping Configs (per-vendor YAML) → Backend API (export + admin endpoints) | Medium | Ships first configs early so A has real data to build against |
| C | Storage & Data Layer → supports RAG chatbot once storage stabilizes | Low–Medium → Medium | Also co-owns documentation with F |
| D | Frontend Dashboard | Medium | Builds against mocked data first, swaps to real endpoints later |
| E | AI Layer — RAG Chatbot (LangChain/LangGraph) | High | Depends on C's storage and A/B's normalized event shape |
| F | AI Layer — Anomaly Detection + DevOps/Packaging | Medium | Also co-owns documentation with C |

## 7. Deliverables required for submission

- Source code link (GitHub/Drive)
- README with setup instructions
- Architecture document (max 2 pages)
- Demo video (max 2 minutes)
- Technical presentation (max 5 slides)

## 8. Design principles an agent should follow when contributing

- **Prefer config over code.** New vendor support should always be
  expressible as a new YAML file, not a new code path.
- **Never drop data.** Any field not explicitly mapped goes into
  `unmapped`, not discarded.
- **Always preserve raw_data and the linking UUID** on every normalized
  event — this is a graded requirement, not optional.
- **Keep the AI layer honest and explainable.** Anomaly detection is
  rule-based, not a black-box model. The chatbot must ground its answers in
  retrieved events from the normalized store, not free-generate.
- **Assume offline/air-gapped as the default deployment target** — avoid
  hard dependencies on external network calls (cloud LLM APIs, external
  package registries at runtime, etc.) in the core pipeline.
- **Don't expand scope** to IoT, PCAP, or other source types unless
  explicitly asked — the mapping/plugin design should remain generalizable
  to them without actually implementing them for this build.
