# ULPF Storage & Data Layer

Basic standalone storage component for the Log-Fusion / ULPF project.

## Purpose

This component provides a storage layer for normalized security events.

It uses:

- OpenSearch
- FastAPI
- Docker

The component is currently standalone. Integration with the team's parser and normalization pipeline can be performed later.

## Architecture

Normalized Event
       |
       v
   FastAPI API
       |
       v
   OpenSearch
       |
       v
Search / Statistics

## OpenSearch Index

The main index is:

ulpf-events

## Features

- Store normalized events
- Preserve raw events
- Event ID traceability
- Bulk event ingestion
- Event search
- Basic statistics
- Docker deployment
- Dynamic support for additional fields

## API

### Health

GET /health

### Insert Event

POST /events

### Bulk Insert

POST /events/bulk

### Get Event

GET /events/{event_id}

### Search

GET /events/search

Example:

GET /events/search?severity_id=3

### Statistics

GET /events/stats

## Running

From the database directory:

docker compose up -d --build

Then open:

http://localhost:8000/docs

OpenSearch:

http://localhost:9200

## Stopping

docker compose down

## Data Preservation

Every stored event contains:

- event_id
- normalized_event
- raw_event
- provenance
- ingested_at

The raw event is retained so that the original source data can be traced back from the normalized representation.

## Current Scope

This is a basic development component.

Production deployment would require additional security, TLS, authentication, replicas, backups, monitoring, and resource configuration.
