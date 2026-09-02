import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from opensearchpy import OpenSearch, helpers
from pydantic import BaseModel, Field


OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
INDEX_NAME = os.getenv("OPENSEARCH_INDEX", "ulpf-events")



app = FastAPI(
    title="ULPF Storage API",
    version="1.0.0",
    description="Basic OpenSearch storage layer for normalized security events.",
)


client = OpenSearch(
    hosts=[
        {
            "host": OPENSEARCH_HOST,
            "port": OPENSEARCH_PORT
        }
    ],
    http_compress=True,
    use_ssl=False,
    verify_certs=False,
    ssl_show_warn=False,
)


# ---------------------------------------------------------
# Event models
# ---------------------------------------------------------

class Event(BaseModel):
    event_id: str = Field(..., min_length=1)

    normalized_event: Dict[str, Any] = Field(
        default_factory=dict
    )

    raw_event: Any

    provenance: Dict[str, Any] = Field(
        default_factory=dict
    )


class BulkEvents(BaseModel):
    events: List[Event]


# ---------------------------------------------------------
# OpenSearch index creation
# ---------------------------------------------------------

def ensure_index():

    if client.indices.exists(index=INDEX_NAME):
        return

    mapping = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        },

        "mappings": {
            "dynamic": True,

            "properties": {

                "event_id": {
                    "type": "keyword"
                },

                "ingested_at": {
                    "type": "date"
                },

                "raw_event": {
                    "type": "object",
                    "enabled": True
                },

                "provenance": {
                    "type": "object",
                    "dynamic": True
                },

                "normalized_event": {

                    "type": "object",

                    "dynamic": True,

                    "properties": {

                        "time": {
                            "type": "date"
                        },

                        "severity_id": {
                            "type": "integer"
                        },

                        "activity_id": {
                            "type": "integer"
                        },

                        "class_uid": {
                            "type": "integer"
                        },

                        "category_uid": {
                            "type": "integer"
                        },

                        "message": {
                            "type": "text"
                        },

                        "src_endpoint": {

                            "type": "object",

                            "dynamic": True,

                            "properties": {

                                "ip": {
                                    "type": "ip"
                                },

                                "port": {
                                    "type": "integer"
                                }
                            }
                        },

                        "dst_endpoint": {

                            "type": "object",

                            "dynamic": True,

                            "properties": {

                                "ip": {
                                    "type": "ip"
                                },

                                "port": {
                                    "type": "integer"
                                }
                            }
                        },

                        "device": {
                            "type": "object",
                            "dynamic": True
                        }
                    }
                }
            }
        }
    }

    client.indices.create(
        index=INDEX_NAME,
        body=mapping
    )


# ---------------------------------------------------------
# Startup
# ---------------------------------------------------------

@app.on_event("startup")
def startup():

    try:
        ensure_index()

    except Exception:
        # OpenSearch may still be starting.
        pass


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

@app.get("/health")
def health():

    try:

        info = client.info()

        ensure_index()

        return {
            "status": "ok",
            "opensearch": "reachable",
            "cluster_name": info.get("cluster_name"),
            "index": INDEX_NAME
        }

    except Exception as exc:

        raise HTTPException(
            status_code=503,
            detail=f"OpenSearch unavailable: {exc}"
        )


# ---------------------------------------------------------
# Insert one event
# ---------------------------------------------------------

@app.post("/events")
def create_event(event: Event):

    try:

        ensure_index()

        document = event.model_dump()

        document["ingested_at"] = (
            datetime.now(timezone.utc).isoformat()
        )

        client.index(
            index=INDEX_NAME,
            id=event.event_id,
            body=document,
            refresh="true"
        )

        return {
            "status": "accepted",
            "event_id": event.event_id
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )


# ---------------------------------------------------------
# Bulk insert
# ---------------------------------------------------------

@app.post("/events/bulk")
def create_events_bulk(payload: BulkEvents):

    try:

        ensure_index()

        actions = []

        for event in payload.events:

            document = event.model_dump()

            document["ingested_at"] = (
                datetime.now(timezone.utc).isoformat()
            )

            actions.append(
                {
                    "_op_type": "index",
                    "_index": INDEX_NAME,
                    "_id": event.event_id,
                    "_source": document
                }
            )

        success, errors = helpers.bulk(
            client,
            actions,
            raise_on_error=False,
            refresh="true"
        )

        return {
            "status": "completed",
            "accepted": success,
            "failed": len(errors),
            "errors": errors[:20]
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )


# ---------------------------------------------------------
# Search events
# ---------------------------------------------------------

@app.get("/events/search")
def search_events(

    keyword: Optional[str] = None,

    severity_id: Optional[int] = None,

    activity_id: Optional[int] = None,

    class_uid: Optional[int] = None,

    source_ip: Optional[str] = None,

    destination_ip: Optional[str] = None,

    vendor: Optional[str] = None,

    limit: int = Query(
        default=50,
        ge=1,
        le=500
    )
):

    must = []

    filters = []

    # Keyword search

    if keyword:

        must.append(
            {
                "multi_match": {
                    "query": keyword,
                    "fields": [
                        "normalized_event.message",
                        "normalized_event.*"
                    ]
                }
            }
        )

    # Severity

    if severity_id is not None:

        filters.append(
            {
                "term": {
                    "normalized_event.severity_id":
                        severity_id
                }
            }
        )

    # Activity

    if activity_id is not None:

        filters.append(
            {
                "term": {
                    "normalized_event.activity_id":
                        activity_id
                }
            }
        )

    # Class

    if class_uid is not None:

        filters.append(
            {
                "term": {
                    "normalized_event.class_uid":
                        class_uid
                }
            }
        )

    # Source IP

    if source_ip:

        filters.append(
            {
                "term": {
                    "normalized_event.src_endpoint.ip":
                        source_ip
                }
            }
        )

    # Destination IP

    if destination_ip:

        filters.append(
            {
                "term": {
                    "normalized_event.dst_endpoint.ip":
                        destination_ip
                }
            }
        )

    # Vendor

    if vendor:

        filters.append(
            {
                "term": {
                    "normalized_event.device.vendor":
                        vendor
                }
            }
        )

    body = {

        "size": limit,

        "sort": [
            {
                "normalized_event.time": {
                    "order": "desc",
                    "unmapped_type": "date"
                }
            }
        ],

        "query": {

            "bool": {

                "must": (
                    must
                    if must
                    else [{"match_all": {}}]
                ),

                "filter": filters
            }
        }
    }

    try:

        ensure_index()

        result = client.search(
            index=INDEX_NAME,
            body=body
        )

        return {

            "total":
                result["hits"]["total"]["value"],

            "events":
                [
                    hit["_source"]
                    for hit in result["hits"]["hits"]
                ]
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )




# ---------------------------------------------------------
# Statistics
# ---------------------------------------------------------

@app.get("/events/stats")
def event_stats():

    body = {

        "size": 0,

        "aggs": {

            "severity": {

                "terms": {

                    "field":
                        "normalized_event.severity_id",

                    "size": 20
                }
            },

            "activity": {

                "terms": {

                    "field":
                        "normalized_event.activity_id",

                    "size": 20
                }
            },

            "vendors": {

                "terms": {

                    "field":
                        "normalized_event.device.vendor.keyword",

                    "size": 20
                }
            }
        }
    }

    try:

        ensure_index()

        result = client.search(
            index=INDEX_NAME,
            body=body
        )

        return {

            "total_events":
                result["hits"]["total"]["value"],

            "severity_counts": {

                str(bucket["key"]):
                    bucket["doc_count"]

                for bucket
                in result["aggregations"]
                    ["severity"]["buckets"]
            },

            "activity_counts": {

                str(bucket["key"]):
                    bucket["doc_count"]

                for bucket
                in result["aggregations"]
                    ["activity"]["buckets"]
            },

            "vendor_counts": {

                str(bucket["key"]):
                    bucket["doc_count"]

                for bucket
                in result["aggregations"]
                    ["vendors"]["buckets"]
            }
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )


# ---------------------------------------------------------
# Get event by ID
# ---------------------------------------------------------

@app.get("/events/{event_id}")
def get_event(event_id: str):

    try:

        result = client.get(
            index=INDEX_NAME,
            id=event_id
        )

        return result["_source"]

    except Exception as exc:

        if getattr(exc, "status_code", None) == 404:

            raise HTTPException(
                status_code=404,
                detail="Event not found"
            )

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )


