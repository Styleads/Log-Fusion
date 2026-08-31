import json
from typing import Callable, Optional, Union
from uuid import uuid4

import pandas as pd


EVENT_UID_COLUMNS = (
    "metadata.uid",
    "event_uid",
    "uid",
)


def _flatten(records: list) -> pd.DataFrame:
    """Flatten normalized OCSF events for pandas-based anomaly rules.

    The original nested event is preserved in raw_data and metadata.uid/event_uid
    is preserved as event_uid for traceability.
    """
    if not records:
        return pd.DataFrame(
            columns=[
                "time",
                "src_endpoint.ip",
                "dst_endpoint.ip",
                "dst_endpoint.port",
                "activity_name",
                "event_uid",
                "raw_data",
            ]
        )

    df = pd.json_normalize(records)

    # Preserve/derive the traceability UUID.
    uid_column = next((c for c in EVENT_UID_COLUMNS if c in df.columns), None)
    if uid_column:
        df["event_uid"] = df[uid_column].astype("string")
    else:
        df["event_uid"] = [str(uuid4()) for _ in range(len(df))]

    # Normalized events should already contain raw_data. If they do not,
    # retain a JSON representation rather than silently losing the event.
    if "raw_data" not in df.columns:
        df["raw_data"] = [
            json.dumps(record, default=str, ensure_ascii=False)
            for record in records
        ]

    if "time" in df.columns:
        df["time"] = pd.to_datetime(df["time"], utc=True, errors="coerce")
        df = df.dropna(subset=["time"]).sort_values("time").reset_index(drop=True)

    return df


def load_events(source: Union[str, list, pd.DataFrame]) -> pd.DataFrame:
    """Load normalized OCSF events from NDJSON, a list of dicts, or a DataFrame."""
    if isinstance(source, pd.DataFrame):
        df = source.copy()

        if "time" in df.columns:
            df["time"] = pd.to_datetime(df["time"], utc=True, errors="coerce")

        if "event_uid" not in df.columns:
            uid_column = next((c for c in EVENT_UID_COLUMNS if c in df.columns), None)
            if uid_column:
                df["event_uid"] = df[uid_column].astype("string")
            else:
                df["event_uid"] = [str(uuid4()) for _ in range(len(df))]

        return df

    if isinstance(source, list):
        return _flatten(source)

    if isinstance(source, str):
        records = []
        with open(source, "r", encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON on line {line_number} of {source}: {exc}"
                    ) from exc
        return _flatten(records)

    raise TypeError(f"Unsupported event source type: {type(source)}")


def load_events_from_opensearch(
    client,
    index: str,
    query: Optional[dict] = None,
    size: int = 10000,
) -> pd.DataFrame:
    """Load normalized OCSF events from OpenSearch.

    Note: this is suitable for a demo-sized result set. For production-scale
    retrieval, use OpenSearch pagination/scroll/search_after.
    """
    if size <= 0:
        raise ValueError("size must be greater than 0")

    body = {
        "query": query or {"match_all": {}},
        "size": size,
    }
    response = client.search(index=index, body=body)
    hits = response.get("hits", {}).get("hits", [])
    records = [hit.get("_source", {}) for hit in hits]
    return _flatten(records)


def _empty_result(columns: list[str]) -> pd.DataFrame:
    return pd.DataFrame(columns=columns)


def detect_port_scans(
    df: pd.DataFrame,
    window_minutes: int = 5,
    distinct_port_threshold: int = 15,
) -> pd.DataFrame:
    """Flag a source IP contacting many distinct destination ports."""
    required = {"src_endpoint.ip", "dst_endpoint.port", "time"}
    if not required.issubset(df.columns):
        return _empty_result(
            ["src_endpoint.ip", "time", "distinct_ports", "rule", "reason", "event_uids"]
        )

    working = df.dropna(subset=list(required)).copy()
    if working.empty:
        return _empty_result(
            ["src_endpoint.ip", "time", "distinct_ports", "rule", "reason", "event_uids"]
        )

    working["window"] = working["time"].dt.floor(f"{window_minutes}min")

    grouped = (
        working.groupby(["src_endpoint.ip", "window"], dropna=False)
        .agg(
            distinct_ports=("dst_endpoint.port", "nunique"),
            event_uids=("event_uid", lambda values: list(values.dropna().astype(str))),
        )
        .reset_index()
        .rename(columns={"window": "time"})
    )

    flagged = grouped[grouped["distinct_ports"] > distinct_port_threshold].copy()
    flagged["rule"] = "port_scan"
    flagged["reason"] = flagged["distinct_ports"].apply(
        lambda n: (
            f"contacted {n} distinct ports within {window_minutes} min "
            f"(threshold={distinct_port_threshold})"
        )
    )
    return flagged


def detect_excessive_denies(
    df: pd.DataFrame,
    window_minutes: int = 5,
    deny_threshold: int = 20,
) -> pd.DataFrame:
    """Flag source IPs with many denied connections in a time window."""
    required = {"src_endpoint.ip", "activity_name", "time"}
    if not required.issubset(df.columns):
        return _empty_result(
            ["src_endpoint.ip", "time", "deny_count", "rule", "reason", "event_uids"]
        )

    activity = df["activity_name"].astype("string").str.strip().str.lower()
    denies = df[activity == "deny"].dropna(
        subset=["src_endpoint.ip", "time"]
    ).copy()

    if denies.empty:
        return _empty_result(
            ["src_endpoint.ip", "time", "deny_count", "rule", "reason", "event_uids"]
        )

    denies["window"] = denies["time"].dt.floor(f"{window_minutes}min")

    grouped = (
        denies.groupby(["src_endpoint.ip", "window"], dropna=False)
        .agg(
            deny_count=("activity_name", "size"),
            event_uids=("event_uid", lambda values: list(values.dropna().astype(str))),
        )
        .reset_index()
        .rename(columns={"window": "time"})
    )

    flagged = grouped[grouped["deny_count"] > deny_threshold].copy()
    flagged["rule"] = "excessive_denies"
    flagged["reason"] = flagged["deny_count"].apply(
        lambda n: (
            f"{n} denied connections within {window_minutes} min "
            f"(threshold={deny_threshold})"
        )
    )
    return flagged


def detect_traffic_spikes(
    df: pd.DataFrame,
    window_minutes: int = 60,
    spike_multiplier: float = 3.0,
    minimum_baseline_windows: int = 2,
) -> pd.DataFrame:
    """Flag a source IP when its latest window exceeds its historical baseline.

    The baseline is calculated from previous windows only, so the suspicious
    latest window cannot inflate its own baseline.
    """
    required = {"src_endpoint.ip", "time"}
    if not required.issubset(df.columns):
        return _empty_result(
            [
                "src_endpoint.ip",
                "time",
                "event_count",
                "baseline_avg",
                "spike_ratio",
                "rule",
                "reason",
                "event_uids",
            ]
        )

    working = df.dropna(subset=list(required)).copy()
    if working.empty:
        return _empty_result(
            [
                "src_endpoint.ip",
                "time",
                "event_count",
                "baseline_avg",
                "spike_ratio",
                "rule",
                "reason",
                "event_uids",
            ]
        )

    working["window"] = working["time"].dt.floor(f"{window_minutes}min")

    per_ip_window = (
        working.groupby(["src_endpoint.ip", "window"], dropna=False)
        .agg(
            event_count=("time", "size"),
            event_uids=("event_uid", lambda values: list(values.dropna().astype(str))),
        )
        .reset_index()
    )

    latest_window = per_ip_window["window"].max()
    latest = per_ip_window[per_ip_window["window"] == latest_window].copy()

    historical = per_ip_window[per_ip_window["window"] < latest_window].copy()

    baseline = (
        historical.groupby("src_endpoint.ip")["event_count"]
        .agg(["mean", "count"])
        .rename(columns={"mean": "baseline_avg", "count": "baseline_windows"})
        .reset_index()
    )

    latest = latest.merge(baseline, on="src_endpoint.ip", how="left")
    latest = latest[latest["baseline_windows"] >= minimum_baseline_windows].copy()

    latest["spike_ratio"] = (
        latest["event_count"] / latest["baseline_avg"].replace(0, pd.NA)
    )

    flagged = latest[latest["spike_ratio"] >= spike_multiplier].copy()
    flagged["time"] = flagged["window"]
    flagged["rule"] = "traffic_spike"
    flagged["reason"] = flagged.apply(
        lambda r: (
            f"{r['event_count']} events in latest {window_minutes}-min window vs "
            f"baseline avg {r['baseline_avg']:.1f} "
            f"({r['spike_ratio']:.1f}x, threshold={spike_multiplier}x)"
        ),
        axis=1,
    )

    return flagged[
        [
            "src_endpoint.ip",
            "time",
            "event_count",
            "baseline_avg",
            "baseline_windows",
            "spike_ratio",
            "rule",
            "reason",
            "event_uids",
        ]
    ]


DEFAULT_RULES: dict[str, Callable[..., pd.DataFrame]] = {
    "port_scan": detect_port_scans,
    "excessive_denies": detect_excessive_denies,
    "traffic_spike": detect_traffic_spikes,
}


def run_all_rules(
    df: pd.DataFrame,
    rules: Optional[dict[str, Callable[..., pd.DataFrame]]] = None,
    rule_kwargs: Optional[dict] = None,
) -> pd.DataFrame:
    rules = rules or DEFAULT_RULES
    rule_kwargs = rule_kwargs or {}

    results = []

    for name, fn in rules.items():
        kwargs = rule_kwargs.get(name, {})
        result = fn(df, **kwargs)

        if not result.empty:
            result["detected_at"] = pd.Timestamp.now(tz="UTC")
            results.append(result)

    if not results:
        return pd.DataFrame(
            columns=["rule", "reason", "detected_at", "event_uids"]
        )

    return pd.concat(results, ignore_index=True, sort=False)


def analyze(
    source: Union[str, list, pd.DataFrame],
    rules: Optional[dict[str, Callable[..., pd.DataFrame]]] = None,
    rule_kwargs: Optional[dict] = None,
    as_records: bool = True,
):
    """Run all anomaly rules against normalized OCSF events."""
    df = load_events(source)
    result_df = run_all_rules(df, rules=rules, rule_kwargs=rule_kwargs)

    if as_records:
        return result_df.to_dict(orient="records")
    return result_df


def export_anomalies_ndjson(anomalies, out_path: str) -> None:
    """Export anomaly findings as NDJSON."""
    records = (
        anomalies.to_dict(orient="records")
        if isinstance(anomalies, pd.DataFrame)
        else anomalies
    )

    with open(out_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print(
            "Usage: python anomaly_detection.py "
            "<input_events.ndjson> <output_anomalies.ndjson>"
        )
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]

    anomalies = analyze(input_path)
    export_anomalies_ndjson(anomalies, output_path)

    print(f"Flagged {len(anomalies)} anomalies -> {output_path}")
