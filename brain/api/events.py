"""
LogClaw Brain - Events API
events.py - Log event query and retrieval endpoints

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : REST endpoints for querying normalised log events from
          DuckDB and the in-memory ring buffer. Supports full
          filtering, pagination, time-range queries, and free-text
          search. Also provides the live event stream endpoint
          that feeds the frontend timeline via ring buffer snapshot.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."
"""

# ── Standard Library ──────────────────────────────────────────────────────────
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

router = APIRouter()


# ── Request / Response Models ─────────────────────────────────────────────────

class EventsResponse(BaseModel):
    events:  List[Dict[str, Any]]
    total:   int
    limit:   int
    offset:  int
    has_more: bool


class EventStatsResponse(BaseModel):
    total_events:      int
    events_last_hour:  int
    events_last_day:   int
    by_platform:       Dict[str, int]
    by_event_type:     Dict[str, int]
    by_severity:       Dict[str, int]
    top_sources:       List[Dict[str, Any]]
    top_actors:        List[Dict[str, Any]]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/", response_model=EventsResponse)
async def get_events(
    request:      Request,
    limit:        int   = Query(default=100, ge=1, le=1000),
    offset:       int   = Query(default=0,   ge=0),
    platform:     Optional[str] = Query(default=None),
    source:       Optional[str] = Query(default=None),
    actor:        Optional[str] = Query(default=None),
    event_type:   Optional[str] = Query(default=None),
    severity_min: int   = Query(default=0, ge=0, le=10),
    since:        Optional[str] = Query(default=None, description="ISO8601 timestamp"),
    until:        Optional[str] = Query(default=None, description="ISO8601 timestamp"),
    search:       Optional[str] = Query(default=None),
    live:         bool  = Query(default=False, description="Query ring buffer instead of DB"),
) -> EventsResponse:
    """
    Query log events with optional filtering.

    Set live=true to query the in-memory ring buffer for the most
    recent events without hitting the database.
    """
    since_dt = _parse_ts(since)
    until_dt = _parse_ts(until)

    if live:
        # Query ring buffer for recent events
        events = await request.app.state.ring_buffer.snapshot(
            limit=limit,
            platform=platform,
            source=source,
            actor=actor,
            event_type=event_type,
            severity_min=severity_min,
            since=since_dt,
            search=search,
        )
        return EventsResponse(
            events=events,
            total=len(events),
            limit=limit,
            offset=0,
            has_more=False,
        )

    # Query DuckDB
    events, total = await request.app.state.storage.get_events(
        limit=limit,
        offset=offset,
        platform=platform,
        source=source,
        actor=actor,
        event_type=event_type,
        severity_min=severity_min,
        since=since_dt,
        until=until_dt,
        search=search,
    )

    return EventsResponse(
        events=events,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@router.get("/recent")
async def get_recent_events(
    request: Request,
    count:   int = Query(default=50, ge=1, le=500),
) -> Dict[str, Any]:
    """
    Get the N most recent events from the ring buffer.
    Fast - no database hit.
    """
    events = await request.app.state.ring_buffer.recent(count=count)
    return {
        "events": events,
        "count":  len(events),
        "source": "ring_buffer",
    }


@router.get("/stats")
async def get_event_stats(request: Request) -> Dict[str, Any]:
    """
    Get aggregated event statistics.
    Computed from DuckDB for accuracy.
    """
    storage = request.app.state.storage

    try:
        # Total and recent counts
        base_stats = await storage.get_stats()

        # Per-platform breakdown
        by_platform = await _count_by_field(storage, "platform")

        # Per-event-type breakdown
        by_type = await _count_by_field(storage, "event_type")

        # Per-severity breakdown
        by_severity = await _count_by_severity(storage)

        # Top sources by event count
        top_sources = await _top_by_field(storage, "source", limit=10)

        # Top actors by event count
        top_actors = await _top_by_field(storage, "actor", limit=10)

        return {
            "total_events":     base_stats.get("events_total", 0),
            "events_last_hour": base_stats.get("events_last_hour", 0),
            "by_platform":      by_platform,
            "by_event_type":    by_type,
            "by_severity":      by_severity,
            "top_sources":      top_sources,
            "top_actors":       top_actors,
        }
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.get("/timeline")
async def get_event_timeline(
    request:   Request,
    since:     Optional[str] = Query(default=None),
    until:     Optional[str] = Query(default=None),
    bucket:    str = Query(default="hour", description="Time bucket: minute|hour|day"),
    platform:  Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """
    Get event counts bucketed by time - used to render the pulse
    heatmap in the frontend.
    """
    since_dt = _parse_ts(since) or _hours_ago(24)
    until_dt = _parse_ts(until) or datetime.now(timezone.utc)

    bucket_map = {
        "minute": "minute",
        "hour":   "hour",
        "day":    "day",
    }
    trunc = bucket_map.get(bucket, "hour")

    sql = f"""
        SELECT
            date_trunc('{trunc}', timestamp) AS bucket,
            COUNT(*) AS count,
            MAX(severity) AS max_severity
        FROM events
        WHERE timestamp >= ? AND timestamp <= ?
        {f"AND platform = '{platform}'" if platform else ""}
        GROUP BY bucket
        ORDER BY bucket ASC
    """

    try:
        import asyncio
        loop = asyncio.get_event_loop()
        rows = await loop.run_in_executor(
            None,
            request.app.state.storage._fetchall,
            sql,
            (since_dt.isoformat(), until_dt.isoformat()),
        )
        buckets = [
            {
                "time":         row[0].isoformat() if row[0] else "",
                "count":        row[1],
                "max_severity": row[2],
            }
            for row in rows
        ]
        return {
            "buckets":   buckets,
            "since":     since_dt.isoformat(),
            "until":     until_dt.isoformat(),
            "bucket":    bucket,
            "total":     sum(b["count"] for b in buckets),
        }
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.get("/{event_id}")
async def get_event(
    request:  Request,
    event_id: str,
) -> Dict[str, Any]:
    """Get a single event by ID."""
    events, _ = await request.app.state.storage.get_events(
        limit=1,
        search=event_id,
    )
    # Search by exact event_id
    sql = "SELECT * FROM events WHERE event_id = ?"
    import asyncio
    loop = asyncio.get_event_loop()
    rows = await loop.run_in_executor(
        None,
        request.app.state.storage._fetchall,
        sql,
        (event_id,),
    )
    if not rows:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

    return request.app.state.storage._row_to_event(rows[0])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ts(ts_str: Optional[str]) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def _hours_ago(hours: int) -> datetime:
    from datetime import timedelta
    return datetime.now(timezone.utc) - timedelta(hours=hours)


async def _count_by_field(storage, field: str) -> Dict[str, int]:
    import asyncio
    loop = asyncio.get_event_loop()
    rows = await loop.run_in_executor(
        None,
        storage._fetchall,
        f"SELECT {field}, COUNT(*) FROM events GROUP BY {field} ORDER BY COUNT(*) DESC",
        (),
    )
    return {str(r[0] or "unknown"): r[1] for r in rows}


async def _count_by_severity(storage) -> Dict[str, int]:
    import asyncio
    loop = asyncio.get_event_loop()
    rows = await loop.run_in_executor(
        None,
        storage._fetchall,
        """
        SELECT
            CASE
                WHEN severity >= 9 THEN 'CRITICAL'
                WHEN severity >= 7 THEN 'HIGH'
                WHEN severity >= 5 THEN 'MEDIUM'
                WHEN severity >= 3 THEN 'LOW'
                ELSE 'INFO'
            END AS level,
            COUNT(*) AS count
        FROM events
        GROUP BY level
        ORDER BY count DESC
        """,
        (),
    )
    return {str(r[0]): r[1] for r in rows}


async def _top_by_field(
    storage,
    field: str,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    import asyncio
    loop = asyncio.get_event_loop()
    rows = await loop.run_in_executor(
        None,
        storage._fetchall,
        f"""
        SELECT {field}, COUNT(*) AS event_count
        FROM events
        WHERE {field} IS NOT NULL AND {field} != 'unknown'
        GROUP BY {field}
        ORDER BY event_count DESC
        LIMIT {limit}
        """,
        (),
    )
    return [{"name": str(r[0]), "count": r[1]} for r in rows]