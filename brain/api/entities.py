"""
LogClaw Brain - Entities API
entities.py - Entity intelligence and behavioural timeline endpoints

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : REST endpoints for querying entity state, risk scores,
          behavioural timelines, and top-risk entity lists. Entities
          are users, IP addresses, hosts, and services tracked by
          the entity engine over time.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."
"""

# ── Standard Library ──────────────────────────────────────────────────────────
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/")
async def get_entities(
    request:     Request,
    limit:       int   = Query(default=100, ge=1, le=1000),
    offset:      int   = Query(default=0,   ge=0),
    entity_type: Optional[str] = Query(default=None, description="user|ip|host|service"),
    risk_min:    float = Query(default=0.0, ge=0.0, le=100.0),
    is_stale:    Optional[bool] = Query(default=None),
    search:      Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """
    Query tracked entities with optional filtering.
    Results are sorted by risk score descending.
    """
    entities, total = await request.app.state.storage.get_entities(
        limit=limit,
        offset=offset,
        entity_type=entity_type,
        risk_min=risk_min,
        is_stale=is_stale,
        search=search,
    )
    return {
        "entities": entities,
        "total":    total,
        "limit":    limit,
        "offset":   offset,
        "has_more": (offset + limit) < total,
    }


@router.get("/top-risk")
async def get_top_risk_entities(
    request:     Request,
    limit:       int   = Query(default=20, ge=1, le=100),
    entity_type: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """
    Get entities with the highest risk scores.
    Used by the frontend dashboard to show the most critical actors.
    """
    entities = await request.app.state.entity_engine.get_top_risk_entities(
        limit=limit,
        entity_type=entity_type,
    )
    return {
        "entities": entities,
        "count":    len(entities),
    }


@router.get("/stats")
async def get_entity_stats(request: Request) -> Dict[str, Any]:
    """Get entity engine statistics."""
    return await request.app.state.entity_engine.get_stats()


@router.get("/search")
async def search_entities(
    request: Request,
    q:       str = Query(..., min_length=1, description="Search query"),
    limit:   int = Query(default=20, ge=1, le=100),
) -> Dict[str, Any]:
    """Search entities by ID substring."""
    entities = await request.app.state.entity_engine.search_entities(
        query=q,
        limit=limit,
    )
    return {
        "entities": entities,
        "count":    len(entities),
        "query":    q,
    }


@router.get("/{entity_id}")
async def get_entity(
    request:   Request,
    entity_id: str,
) -> Dict[str, Any]:
    """Get a single entity by ID with full state."""
    # Try in-memory engine first (most up to date)
    entity = await request.app.state.entity_engine.get_entity(entity_id)
    if not entity:
        # Fall back to storage
        entity = await request.app.state.storage.get_entity(entity_id)
    if not entity:
        raise HTTPException(
            status_code=404,
            detail=f"Entity '{entity_id}' not found",
        )
    return entity


@router.get("/{entity_id}/timeline")
async def get_entity_timeline(
    request:   Request,
    entity_id: str,
    limit:     int   = Query(default=200, ge=1, le=1000),
    since:     Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """
    Get the behavioural timeline for an entity -
    every significant event this actor has been involved in,
    ordered newest first.
    """
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            pass

    timeline = await request.app.state.storage.get_entity_timeline(
        entity_id=entity_id,
        limit=limit,
        since=since_dt,
    )
    return {
        "entity_id": entity_id,
        "timeline":  timeline,
        "count":     len(timeline),
    }


@router.get("/{entity_id}/events")
async def get_entity_events(
    request:   Request,
    entity_id: str,
    limit:     int = Query(default=100, ge=1, le=500),
    since:     Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """
    Get all raw log events for an entity.
    Combines events where actor or target matches the entity ID.
    """
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            pass

    events, total = await request.app.state.storage.get_events(
        limit=limit,
        actor=entity_id,
        since=since_dt,
    )
    return {
        "entity_id": entity_id,
        "events":    events,
        "total":     total,
    }


@router.get("/{entity_id}/alerts")
async def get_entity_alerts(
    request:   Request,
    entity_id: str,
    limit:     int = Query(default=50, ge=1, le=200),
) -> Dict[str, Any]:
    """Get all alerts involving a specific entity."""
    alerts, total = await request.app.state.storage.get_alerts(
        limit=limit,
        actor=entity_id,
    )
    return {
        "entity_id": entity_id,
        "alerts":    alerts,
        "total":     total,
    }