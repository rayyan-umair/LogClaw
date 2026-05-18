"""
LogClaw Brain - Investigations API
investigations.py - Investigation case management endpoints

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : REST endpoints for creating and managing investigation
          cases. Cases group related alerts, events, and analyst
          notes into a single tracked workflow. Supports case
          creation, note addition, status updates, and timeline
          export.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

router = APIRouter()


# ── Request Models ────────────────────────────────────────────────────────────

class CreateInvestigationRequest(BaseModel):
    title:       str
    description: Optional[str] = None
    severity:    str = "MEDIUM"
    assigned_to: Optional[str] = None
    alert_ids:   List[str] = []
    event_ids:   List[str] = []


class AddNoteRequest(BaseModel):
    content:    str
    author:     Optional[str] = "analyst"
    note_type:  str = "note"  # note | action | finding


class UpdateStatusRequest(BaseModel):
    status:     str   # open | in_progress | closed
    by:         Optional[str] = None


class AddAlertsRequest(BaseModel):
    alert_ids: List[str]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/")
async def get_investigations(
    request: Request,
    limit:   int = Query(default=50, ge=1, le=200),
    offset:  int = Query(default=0,  ge=0),
    status:  Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Get investigation cases with optional status filter."""
    investigations, total = await request.app.state.storage.get_investigations(
        limit=limit,
        offset=offset,
        status=status,
    )
    return {
        "investigations": investigations,
        "total":          total,
        "limit":          limit,
        "offset":         offset,
        "has_more":       (offset + limit) < total,
    }


@router.post("/")
async def create_investigation(
    request: Request,
    body:    CreateInvestigationRequest,
) -> Dict[str, Any]:
    """Create a new investigation case."""
    investigation_id = str(uuid.uuid4())
    investigation = {
        "investigation_id": investigation_id,
        "title":            body.title,
        "description":      body.description,
        "severity":         body.severity,
        "assigned_to":      body.assigned_to,
        "alert_ids":        body.alert_ids,
        "event_ids":        body.event_ids,
        "status":           "open",
    }

    success = await request.app.state.storage.create_investigation(investigation)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to create investigation")

    return {
        "investigation_id": investigation_id,
        "created":          True,
        "title":            body.title,
    }


@router.get("/{investigation_id}")
async def get_investigation(
    request:          Request,
    investigation_id: str,
) -> Dict[str, Any]:
    """Get a single investigation case with full detail."""
    import asyncio
    loop = asyncio.get_event_loop()
    rows = await loop.run_in_executor(
        None,
        request.app.state.storage._fetchall,
        """
        SELECT investigation_id, title, description, status,
               severity, assigned_to, alert_ids, event_ids,
               notes, timeline, created_at, updated_at, closed_at
        FROM investigations WHERE investigation_id = ?
        """,
        (investigation_id,),
    )
    if not rows:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation {investigation_id} not found",
        )
    return request.app.state.storage._row_to_investigation(rows[0])


@router.post("/{investigation_id}/notes")
async def add_note(
    request:          Request,
    investigation_id: str,
    body:             AddNoteRequest,
) -> Dict[str, Any]:
    """Add a note, action record, or finding to an investigation."""
    import asyncio
    loop = asyncio.get_event_loop()

    # Get current notes
    rows = await loop.run_in_executor(
        None,
        request.app.state.storage._fetchall,
        "SELECT notes FROM investigations WHERE investigation_id = ?",
        (investigation_id,),
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Investigation not found")

    notes = json.loads(rows[0][0]) if rows[0][0] else []
    note  = {
        "id":         str(uuid.uuid4()),
        "content":    body.content,
        "author":     body.author,
        "note_type":  body.note_type,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }
    notes.append(note)

    await loop.run_in_executor(
        None,
        request.app.state.storage._exec,
        """
        UPDATE investigations
        SET notes = ?, updated_at = now()
        WHERE investigation_id = ?
        """,
        (json.dumps(notes), investigation_id),
    )
    await loop.run_in_executor(
        None,
        request.app.state.storage._conn.commit,
    )

    return {
        "investigation_id": investigation_id,
        "note":             note,
        "added":            True,
    }


@router.patch("/{investigation_id}/status")
async def update_investigation_status(
    request:          Request,
    investigation_id: str,
    body:             UpdateStatusRequest,
) -> Dict[str, Any]:
    """Update investigation status."""
    valid = {"open", "in_progress", "closed"}
    if body.status not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Status must be one of: {valid}",
        )

    import asyncio
    loop = asyncio.get_event_loop()

    if body.status == "closed":
        sql    = "UPDATE investigations SET status=?, closed_at=now(), updated_at=now() WHERE investigation_id=?"
        params = (body.status, investigation_id)
    else:
        sql    = "UPDATE investigations SET status=?, updated_at=now() WHERE investigation_id=?"
        params = (body.status, investigation_id)

    await loop.run_in_executor(
        None,
        request.app.state.storage._exec,
        sql,
        params,
    )
    await loop.run_in_executor(
        None,
        request.app.state.storage._conn.commit,
    )

    return {
        "investigation_id": investigation_id,
        "status":           body.status,
        "updated":          True,
    }


@router.post("/{investigation_id}/alerts")
async def add_alerts_to_investigation(
    request:          Request,
    investigation_id: str,
    body:             AddAlertsRequest,
) -> Dict[str, Any]:
    """Add additional alerts to an existing investigation."""
    import asyncio
    loop = asyncio.get_event_loop()

    rows = await loop.run_in_executor(
        None,
        request.app.state.storage._fetchall,
        "SELECT alert_ids FROM investigations WHERE investigation_id = ?",
        (investigation_id,),
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Investigation not found")

    existing = json.loads(rows[0][0]) if rows[0][0] else []
    merged   = list(set(existing + body.alert_ids))

    await loop.run_in_executor(
        None,
        request.app.state.storage._exec,
        "UPDATE investigations SET alert_ids=?, updated_at=now() WHERE investigation_id=?",
        (json.dumps(merged), investigation_id),
    )
    await loop.run_in_executor(
        None,
        request.app.state.storage._conn.commit,
    )

    return {
        "investigation_id": investigation_id,
        "alert_ids":        merged,
        "added":            len(body.alert_ids),
    }