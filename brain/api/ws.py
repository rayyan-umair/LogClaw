"""
LogClaw Brain - WebSocket API
ws.py - Real-time event and alert streaming via WebSocket

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : WebSocket endpoints for streaming live events and alerts
          to the frontend dashboard. Clients subscribe and receive
          a snapshot of recent events immediately on connection,
          then receive new events and alerts in real time as they
          arrive. Supports per-connection filtering so the frontend
          can subscribe to only high-severity events or specific
          platforms without the server sending unnecessary data.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Set

# ── Third Party ───────────────────────────────────────────────────────────────
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

router = APIRouter()
log    = logging.getLogger("logclaw.ws")

# ── Connection Manager ────────────────────────────────────────────────────────

class ConnectionManager:
    """
    Manages all active WebSocket connections.
    Handles broadcast to all connections and per-connection messaging.
    Thread-safe via asyncio lock.
    """

    def __init__(self):
        self._connections: Dict[str, WebSocket] = {}
        self._lock        = asyncio.Lock()
        self.total_connected = 0
        self.total_messages  = 0

    async def connect(self, ws: WebSocket, conn_id: str):
        await ws.accept()
        async with self._lock:
            self._connections[conn_id] = ws
            self.total_connected += 1
        log.info(f"[WS] Connected: {conn_id} - total: {len(self._connections)}")

    async def disconnect(self, conn_id: str):
        async with self._lock:
            self._connections.pop(conn_id, None)
        log.info(f"[WS] Disconnected: {conn_id} - total: {len(self._connections)}")

    async def send(self, conn_id: str, message: Dict) -> bool:
        """Send a message to a specific connection. Returns False if failed."""
        async with self._lock:
            ws = self._connections.get(conn_id)
        if not ws:
            return False
        try:
            await ws.send_text(json.dumps(message, default=str))
            self.total_messages += 1
            return True
        except Exception:
            await self.disconnect(conn_id)
            return False

    async def broadcast(self, message: Dict):
        """Send a message to all connected clients."""
        async with self._lock:
            connections = dict(self._connections)

        failed = []
        for conn_id, ws in connections.items():
            try:
                await ws.send_text(json.dumps(message, default=str))
                self.total_messages += 1
            except Exception:
                failed.append(conn_id)

        for conn_id in failed:
            await self.disconnect(conn_id)

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    @property
    def stats(self) -> Dict:
        return {
            "active":          self.connection_count,
            "total_connected": self.total_connected,
            "total_messages":  self.total_messages,
        }


# Global connection manager instance
manager = ConnectionManager()


# ── Broadcast Callback ────────────────────────────────────────────────────────

async def broadcast_alert(alert_message: Dict):
    """
    Called by the correlation engine when a new alert is generated.
    Broadcasts to all connected WebSocket clients immediately.
    """
    await manager.broadcast({
        "type":      "alert",
        "data":      alert_message.get("data", alert_message),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ── WebSocket Endpoints ───────────────────────────────────────────────────────

@router.websocket("/events")
async def ws_events(
    websocket:    WebSocket,
    platform:     Optional[str] = Query(default=None),
    severity_min: int           = Query(default=0),
    snapshot:     int           = Query(default=100),
):
    """
    WebSocket endpoint for live event streaming.

    On connection:
    - Sends a snapshot of the N most recent events
    - Registers as a subscriber to the ring buffer
    - Streams new events in real time as they arrive

    Query params:
    - platform:     Filter to a specific platform (windows|linux|network)
    - severity_min: Minimum severity 0-10
    - snapshot:     How many recent events to send on connect (default 100)
    """
    conn_id = str(uuid.uuid4())
    await manager.connect(websocket, conn_id)

    # Build filter function
    filter_fn = _build_event_filter(platform, severity_min)

    # Subscribe to ring buffer
    ring_buffer = websocket.app.state.ring_buffer
    subscriber  = await ring_buffer.subscribe(
        subscriber_id=conn_id,
        filter_fn=filter_fn,
        snapshot_count=snapshot,
        queue_size=2000,
    )

    # Send connection confirmation
    await manager.send(conn_id, {
        "type":     "connected",
        "conn_id":  conn_id,
        "filters":  {"platform": platform, "severity_min": severity_min},
        "snapshot": snapshot,
        "time":     datetime.now(timezone.utc).isoformat(),
    })

    try:
        # Stream loop - send events from subscriber queue to WebSocket
        while True:
            try:
                event = await asyncio.wait_for(
                    subscriber.get(),
                    timeout=30.0,
                )
                sent = await manager.send(conn_id, {
                    "type":  "event",
                    "data":  event,
                })
                if not sent:
                    break
            except asyncio.TimeoutError:
                # Send heartbeat to keep connection alive
                sent = await manager.send(conn_id, {
                    "type": "heartbeat",
                    "time": datetime.now(timezone.utc).isoformat(),
                })
                if not sent:
                    break

            # Check for client messages (e.g. filter updates)
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=0.01,
                )
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await manager.send(conn_id, {"type": "pong"})
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

    except WebSocketDisconnect:
        pass
    except Exception as ex:
        log.error(f"[WS] Event stream error {conn_id}: {ex}")
    finally:
        await ring_buffer.unsubscribe(conn_id)
        await manager.disconnect(conn_id)


@router.websocket("/alerts")
async def ws_alerts(websocket: WebSocket):
    """
    WebSocket endpoint for live alert streaming.
    Receives new alerts immediately when generated by the correlation engine.
    Also sends recent open alerts on connection.
    """
    conn_id = str(uuid.uuid4())
    await manager.connect(websocket, conn_id)

    # Send recent open alerts as snapshot
    try:
        alerts, _ = await websocket.app.state.storage.get_alerts(
            limit=20,
            status="open",
        )
        await manager.send(conn_id, {
            "type":    "alert_snapshot",
            "alerts":  alerts,
            "count":   len(alerts),
        })
    except Exception as ex:
        log.error(f"[WS] Alert snapshot error: {ex}")

    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0,
                )
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await manager.send(conn_id, {
                        "type": "pong",
                        "time": datetime.now(timezone.utc).isoformat(),
                    })
                elif msg.get("type") == "subscribe_alert":
                    # Client subscribing to a specific alert ID for updates
                    pass
            except asyncio.TimeoutError:
                await manager.send(conn_id, {
                    "type": "heartbeat",
                    "time": datetime.now(timezone.utc).isoformat(),
                })
    except WebSocketDisconnect:
        pass
    except Exception as ex:
        log.error(f"[WS] Alert stream error {conn_id}: {ex}")
    finally:
        await manager.disconnect(conn_id)


@router.websocket("/dashboard")
async def ws_dashboard(websocket: WebSocket):
    """
    Combined WebSocket for the main dashboard.
    Streams both events and alerts, plus periodic stat updates.
    """
    conn_id = str(uuid.uuid4())
    await manager.connect(websocket, conn_id)

    # Subscribe to ring buffer with high-severity filter for dashboard
    ring_buffer = websocket.app.state.ring_buffer
    subscriber  = await ring_buffer.subscribe(
        subscriber_id=f"dash-{conn_id}",
        filter_fn=_build_event_filter(None, 5),
        snapshot_count=50,
    )

    # Send initial dashboard state
    try:
        stats = await websocket.app.state.storage.get_stats()
        await manager.send(conn_id, {
            "type":  "dashboard_init",
            "stats": stats,
            "time":  datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        pass

    stats_task  = asyncio.create_task(_stats_pusher(conn_id, websocket.app))
    stream_task = asyncio.create_task(_event_streamer(conn_id, subscriber))

    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=60.0,
                )
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await manager.send(conn_id, {"type": "pong"})
            except asyncio.TimeoutError:
                if not await manager.send(conn_id, {"type": "heartbeat"}):
                    break
    except WebSocketDisconnect:
        pass
    except Exception as ex:
        log.error(f"[WS] Dashboard error {conn_id}: {ex}")
    finally:
        stats_task.cancel()
        stream_task.cancel()
        await ring_buffer.unsubscribe(f"dash-{conn_id}")
        await manager.disconnect(conn_id)


# ── Stats Endpoint ────────────────────────────────────────────────────────────

@router.get("/connections")
async def get_ws_connections() -> Dict[str, Any]:
    """Get current WebSocket connection statistics."""
    return manager.stats


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_event_filter(
    platform:     Optional[str],
    severity_min: int,
) -> Optional[Callable[[Dict], bool]]:
    """Build a filter function for ring buffer subscription."""
    if not platform and severity_min <= 0:
        return None  # No filter - receive all events

    def _filter(event: Dict) -> bool:
        if platform:
            if event.get("platform") != platform:
                return False
        if severity_min > 0:
            sev = (
                event.get("event", {}).get("severity") or
                event.get("severity") or 0
            )
            if sev < severity_min:
                return False
        return True

    return _filter


async def _stats_pusher(conn_id: str, app) -> None:
    """Push system stats to dashboard every 30 seconds."""
    while True:
        await asyncio.sleep(30)
        try:
            stats = await app.state.storage.get_stats()
            await manager.send(conn_id, {
                "type":  "stats_update",
                "stats": stats,
                "time":  datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            break


async def _event_streamer(conn_id: str, subscriber) -> None:
    """Stream events from subscriber queue to WebSocket."""
    while True:
        try:
            event = await asyncio.wait_for(subscriber.get(), timeout=5.0)
            await manager.send(conn_id, {
                "type": "event",
                "data": event,
            })
        except asyncio.TimeoutError:
            continue
        except Exception:
            break