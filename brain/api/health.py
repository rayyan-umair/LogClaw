"""
LogClaw Brain - Health API
health.py - System health, status, and statistics endpoints

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Health check and system statistics endpoints. Used by
          monitoring tools, Docker health checks, and the frontend
          dashboard to confirm the brain is running and show
          current system state. No authentication required -
          health endpoints are always public.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import time
from datetime import datetime, timezone
from typing import Any, Dict

# ── Third Party ───────────────────────────────────────────────────────────────
from fastapi import APIRouter, Request

router = APIRouter()

# Track startup time for uptime calculation
_start_time = time.time()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/")
async def health_check(request: Request) -> Dict[str, Any]:
    """
    Basic health check - returns 200 if the brain is running.
    Used by Docker health checks and load balancers.
    """
    return {
        "status":  "healthy",
        "service": "LogClaw Brain",
        "version": "1.0.0",
        "time":    datetime.now(timezone.utc).isoformat(),
    }


@router.get("/stats")
async def system_stats(request: Request) -> Dict[str, Any]:
    """
    Full system statistics - event counts, entity counts,
    alert counts, engine states, and ingester throughput.
    """
    uptime_sec = int(time.time() - _start_time)

    # Storage stats
    try:
        storage_stats = await request.app.state.storage.get_stats()
    except Exception:
        storage_stats = {}

    # Ring buffer stats
    try:
        buffer_stats = await request.app.state.ring_buffer.stats()
    except Exception:
        buffer_stats = {}

    # Entity engine stats
    try:
        entity_stats = await request.app.state.entity_engine.get_stats()
    except Exception:
        entity_stats = {}

    # Correlation engine stats
    try:
        corr_stats = await request.app.state.correlation.get_stats()
    except Exception:
        corr_stats = {}

    # Sigma engine stats
    try:
        sigma_stats = await request.app.state.sigma_engine.get_stats()
    except Exception:
        sigma_stats = {}

    # Ingester stats
    try:
        ingester_stats = request.app.state.s.ingester.stats
    except Exception:
        ingester_stats = {}

    uptime_str = _format_uptime(uptime_sec)

    return {
        "status":    "healthy",
        "service":   "LogClaw Brain",
        "version":   "1.0.0",
        "uptime":    uptime_str,
        "uptime_sec": uptime_sec,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "author":    "Rayyan Umair",
        "tagline":   "Technology evolves quickly. Responsibility does not.",
        "storage":   storage_stats,
        "ring_buffer": buffer_stats,
        "entities":  entity_stats,
        "correlation": corr_stats,
        "sigma":     sigma_stats,
        "ingester":  ingester_stats,
    }


@router.get("/ready")
async def readiness_check(request: Request) -> Dict[str, Any]:
    """
    Readiness check - confirms all subsystems are initialised.
    Returns 200 only when the brain is ready to process events.
    Used by Kubernetes readiness probes.
    """
    checks = {}
    ready  = True

    # Check storage
    try:
        await request.app.state.storage.get_stats()
        checks["storage"] = "ok"
    except Exception as ex:
        checks["storage"] = f"error: {ex}"
        ready = False

    # Check ring buffer
    try:
        await request.app.state.ring_buffer.count()
        checks["ring_buffer"] = "ok"
    except Exception as ex:
        checks["ring_buffer"] = f"error: {ex}"
        ready = False

    # Check entity engine
    try:
        await request.app.state.entity_engine.get_stats()
        checks["entity_engine"] = "ok"
    except Exception as ex:
        checks["entity_engine"] = f"error: {ex}"
        ready = False

    # Check sigma engine
    try:
        await request.app.state.sigma_engine.get_stats()
        checks["sigma_engine"] = "ok"
    except Exception as ex:
        checks["sigma_engine"] = f"error: {ex}"
        ready = False

    status_code = 200 if ready else 503
    return {
        "ready":  ready,
        "checks": checks,
        "time":   datetime.now(timezone.utc).isoformat(),
    }


@router.get("/version")
async def version() -> Dict[str, str]:
    """Return version information."""
    return {
        "name":    "LogClaw Brain",
        "version": "1.0.0",
        "author":  "Rayyan Umair",
        "github":  "github.com/rayyan-umair/LogClaw",
        "tagline": "Technology evolves quickly. Responsibility does not.",
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _format_uptime(seconds: int) -> str:
    days    = seconds // 86400
    hours   = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs    = seconds % 60
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"