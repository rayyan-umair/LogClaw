"""
LogClaw Brain — Intelligence Layer Entry Point
main.py — FastAPI application, startup, shutdown, route registration

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Entry point for the LogClaw intelligence brain. Starts the
          ZeroMQ subscriber that receives events from the Go harvester,
          initialises all intelligence modules, registers all API
          routes, and serves the React frontend in production mode.
          Run this file directly for development or via Docker in
          production.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
  All imports at module level — prevents NameError in threaded
  callbacks. Never import inside functions or route handlers.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import asyncio
import logging
import os
import signal
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# ── Third Party ───────────────────────────────────────────────────────────────
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from storage import Storage
from ring_buffer import RingBuffer
from entity_engine import EntityEngine
from correlation import CorrelationEngine
from sigma_engine import SigmaEngine
from five_w import FiveWEngine
from ingester import Ingester

# API routers — all imported at module level
from api.events import router as events_router
from api.entities import router as entities_router
from api.alerts import router as alerts_router
from api.investigations import router as investigations_router
from api.sigma import router as sigma_router
from api.health import router as health_router
from api.ws import router as ws_router

# ── Logging Setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(name)s]  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("logclaw.brain")

# ── Application State ─────────────────────────────────────────────────────────
# Shared state accessible across all route handlers via app.state.
# Initialised during startup, cleaned up during shutdown.

class AppState:
    settings:     Settings
    storage:      Storage
    ring_buffer:  RingBuffer
    entity_engine: EntityEngine
    correlation:  CorrelationEngine
    sigma_engine: SigmaEngine
    five_w:       FiveWEngine
    ingester:     Ingester


state = AppState()


# ── Lifespan ──────────────────────────────────────────────────────────────────
# FastAPI lifespan context manager handles startup and shutdown.
# Everything that needs to run before the first request goes in startup.
# Everything that needs to clean up on SIGTERM goes in shutdown.

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────────────────────
    log.info("━" * 60)
    log.info("  ◈ LogClaw Brain  v1.0.0")
    log.info("  Technology evolves quickly. Responsibility does not.")
    log.info("  github.com/rayyan-umair/LogClaw")
    log.info("━" * 60)

    # Load settings from environment / .env file
    settings = Settings()
    state.settings = settings
    log.info(f"[Config] ZMQ address : {settings.zmq_address}")
    log.info(f"[Config] DB path     : {settings.db_path}")
    log.info(f"[Config] Log level   : {settings.log_level}")

    # Set log level from config
    logging.getLogger().setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))

    # Initialise storage — creates DuckDB database and all tables
    log.info("[Storage] Initialising DuckDB...")
    storage = Storage(settings.db_path)
    await storage.initialise()
    state.storage = storage
    log.info("[Storage] Ready")

    # Initialise ring buffer — in-memory live event store
    ring_buffer = RingBuffer(maxsize=settings.ring_buffer_size)
    state.ring_buffer = ring_buffer
    log.info(f"[RingBuffer] Initialised — capacity {settings.ring_buffer_size}")

    # Initialise entity engine — tracks actors, hosts, IPs over time
    entity_engine = EntityEngine(storage=storage)
    await entity_engine.load_state()
    state.entity_engine = entity_engine
    log.info("[EntityEngine] Ready")

    # Initialise Sigma rule engine — loads built-in and community rules
    sigma_engine = SigmaEngine(rules_dir=settings.rules_dir)
    await sigma_engine.load_rules()
    state.sigma_engine = sigma_engine
    log.info(f"[SigmaEngine] Loaded {sigma_engine.rule_count} rule(s)")

    # Initialise 5W+H transformation engine
    five_w = FiveWEngine()
    state.five_w = five_w
    log.info("[5W+H] Ready")

    # Initialise correlation engine — sliding window pattern detection
    correlation = CorrelationEngine(
        storage=storage,
        entity_engine=entity_engine,
        sigma_engine=sigma_engine,
        five_w=five_w,
        window_seconds=settings.correlation_window_seconds,
    )
    state.correlation = correlation
    log.info(f"[Correlation] Window {settings.correlation_window_seconds}s")

    # Initialise ZeroMQ ingester — receives events from Go harvester
    ingester = Ingester(
        zmq_address=settings.zmq_address,
        ring_buffer=ring_buffer,
        storage=storage,
        entity_engine=entity_engine,
        correlation=correlation,
    )
    state.ingester = ingester

    # Start ingester in background task
    ingester_task = asyncio.create_task(ingester.run(), name="ingester")
    log.info(f"[Ingester] Listening on {settings.zmq_address}")

    # Expose state on app for route handlers
    app.state.s         = state
    app.state.storage   = storage
    app.state.ring_buffer = ring_buffer
    app.state.entity_engine = entity_engine
    app.state.correlation   = correlation
    app.state.sigma_engine  = sigma_engine
    app.state.five_w        = five_w
    app.state.settings      = settings

    log.info("[Brain] All systems online — ready to receive events")
    log.info("━" * 60)

    yield  # Application runs here

    # ── Shutdown ──────────────────────────────────────────────────────────────
    log.info("[Brain] Shutting down gracefully...")

    # Stop ingester
    ingester.stop()
    try:
        await asyncio.wait_for(ingester_task, timeout=5.0)
    except asyncio.TimeoutError:
        log.warning("[Ingester] Forced shutdown after timeout")
        ingester_task.cancel()

    # Persist entity state
    await entity_engine.save_state()
    log.info("[EntityEngine] State saved")

    # Close storage
    await storage.close()
    log.info("[Storage] Closed")

    log.info("[Brain] Shutdown complete")


# ── FastAPI App ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="LogClaw Brain",
    description="Local-first telemetry intelligence — LogClaw Intelligence Layer",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# In development the React frontend runs on port 3000.
# In production it is served from the same origin.

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",    # React dev server
        "http://localhost:8000",    # Brain dev server
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Routes ────────────────────────────────────────────────────────────────

app.include_router(health_router,          prefix="/api/health",          tags=["health"])
app.include_router(events_router,          prefix="/api/events",          tags=["events"])
app.include_router(entities_router,        prefix="/api/entities",        tags=["entities"])
app.include_router(alerts_router,          prefix="/api/alerts",          tags=["alerts"])
app.include_router(investigations_router,  prefix="/api/investigations",  tags=["investigations"])
app.include_router(sigma_router,           prefix="/api/sigma",           tags=["sigma"])
app.include_router(ws_router,              prefix="/api/ws",              tags=["websocket"])

# ── Static Frontend ───────────────────────────────────────────────────────────
# In production the React build output is served from here.
# In development the React dev server handles its own requests.

FRONTEND_BUILD = Path(__file__).parent.parent / "frontend" / "dist"

if FRONTEND_BUILD.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_BUILD / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        """Serve React frontend for all non-API routes."""
        index = FRONTEND_BUILD / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return {"error": "Frontend not built. Run: cd frontend && npm run build"}
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {
            "name":    "LogClaw Brain",
            "version": "1.0.0",
            "status":  "online",
            "docs":    "/api/docs",
            "note":    "Frontend not found. Run: cd frontend && npm run build",
            "author":  "Rayyan Umair",
            "tagline": "Technology evolves quickly. Responsibility does not.",
        }


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,           # Hot reload in development
        reload_dirs=["./"],
        log_level="info",
        access_log=True,
    )