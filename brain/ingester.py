"""
LogClaw Brain — ZeroMQ Ingester
ingester.py — Receives events from the Go harvester and feeds the pipeline

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Subscribes to the ZeroMQ PUB socket published by the Go
          harvester. Receives normalised log events as JSON, validates
          them against the universal schema, and feeds them through
          the full intelligence pipeline: storage, ring buffer, entity
          engine, and correlation engine. Handles reconnection
          automatically. Batches database writes for performance.
          This is the bridge between the Go harvester and the Python
          intelligence brain.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
import zmq
import zmq.asyncio

log = logging.getLogger("logclaw.ingester")

# ── Constants ─────────────────────────────────────────────────────────────────

# How many events to buffer before flushing to DuckDB in one batch write
BATCH_SIZE         = 50

# How long to wait for a batch to fill before flushing anyway (seconds)
BATCH_FLUSH_INTERVAL = 2.0

# ZeroMQ receive timeout in milliseconds
# Short timeout so we can check stop flag and flush batches regularly
ZMQ_RECV_TIMEOUT   = 500

# Reconnect delay on ZeroMQ connection failure (seconds)
RECONNECT_DELAY    = 5

# Maximum number of events to queue in the async processing queue
# before applying back-pressure
QUEUE_MAXSIZE      = 5000


# ── Schema Validator ──────────────────────────────────────────────────────────

REQUIRED_FIELDS = {"event_id", "timestamp", "platform", "source"}

VALID_PLATFORMS = {"windows", "linux", "network", "file", "unknown"}

VALID_EVENT_TYPES = {
    "auth", "network", "config", "process",
    "file", "system", "unknown",
}


def validate_event(event: Dict[str, Any]) -> tuple:
    """
    Validate an incoming event against the universal LogClaw schema.
    Returns (is_valid: bool, error_message: str).
    Validation is intentionally lenient — we fix what we can,
    reject only what is unrecoverable.
    """
    if not isinstance(event, dict):
        return False, "Event is not a dict"

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in event:
            return False, f"Missing required field: {field}"

    # Validate and normalise platform
    platform = str(event.get("platform", "unknown")).lower()
    if platform not in VALID_PLATFORMS:
        event["platform"] = "unknown"

    # Ensure event sub-object exists
    if "event" not in event or not isinstance(event["event"], dict):
        event["event"] = {
            "type":         "unknown",
            "severity":     1,
            "raw_event_id": 0,
            "description":  "",
        }

    # Ensure entity sub-object exists
    if "entity" not in event or not isinstance(event["entity"], dict):
        event["entity"] = {
            "actor":  "unknown",
            "target": "unknown",
        }

    # Ensure MITRE sub-object exists
    if "mitre" not in event or not isinstance(event["mitre"], dict):
        event["mitre"] = {
            "technique_id": "",
            "tactic_name":  "",
        }

    # Validate severity is integer 0-10
    sev = event["event"].get("severity", 1)
    try:
        sev = int(sev)
        event["event"]["severity"] = max(0, min(10, sev))
    except (TypeError, ValueError):
        event["event"]["severity"] = 1

    # Validate timestamp is parseable
    ts = event.get("timestamp", "")
    if not ts:
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
    else:
        try:
            datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Ensure raw_payload exists
    if "raw_payload" not in event:
        event["raw_payload"] = ""

    return True, ""


def sanitise_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitise event field values — truncate strings, ensure types.
    Called after validation passes.
    """
    max_lengths = {
        "source":       256,
        "raw_payload": 4096,
    }

    for field, max_len in max_lengths.items():
        val = event.get(field)
        if val and isinstance(val, str) and len(val) > max_len:
            event[field] = val[:max_len]

    # Truncate entity fields
    entity = event.get("entity", {})
    for key in ("actor", "target"):
        val = entity.get(key)
        if val and isinstance(val, str) and len(val) > 256:
            entity[key] = val[:256]

    # Truncate description
    ev = event.get("event", {})
    desc = ev.get("description")
    if desc and isinstance(desc, str) and len(desc) > 512:
        ev["description"] = desc[:512]

    return event


# ── Processing Queue ──────────────────────────────────────────────────────────

class ProcessingQueue:
    """
    Async queue that decouples ZeroMQ reception from pipeline processing.
    ZeroMQ receives at full speed into the queue.
    Pipeline processing consumes from the queue at its own pace.
    Back-pressure is applied when the queue fills — ZeroMQ receive
    slows down rather than overflowing memory.
    """

    def __init__(self, maxsize: int = QUEUE_MAXSIZE):
        self._queue      = asyncio.Queue(maxsize=maxsize)
        self.total_in    = 0
        self.total_out   = 0
        self.total_drop  = 0

    async def put(self, event: Dict) -> bool:
        """Add event to queue. Returns False if queue is full."""
        try:
            self._queue.put_nowait(event)
            self.total_in += 1
            return True
        except asyncio.QueueFull:
            self.total_drop += 1
            return False

    async def get(self) -> Dict:
        """Wait for and return the next event."""
        event = await self._queue.get()
        self.total_out += 1
        return event

    async def get_batch(self, max_size: int = BATCH_SIZE) -> List[Dict]:
        """
        Get up to max_size events without blocking longer than
        BATCH_FLUSH_INTERVAL seconds. Returns whatever is available.
        """
        batch = []

        # Wait for the first event with a timeout
        try:
            first = await asyncio.wait_for(
                self._queue.get(),
                timeout=BATCH_FLUSH_INTERVAL,
            )
            batch.append(first)
            self.total_out += 1
        except asyncio.TimeoutError:
            return batch  # Empty batch — timeout expired

        # Drain up to max_size more events without blocking
        while len(batch) < max_size:
            try:
                event = self._queue.get_nowait()
                batch.append(event)
                self.total_out += 1
            except asyncio.QueueEmpty:
                break

        return batch

    @property
    def size(self) -> int:
        return self._queue.qsize()

    @property
    def stats(self) -> Dict:
        return {
            "queued":      self.size,
            "total_in":    self.total_in,
            "total_out":   self.total_out,
            "total_drop":  self.total_drop,
        }


# ── Ingester ──────────────────────────────────────────────────────────────────

class Ingester:
    """
    ZeroMQ subscriber that receives events from the Go harvester
    and feeds them through the LogClaw intelligence pipeline.

    Architecture:
    ZeroMQ SUB socket -> receive loop -> processing queue
    processing queue  -> pipeline worker -> storage + ring buffer + correlation
    """

    def __init__(
        self,
        zmq_address:   str,
        ring_buffer,
        storage,
        entity_engine,
        correlation,
        topic:         str = "log:",
    ):
        self.zmq_address  = zmq_address
        self.ring_buffer  = ring_buffer
        self.storage      = storage
        self.entity_engine = entity_engine
        self.correlation  = correlation
        self.topic        = topic.encode()

        self._queue       = ProcessingQueue(maxsize=QUEUE_MAXSIZE)
        self._stop_event  = asyncio.Event()
        self._zmq_ctx     = zmq.asyncio.Context()

        # Stats
        self._received    = 0
        self._processed   = 0
        self._rejected    = 0
        self._errors      = 0
        self._start_time  = time.time()

        log.info(f"[Ingester] Configured — ZMQ: {zmq_address}")

    def stop(self):
        """Signal the ingester to stop gracefully."""
        self._stop_event.set()
        log.info("[Ingester] Stop signal received")

    async def run(self):
        """
        Main entry point. Starts the ZeroMQ receive loop and the
        pipeline worker concurrently. Runs until stop() is called.
        """
        log.info(f"[Ingester] Starting — subscribing to {self.zmq_address}")

        receive_task = asyncio.create_task(
            self._receive_loop(),
            name="ingester-receive",
        )
        pipeline_task = asyncio.create_task(
            self._pipeline_worker(),
            name="ingester-pipeline",
        )
        stats_task = asyncio.create_task(
            self._stats_reporter(),
            name="ingester-stats",
        )

        try:
            await asyncio.gather(receive_task, pipeline_task, stats_task)
        except asyncio.CancelledError:
            pass
        finally:
            receive_task.cancel()
            pipeline_task.cancel()
            stats_task.cancel()
            self._zmq_ctx.term()
            log.info("[Ingester] Stopped")

    # ── ZeroMQ Receive Loop ───────────────────────────────────────────────────

    async def _receive_loop(self):
        """
        Connects to the ZeroMQ PUB socket and receives events continuously.
        Reconnects automatically on connection failure.
        Events are placed into the processing queue immediately —
        no processing happens here.
        """
        while not self._stop_event.is_set():
            socket = None
            try:
                socket = self._zmq_ctx.socket(zmq.SUB)
                socket.setsockopt(zmq.RCVTIMEO, ZMQ_RECV_TIMEOUT)
                socket.setsockopt(zmq.LINGER, 0)
                socket.setsockopt_string(zmq.SUBSCRIBE, "log:")
                socket.connect(self.zmq_address)

                log.info(f"[Ingester] Connected to {self.zmq_address}")

                while not self._stop_event.is_set():
                    try:
                        # Receive multipart message: [topic, payload]
                        parts = await socket.recv_multipart()
                        if len(parts) < 2:
                            continue

                        payload = parts[1]
                        await self._handle_raw(payload)

                    except zmq.Again:
                        # Timeout — normal, just loop and check stop flag
                        continue
                    except zmq.ZMQError as ex:
                        if self._stop_event.is_set():
                            break
                        log.error(f"[Ingester] ZMQ receive error: {ex}")
                        break

            except zmq.ZMQError as ex:
                log.error(f"[Ingester] ZMQ connect error: {ex}")
            finally:
                if socket:
                    try:
                        socket.close()
                    except Exception:
                        pass

            if not self._stop_event.is_set():
                log.info(f"[Ingester] Reconnecting in {RECONNECT_DELAY}s...")
                await asyncio.sleep(RECONNECT_DELAY)

    async def _handle_raw(self, payload: bytes):
        """
        Parse raw bytes from ZeroMQ into an event dict.
        Validate and sanitise before queuing.
        """
        try:
            event = json.loads(payload.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as ex:
            self._rejected += 1
            log.debug(f"[Ingester] JSON parse error: {ex}")
            return

        self._received += 1

        # Validate schema
        valid, error = validate_event(event)
        if not valid:
            self._rejected += 1
            log.debug(f"[Ingester] Invalid event: {error}")
            return

        # Sanitise
        event = sanitise_event(event)

        # Queue for pipeline processing
        queued = await self._queue.put(event)
        if not queued:
            log.warning("[Ingester] Processing queue full — event dropped")

    # ── Pipeline Worker ───────────────────────────────────────────────────────

    async def _pipeline_worker(self):
        """
        Consumes events from the processing queue and runs them through
        the full intelligence pipeline:

        1. Batch insert to DuckDB (storage)
        2. Push to ring buffer (live streaming)
        3. Entity engine (behavioural tracking)
        4. Correlation engine (pattern detection + alerts)
        """
        log.info("[Ingester] Pipeline worker started")

        while not self._stop_event.is_set():
            # Get a batch of events
            batch = await self._queue.get_batch(max_size=BATCH_SIZE)

            if not batch:
                continue

            # Step 1: Batch insert to DuckDB
            try:
                inserted = await self.storage.insert_events_batch(batch)
                if inserted < len(batch):
                    log.warning(
                        f"[Ingester] Storage: {inserted}/{len(batch)} events inserted "
                        f"({len(batch) - inserted} duplicates skipped)"
                    )
            except Exception as ex:
                self._errors += 1
                log.error(f"[Ingester] Storage insert error: {ex}")

            # Step 2: Push to ring buffer (does not block)
            try:
                await self.ring_buffer.push_batch(batch)
            except Exception as ex:
                log.error(f"[Ingester] Ring buffer error: {ex}")

            # Steps 3 & 4: Entity engine + correlation per event
            # These run individually — correlation needs per-event timing
            for event in batch:
                try:
                    await self._process_single(event)
                    self._processed += 1
                except Exception as ex:
                    self._errors += 1
                    log.error(
                        f"[Ingester] Pipeline error for event "
                        f"{event.get('event_id', 'unknown')}: {ex}"
                    )

        # Flush remaining events on shutdown
        log.info("[Ingester] Flushing remaining events...")
        remaining = []
        while True:
            event = await self._queue.get_nowait() if hasattr(self._queue._queue, 'get_nowait') else None
            if event is None:
                break
            remaining.append(event)

        if remaining:
            try:
                await self.storage.insert_events_batch(remaining)
                await self.ring_buffer.push_batch(remaining)
                log.info(f"[Ingester] Flushed {len(remaining)} remaining events")
            except Exception as ex:
                log.error(f"[Ingester] Flush error: {ex}")

    async def _process_single(self, event: Dict[str, Any]):
        """
        Run a single event through entity engine and correlation engine.
        These run sequentially — correlation depends on entity state.
        """
        # Entity engine — update actor state, detect deviations
        entity_alerts = await self.entity_engine.process_event(event)

        # Correlation engine — window-based pattern detection
        # Also receives entity alerts so they go through the same pipeline
        corr_alerts = await self.correlation.process(event)

        # Log high-severity alerts
        all_alerts = entity_alerts + corr_alerts
        for alert in all_alerts:
            sev = alert.get("severity", "INFO")
            if sev in ("CRITICAL", "HIGH"):
                log.warning(
                    f"[Ingester] [{sev}] {alert.get('title', 'Alert')} "
                    f"— {alert.get('actor', 'unknown')} on {alert.get('source_host', 'unknown')}"
                )

    # ── Stats Reporter ────────────────────────────────────────────────────────

    async def _stats_reporter(self):
        """Log ingestion statistics every 60 seconds."""
        while not self._stop_event.is_set():
            await asyncio.sleep(60)
            if self._stop_event.is_set():
                break

            uptime  = time.time() - self._start_time
            rate    = self._processed / max(uptime, 1)
            q_stats = self._queue.stats

            log.info(
                f"[Ingester] Stats — "
                f"received={self._received} "
                f"processed={self._processed} "
                f"rejected={self._rejected} "
                f"errors={self._errors} "
                f"rate={rate:.1f}/s "
                f"queued={q_stats['queued']} "
                f"dropped={q_stats['total_drop']}"
            )

    # ── Public Stats ──────────────────────────────────────────────────────────

    @property
    def stats(self) -> Dict[str, Any]:
        """Return current ingester statistics."""
        uptime = time.time() - self._start_time
        return {
            "received":    self._received,
            "processed":   self._processed,
            "rejected":    self._rejected,
            "errors":      self._errors,
            "rate_per_sec": round(self._processed / max(uptime, 1), 2),
            "uptime_sec":  int(uptime),
            "queue":       self._queue.stats,
            "zmq_address": self.zmq_address,
        }