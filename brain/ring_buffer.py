"""
LogClaw Brain — In-Memory Ring Buffer
ring_buffer.py — Live event buffer for real-time streaming

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Thread-safe, fixed-size ring buffer that holds the most
          recent N events in memory. Used for live event streaming
          to WebSocket clients and for fast access to recent events
          without hitting the database. When the buffer is full the
          oldest event is automatically evicted. Supports filtering,
          subscription callbacks for real-time push, and snapshot
          export for new WebSocket connections.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import asyncio
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("logclaw.ring_buffer")


# ── Subscriber ────────────────────────────────────────────────────────────────

class Subscriber:
    """
    A registered listener that receives events as they arrive.
    Used by WebSocket handlers to push events to connected clients.
    Each subscriber has an asyncio Queue so events are never dropped
    due to slow consumers — the queue absorbs bursts.
    """

    def __init__(
        self,
        subscriber_id: str,
        queue_size:    int = 1000,
        filter_fn:     Optional[Callable[[Dict], bool]] = None,
    ):
        self.subscriber_id = subscriber_id
        self.queue         = asyncio.Queue(maxsize=queue_size)
        self.filter_fn     = filter_fn  # Optional filter — None means receive all
        self.created_at    = datetime.now(timezone.utc)
        self.received      = 0
        self.dropped       = 0

    def matches(self, event: Dict) -> bool:
        """Returns True if this subscriber should receive this event."""
        if self.filter_fn is None:
            return True
        try:
            return self.filter_fn(event)
        except Exception:
            return True  # On filter error, include the event — never silently drop

    async def push(self, event: Dict):
        """Push an event to this subscriber's queue. Non-blocking."""
        try:
            self.queue.put_nowait(event)
            self.received += 1
        except asyncio.QueueFull:
            # Subscriber is too slow — evict oldest event and push new one
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                self.queue.put_nowait(event)
                self.dropped += 1
            except asyncio.QueueFull:
                pass

    async def get(self) -> Dict:
        """Wait for and return the next event from the queue."""
        return await self.queue.get()

    async def get_nowait(self) -> Optional[Dict]:
        """Return next event immediately or None if queue is empty."""
        try:
            return self.queue.get_nowait()
        except asyncio.QueueEmpty:
            return None


# ── Ring Buffer ───────────────────────────────────────────────────────────────

class RingBuffer:
    """
    Thread-safe fixed-size ring buffer for live event storage.

    Holds the most recent `maxsize` events in memory.
    When full, the oldest event is automatically evicted.

    Subscribers register to receive events in real time via asyncio
    queues. New subscribers receive a configurable snapshot of recent
    events on connection so they have immediate context.

    All public methods are async-safe and can be called from any
    coroutine or background thread via run_in_executor.
    """

    def __init__(self, maxsize: int = 50000):
        self.maxsize     = maxsize
        self._buffer     = deque(maxlen=maxsize)
        self._lock       = asyncio.Lock()
        self._subscribers: Dict[str, Subscriber] = {}
        self._sub_lock   = asyncio.Lock()

        # Counters
        self.total_received = 0
        self.total_evicted  = 0

        log.info(f"[RingBuffer] Initialised — capacity {maxsize}")

    # ── Write ─────────────────────────────────────────────────────────────────

    async def push(self, event: Dict[str, Any]) -> None:
        """
        Add an event to the ring buffer and notify all subscribers.
        If the buffer is full, the oldest event is automatically evicted
        by the deque's maxlen behaviour.
        """
        async with self._lock:
            # Track eviction
            if len(self._buffer) == self.maxsize:
                self.total_evicted += 1

            self._buffer.append(event)
            self.total_received += 1

        # Notify subscribers outside the main lock
        # so a slow subscriber never blocks ingestion
        await self._notify_subscribers(event)

    async def push_batch(self, events: List[Dict[str, Any]]) -> None:
        """
        Add multiple events at once. More efficient than individual pushes
        for burst ingestion from the ZeroMQ subscriber.
        """
        if not events:
            return

        async with self._lock:
            for event in events:
                if len(self._buffer) == self.maxsize:
                    self.total_evicted += 1
                self._buffer.append(event)
            self.total_received += len(events)

        for event in events:
            await self._notify_subscribers(event)

    # ── Read ──────────────────────────────────────────────────────────────────

    async def snapshot(
        self,
        limit:        int = 500,
        platform:     Optional[str] = None,
        source:       Optional[str] = None,
        actor:        Optional[str] = None,
        event_type:   Optional[str] = None,
        severity_min: int = 0,
        since:        Optional[datetime] = None,
        search:       Optional[str] = None,
    ) -> List[Dict]:
        """
        Return a filtered snapshot of recent events from the buffer.
        Returns the most recent `limit` events matching all filters,
        ordered newest first.
        """
        async with self._lock:
            # Work from newest to oldest
            items = list(reversed(self._buffer))

        results = []
        for event in items:
            if len(results) >= limit:
                break
            if not self._matches_filters(
                event, platform, source, actor,
                event_type, severity_min, since, search
            ):
                continue
            results.append(event)

        return results

    async def recent(self, count: int = 100) -> List[Dict]:
        """Return the N most recent events with no filtering."""
        async with self._lock:
            items = list(self._buffer)
        return list(reversed(items[-count:]))

    async def count(self) -> int:
        """Current number of events in the buffer."""
        async with self._lock:
            return len(self._buffer)

    async def clear(self) -> None:
        """Clear all events from the buffer. Useful for testing."""
        async with self._lock:
            self._buffer.clear()
            self.total_received = 0
            self.total_evicted  = 0

    # ── Subscribers ───────────────────────────────────────────────────────────

    async def subscribe(
        self,
        subscriber_id: str,
        filter_fn:     Optional[Callable[[Dict], bool]] = None,
        snapshot_count: int = 100,
        queue_size:    int = 1000,
    ) -> Subscriber:
        """
        Register a new subscriber.

        subscriber_id:  Unique identifier (usually WebSocket connection ID)
        filter_fn:      Optional callable(event) -> bool for filtering
        snapshot_count: How many recent events to send immediately on subscribe
        queue_size:     Maximum events to queue before dropping oldest

        Returns the Subscriber object. The caller reads from subscriber.queue.
        """
        sub = Subscriber(
            subscriber_id=subscriber_id,
            queue_size=queue_size,
            filter_fn=filter_fn,
        )

        async with self._sub_lock:
            self._subscribers[subscriber_id] = sub

        # Send snapshot of recent events immediately
        if snapshot_count > 0:
            recent_events = await self.recent(snapshot_count)
            for event in recent_events:
                if sub.matches(event):
                    await sub.push(event)

        log.debug(f"[RingBuffer] Subscriber registered: {subscriber_id}")
        return sub

    async def unsubscribe(self, subscriber_id: str) -> None:
        """Remove a subscriber."""
        async with self._sub_lock:
            self._subscribers.pop(subscriber_id, None)
        log.debug(f"[RingBuffer] Subscriber removed: {subscriber_id}")

    async def subscriber_count(self) -> int:
        """Current number of active subscribers."""
        async with self._sub_lock:
            return len(self._subscribers)

    async def _notify_subscribers(self, event: Dict) -> None:
        """Push event to all matching subscribers."""
        async with self._sub_lock:
            subscribers = list(self._subscribers.values())

        for sub in subscribers:
            if sub.matches(event):
                await sub.push(event)

    # ── Stats ─────────────────────────────────────────────────────────────────

    async def stats(self) -> Dict[str, Any]:
        """Return buffer statistics."""
        async with self._lock:
            current_size = len(self._buffer)
            total_rx     = self.total_received
            total_ev     = self.total_evicted

        async with self._sub_lock:
            sub_count = len(self._subscribers)
            sub_stats = [
                {
                    "id":       s.subscriber_id,
                    "received": s.received,
                    "dropped":  s.dropped,
                    "queued":   s.queue.qsize(),
                }
                for s in self._subscribers.values()
            ]

        return {
            "capacity":        self.maxsize,
            "current_size":    current_size,
            "utilisation_pct": round(current_size / self.maxsize * 100, 1),
            "total_received":  total_rx,
            "total_evicted":   total_ev,
            "subscribers":     sub_count,
            "subscriber_stats": sub_stats,
        }

    # ── Filter Helper ─────────────────────────────────────────────────────────

    @staticmethod
    def _matches_filters(
        event:        Dict,
        platform:     Optional[str],
        source:       Optional[str],
        actor:        Optional[str],
        event_type:   Optional[str],
        severity_min: int,
        since:        Optional[datetime],
        search:       Optional[str],
    ) -> bool:
        """Returns True if the event matches all provided filters."""

        if platform and event.get("platform") != platform:
            return False

        if source and source.lower() not in (event.get("source") or "").lower():
            return False

        if actor and actor.lower() not in (
            event.get("entity", {}).get("actor") or event.get("actor") or ""
        ).lower():
            return False

        if event_type and event.get("event", {}).get("type") != event_type:
            return False

        sev = event.get("event", {}).get("severity") or event.get("severity") or 0
        if severity_min > 0 and sev < severity_min:
            return False

        if since:
            ts_str = event.get("timestamp")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ts < since:
                        return False
                except ValueError:
                    pass

        if search:
            search_lower = search.lower()
            searchable   = " ".join([
                str(event.get("source")      or ""),
                str(event.get("actor")       or ""),
                str(event.get("description") or ""),
                str(event.get("event", {}).get("description") or ""),
                str(event.get("entity", {}).get("actor")      or ""),
                str(event.get("raw_payload") or ""),
            ]).lower()
            if search_lower not in searchable:
                return False

        return True


# ── Filter Factories ──────────────────────────────────────────────────────────
# Pre-built filter functions for common subscription patterns.
# Pass these to subscribe(filter_fn=...) for typed event streams.

def filter_by_platform(platform: str) -> Callable[[Dict], bool]:
    """Only receive events from a specific platform."""
    def _filter(event: Dict) -> bool:
        return event.get("platform") == platform
    return _filter


def filter_by_severity(min_severity: int) -> Callable[[Dict], bool]:
    """Only receive events at or above a severity threshold."""
    def _filter(event: Dict) -> bool:
        sev = event.get("event", {}).get("severity") or event.get("severity") or 0
        return sev >= min_severity
    return _filter


def filter_by_actor(actor: str) -> Callable[[Dict], bool]:
    """Only receive events involving a specific actor."""
    actor_lower = actor.lower()
    def _filter(event: Dict) -> bool:
        event_actor = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or ""
        ).lower()
        return actor_lower in event_actor
    return _filter


def filter_by_source(source: str) -> Callable[[Dict], bool]:
    """Only receive events from a specific source host."""
    source_lower = source.lower()
    def _filter(event: Dict) -> bool:
        return source_lower in (event.get("source") or "").lower()
    return _filter


def filter_high_severity() -> Callable[[Dict], bool]:
    """Only receive events with severity 7 or above."""
    return filter_by_severity(7)


def filter_auth_events() -> Callable[[Dict], bool]:
    """Only receive authentication events."""
    def _filter(event: Dict) -> bool:
        return event.get("event", {}).get("type") == "auth"
    return _filter


def filter_windows_events() -> Callable[[Dict], bool]:
    """Only receive Windows platform events."""
    return filter_by_platform("windows")


def filter_critical_event_ids() -> Callable[[Dict], bool]:
    """
    Only receive Windows events with critical Event IDs.
    1102, 7045, 4697, 4720, 4728 — the ones that always matter.
    """
    critical_ids = {1102, 7045, 4697, 4720, 4728, 4732, 4698}
    def _filter(event: Dict) -> bool:
        raw_id = (
            event.get("event", {}).get("raw_event_id") or
            event.get("raw_event_id")
        )
        if raw_id and int(raw_id) in critical_ids:
            return True
        sev = event.get("event", {}).get("severity") or event.get("severity") or 0
        return sev >= 9
    return _filter