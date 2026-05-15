"""
LogClaw Brain — Correlation Engine
correlation.py — Sliding window pattern detection and alert generation

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Receives every normalised event and runs it through a set of
          correlation rules within a sliding time window. Detects
          attack patterns that span multiple events — brute force,
          lateral movement, privilege escalation chains, persistence
          mechanisms. When a pattern is confirmed it generates a
          structured alert with a 5W+H breakdown and passes it to
          the alert pipeline. Works alongside the Sigma engine —
          Sigma handles single-event rule matching, this engine
          handles multi-event temporal correlation.
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
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger("logclaw.correlation")

# ── Severity Map ──────────────────────────────────────────────────────────────

SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH":      7,
    "MEDIUM":    5,
    "LOW":       3,
    "INFO":      1,
}


# ── Window Buffer ─────────────────────────────────────────────────────────────

class WindowBuffer:
    """
    Maintains a sliding time window of events per actor and per source.
    Events older than window_seconds are automatically pruned on access.
    Thread-safe via asyncio lock.
    """

    def __init__(self, window_seconds: int = 600):
        self.window_seconds = window_seconds
        # actor -> deque of events
        self._by_actor:  Dict[str, deque] = defaultdict(deque)
        # source -> deque of events
        self._by_source: Dict[str, deque] = defaultdict(deque)
        # global deque for cross-actor correlation
        self._global:    deque = deque(maxlen=10000)
        self._lock       = asyncio.Lock()

    async def add(self, event: Dict[str, Any]):
        """Add an event to the window buffer."""
        actor  = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )
        source = event.get("source", "unknown")

        async with self._lock:
            self._by_actor[actor].append(event)
            self._by_source[source].append(event)
            self._global.append(event)

    async def get_actor_window(
        self,
        actor: str,
        since: Optional[datetime] = None,
    ) -> List[Dict]:
        """Get all events for an actor within the time window."""
        cutoff = since or (
            datetime.now(timezone.utc) -
            timedelta(seconds=self.window_seconds)
        )
        async with self._lock:
            events = list(self._by_actor.get(actor, deque()))

        return [
            e for e in events
            if self._ts(e) >= cutoff
        ]

    async def get_source_window(
        self,
        source: str,
        since:  Optional[datetime] = None,
    ) -> List[Dict]:
        """Get all events from a source host within the time window."""
        cutoff = since or (
            datetime.now(timezone.utc) -
            timedelta(seconds=self.window_seconds)
        )
        async with self._lock:
            events = list(self._by_source.get(source, deque()))

        return [
            e for e in events
            if self._ts(e) >= cutoff
        ]

    async def get_global_window(
        self,
        since: Optional[datetime] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict]:
        """Get all events in the global window, optionally filtered."""
        cutoff = since or (
            datetime.now(timezone.utc) -
            timedelta(seconds=self.window_seconds)
        )
        async with self._lock:
            events = list(self._global)

        result = [e for e in events if self._ts(e) >= cutoff]
        if event_type:
            result = [
                e for e in result
                if e.get("event", {}).get("type") == event_type
            ]
        return result

    async def prune(self):
        """Remove events older than window_seconds from all buffers."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.window_seconds)

        async with self._lock:
            # Prune per-actor buffers
            for actor in list(self._by_actor.keys()):
                buf = self._by_actor[actor]
                while buf and self._ts(buf[0]) < cutoff:
                    buf.popleft()
                if not buf:
                    del self._by_actor[actor]

            # Prune per-source buffers
            for source in list(self._by_source.keys()):
                buf = self._by_source[source]
                while buf and self._ts(buf[0]) < cutoff:
                    buf.popleft()
                if not buf:
                    del self._by_source[source]

    @staticmethod
    def _ts(event: Dict) -> datetime:
        """Extract timestamp from event dict. Returns now() on parse failure."""
        ts_str = event.get("timestamp", "")
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc)

    async def actor_count(self) -> int:
        async with self._lock:
            return len(self._by_actor)


# ── Deduplication ─────────────────────────────────────────────────────────────

class AlertDeduplicator:
    """
    Prevents the same pattern from generating duplicate alerts within
    a cooldown period. Keyed by (alert_type, actor, source).
    """

    def __init__(self, cooldown_seconds: int = 300):
        self.cooldown = cooldown_seconds
        self._seen:   Dict[str, datetime] = {}
        self._lock    = asyncio.Lock()

    async def is_duplicate(self, alert_type: str, actor: str, source: str) -> bool:
        key = f"{alert_type}:{actor}:{source}"
        now = datetime.now(timezone.utc)
        async with self._lock:
            if key in self._seen:
                if (now - self._seen[key]).total_seconds() < self.cooldown:
                    return True
            self._seen[key] = now
            return False

    async def prune(self):
        """Remove expired deduplication entries."""
        now = datetime.now(timezone.utc)
        async with self._lock:
            expired = [
                k for k, ts in self._seen.items()
                if (now - ts).total_seconds() > self.cooldown * 2
            ]
            for k in expired:
                del self._seen[k]


# ── Correlation Rules ─────────────────────────────────────────────────────────

class CorrelationRule:
    """Base class for all correlation rules."""

    name:        str = "base_rule"
    alert_type:  str = "generic"
    severity:    str = "MEDIUM"
    description: str = ""

    async def evaluate(
        self,
        event:  Dict[str, Any],
        buffer: WindowBuffer,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate this rule against the current event and window buffer.
        Returns an alert dict if the rule fires, None otherwise.
        """
        raise NotImplementedError


class BruteForceRule(CorrelationRule):
    """
    Detects brute force attacks — repeated authentication failures
    against the same account within the time window.
    """
    name       = "brute_force"
    alert_type = "brute_force"
    severity   = "HIGH"

    def __init__(self, threshold: int = 10):
        self.threshold = threshold

    async def evaluate(
        self,
        event:  Dict,
        buffer: WindowBuffer,
    ) -> Optional[Dict]:
        ev     = event.get("event", {})
        raw_id = ev.get("raw_event_id", 0)

        # Only trigger on authentication failures
        if raw_id != 4625 and not (
            ev.get("type") == "auth" and
            "fail" in (ev.get("description") or "").lower()
        ):
            return None

        actor  = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )
        source = event.get("source", "unknown")

        # Get all events for this actor in the window
        window_events = await buffer.get_actor_window(actor)

        # Count authentication failures
        failures = [
            e for e in window_events
            if (
                e.get("event", {}).get("raw_event_id") == 4625 or
                (
                    e.get("event", {}).get("type") == "auth" and
                    "fail" in (e.get("event", {}).get("description") or "").lower()
                )
            )
        ]

        if len(failures) < self.threshold:
            return None

        # Calculate time span
        timestamps = sorted([WindowBuffer._ts(e) for e in failures])
        span_secs  = (timestamps[-1] - timestamps[0]).total_seconds()

        return {
            "alert_type":    self.alert_type,
            "severity":      self.severity,
            "severity_score": SEVERITY_SCORE[self.severity],
            "title":         f"Brute Force Attack — {actor}",
            "description":   (
                f"{len(failures)} failed authentication attempts against "
                f"'{actor}' from {source} within {int(span_secs)}s"
            ),
            "actor":         actor,
            "source_host":   source,
            "event_ids":     [e.get("event_id", "") for e in failures[-10:]],
            "mitre_technique": "T1110",
            "mitre_tactic":    "credential-access",
            "metadata": {
                "failure_count": len(failures),
                "span_seconds":  int(span_secs),
                "threshold":     self.threshold,
            },
        }


class CredentialStuffingRule(CorrelationRule):
    """
    Detects successful authentication following repeated failures —
    a strong indicator of a successful brute force or credential stuffing.
    """
    name       = "credential_stuffing"
    alert_type = "credential_stuffing"
    severity   = "CRITICAL"

    def __init__(self, failure_threshold: int = 5):
        self.failure_threshold = failure_threshold

    async def evaluate(self, event: Dict, buffer: WindowBuffer) -> Optional[Dict]:
        ev     = event.get("event", {})
        raw_id = ev.get("raw_event_id", 0)

        # Only trigger on successful authentication
        if raw_id != 4624 and not (
            ev.get("type") == "auth" and
            "success" in (ev.get("description") or "").lower()
        ):
            return None

        actor  = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )
        source = event.get("source", "unknown")

        window_events = await buffer.get_actor_window(actor)

        # Count failures before this success
        failures = [
            e for e in window_events
            if (
                e.get("event", {}).get("raw_event_id") == 4625 or
                (
                    e.get("event", {}).get("type") == "auth" and
                    "fail" in (e.get("event", {}).get("description") or "").lower()
                )
            )
        ]

        if len(failures) < self.failure_threshold:
            return None

        return {
            "alert_type":    self.alert_type,
            "severity":      self.severity,
            "severity_score": SEVERITY_SCORE[self.severity],
            "title":         f"Successful Login After Failures — {actor}",
            "description":   (
                f"Account '{actor}' had {len(failures)} failed attempts followed "
                f"by a successful login from {source}. "
                f"Consistent with a successful brute force or credential stuffing attack."
            ),
            "actor":         actor,
            "source_host":   source,
            "event_ids":     [e.get("event_id", "") for e in failures[-5:]] +
                             [event.get("event_id", "")],
            "mitre_technique": "T1110.004",
            "mitre_tactic":    "credential-access",
            "metadata": {
                "failure_count": len(failures),
            },
        }


class LateralMovementRule(CorrelationRule):
    """
    Detects lateral movement — the same actor authenticating to
    multiple distinct hosts within the time window.
    """
    name       = "lateral_movement"
    alert_type = "lateral_movement"
    severity   = "CRITICAL"

    def __init__(self, host_threshold: int = 3):
        self.host_threshold = host_threshold

    async def evaluate(self, event: Dict, buffer: WindowBuffer) -> Optional[Dict]:
        ev     = event.get("event", {})
        raw_id = ev.get("raw_event_id", 0)

        # Only trigger on successful auth events
        if raw_id != 4624 and ev.get("type") != "auth":
            return None

        actor  = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )

        window_events = await buffer.get_actor_window(actor)

        # Count distinct hosts with successful auth
        auth_success_events = [
            e for e in window_events
            if (
                e.get("event", {}).get("raw_event_id") == 4624 or
                e.get("event", {}).get("type") == "auth"
            )
        ]

        distinct_hosts: Set[str] = set()
        for e in auth_success_events:
            src = e.get("source", "")
            if src and src != "unknown":
                distinct_hosts.add(src)

        if len(distinct_hosts) < self.host_threshold:
            return None

        timestamps = sorted([WindowBuffer._ts(e) for e in auth_success_events])
        span_secs  = (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) > 1 else 0

        return {
            "alert_type":    self.alert_type,
            "severity":      self.severity,
            "severity_score": SEVERITY_SCORE[self.severity],
            "title":         f"Lateral Movement — {actor}",
            "description":   (
                f"Actor '{actor}' authenticated to {len(distinct_hosts)} distinct hosts "
                f"within {int(span_secs)}s: {', '.join(list(distinct_hosts)[:5])}"
            ),
            "actor":         actor,
            "source_host":   event.get("source", "unknown"),
            "event_ids":     [e.get("event_id", "") for e in auth_success_events[-10:]],
            "mitre_technique": "T1021",
            "mitre_tactic":    "lateral-movement",
            "metadata": {
                "distinct_hosts": list(distinct_hosts),
                "host_count":     len(distinct_hosts),
                "span_seconds":   int(span_secs),
            },
        }


class PrivilegeEscalationChainRule(CorrelationRule):
    """
    Detects a privilege escalation chain — a login followed by
    adding the account to an admin group within the window.
    This pattern strongly suggests a compromise in progress.
    """
    name       = "privilege_escalation_chain"
    alert_type = "privilege_escalation_chain"
    severity   = "CRITICAL"

    async def evaluate(self, event: Dict, buffer: WindowBuffer) -> Optional[Dict]:
        ev     = event.get("event", {})
        raw_id = ev.get("raw_event_id", 0)

        # Trigger on group membership add events
        if raw_id not in (4728, 4732, 4756):
            return None

        actor  = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )

        window_events = await buffer.get_actor_window(actor)

        # Look for a recent login from the same actor
        recent_logins = [
            e for e in window_events
            if e.get("event", {}).get("raw_event_id") == 4624
        ]

        if not recent_logins:
            return None

        return {
            "alert_type":    self.alert_type,
            "severity":      self.severity,
            "severity_score": SEVERITY_SCORE[self.severity],
            "title":         f"Privilege Escalation Chain — {actor}",
            "description":   (
                f"Actor '{actor}' logged in and was subsequently added to a "
                f"security group within the correlation window. "
                f"This sequence may indicate an account takeover with privilege escalation."
            ),
            "actor":         actor,
            "source_host":   event.get("source", "unknown"),
            "event_ids":     [e.get("event_id", "") for e in recent_logins[-3:]] +
                             [event.get("event_id", "")],
            "mitre_technique": "T1078",
            "mitre_tactic":    "privilege-escalation",
            "metadata": {
                "login_count": len(recent_logins),
            },
        }


class PersistenceInstallRule(CorrelationRule):
    """
    Detects persistence installation — a new service or scheduled task
    created shortly after an authentication event on the same host.
    """
    name       = "persistence_after_auth"
    alert_type = "persistence_after_auth"
    severity   = "HIGH"

    async def evaluate(self, event: Dict, buffer: WindowBuffer) -> Optional[Dict]:
        ev     = event.get("event", {})
        raw_id = ev.get("raw_event_id", 0)
        source = event.get("source", "unknown")

        # Trigger on service install or scheduled task
        if raw_id not in (7045, 4697, 4698):
            return None

        # Look for a recent auth event on the same host
        source_events = await buffer.get_source_window(source)

        recent_auths = [
            e for e in source_events
            if (
                e.get("event", {}).get("raw_event_id") == 4624 or
                e.get("event", {}).get("type") == "auth"
            )
        ]

        if not recent_auths:
            return None

        actor = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )

        persistence_type = (
            "service installation" if raw_id in (7045, 4697)
            else "scheduled task creation"
        )

        return {
            "alert_type":    self.alert_type,
            "severity":      self.severity,
            "severity_score": SEVERITY_SCORE[self.severity],
            "title":         f"Persistence After Auth — {source}",
            "description":   (
                f"{persistence_type.title()} on '{source}' followed "
                f"a recent authentication event. "
                f"Potential persistence mechanism being established."
            ),
            "actor":         actor,
            "source_host":   source,
            "event_ids":     [e.get("event_id", "") for e in recent_auths[-3:]] +
                             [event.get("event_id", "")],
            "mitre_technique": "T1543" if raw_id in (7045, 4697) else "T1053",
            "mitre_tactic":    "persistence",
            "metadata": {
                "persistence_type": persistence_type,
                "recent_auth_count": len(recent_auths),
            },
        }


class AuditLogClearedRule(CorrelationRule):
    """
    Detects audit log clearing — always a critical event.
    Fired immediately on Event ID 1102 — no window needed.
    """
    name       = "audit_log_cleared"
    alert_type = "audit_log_cleared"
    severity   = "CRITICAL"

    async def evaluate(self, event: Dict, buffer: WindowBuffer) -> Optional[Dict]:
        ev     = event.get("event", {})
        raw_id = ev.get("raw_event_id", 0)

        if raw_id != 1102:
            return None

        actor  = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )
        source = event.get("source", "unknown")

        return {
            "alert_type":    self.alert_type,
            "severity":      self.severity,
            "severity_score": SEVERITY_SCORE[self.severity],
            "title":         f"Audit Log Cleared — {source}",
            "description":   (
                f"The Windows Security audit log on '{source}' was cleared "
                f"by '{actor}'. This is a strong indicator of anti-forensic "
                f"activity following a compromise."
            ),
            "actor":         actor,
            "source_host":   source,
            "event_ids":     [event.get("event_id", "")],
            "mitre_technique": "T1070.001",
            "mitre_tactic":    "defense-evasion",
            "metadata": {},
        }


class AfterHoursAuthRule(CorrelationRule):
    """
    Detects authentication outside of business hours.
    Only fires for entities with established activity history
    to avoid false positives for new or rarely-seen accounts.
    """
    name       = "after_hours_auth"
    alert_type = "after_hours_auth"
    severity   = "MEDIUM"

    def __init__(self, business_start: int = 7, business_end: int = 18):
        self.business_start = business_start
        self.business_end   = business_end

    async def evaluate(self, event: Dict, buffer: WindowBuffer) -> Optional[Dict]:
        ev     = event.get("event", {})
        raw_id = ev.get("raw_event_id", 0)

        # Only trigger on successful auth
        if raw_id != 4624 and ev.get("type") != "auth":
            return None

        ts_str = event.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

        # Check if outside business hours
        hour = ts.hour
        if self.business_start <= hour < self.business_end:
            return None  # Normal business hours — no alert

        actor  = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )
        source = event.get("source", "unknown")

        # Need at least some history to avoid false positives
        window_events = await buffer.get_actor_window(actor)
        if len(window_events) < 3:
            return None  # Not enough history

        return {
            "alert_type":    self.alert_type,
            "severity":      self.severity,
            "severity_score": SEVERITY_SCORE[self.severity],
            "title":         f"After-Hours Authentication — {actor}",
            "description":   (
                f"Actor '{actor}' authenticated to '{source}' at "
                f"{ts.strftime('%H:%M')} UTC — outside business hours "
                f"({self.business_start:02d}:00–{self.business_end:02d}:00)."
            ),
            "actor":         actor,
            "source_host":   source,
            "event_ids":     [event.get("event_id", "")],
            "mitre_technique": "T1078",
            "mitre_tactic":    "defense-evasion",
            "metadata": {
                "auth_hour":       hour,
                "business_start":  self.business_start,
                "business_end":    self.business_end,
            },
        }


class NewDeviceAuthRule(CorrelationRule):
    """
    Detects authentication from a source IP or host that has never
    been seen before in the global window.
    """
    name       = "new_source_auth"
    alert_type = "new_source_auth"
    severity   = "MEDIUM"

    async def evaluate(self, event: Dict, buffer: WindowBuffer) -> Optional[Dict]:
        ev     = event.get("event", {})
        raw_id = ev.get("raw_event_id", 0)

        if raw_id != 4624 and ev.get("type") != "auth":
            return None

        actor  = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )
        source = event.get("source", "unknown")

        if source == "unknown":
            return None

        # Check if this source has been seen before for this actor
        actor_events = await buffer.get_actor_window(actor)
        known_sources = {
            e.get("source") for e in actor_events
            if e.get("event_id") != event.get("event_id")
        }

        if source in known_sources:
            return None  # Source is known — no alert

        # Only alert if actor has some history
        if len(actor_events) < 5:
            return None

        return {
            "alert_type":    self.alert_type,
            "severity":      self.severity,
            "severity_score": SEVERITY_SCORE[self.severity],
            "title":         f"Authentication From New Source — {actor}",
            "description":   (
                f"Actor '{actor}' authenticated from a previously unseen "
                f"source '{source}'. Known sources: "
                f"{', '.join(list(known_sources)[:3])}."
            ),
            "actor":         actor,
            "source_host":   source,
            "event_ids":     [event.get("event_id", "")],
            "mitre_technique": "T1078",
            "mitre_tactic":    "initial-access",
            "metadata": {
                "new_source":    source,
                "known_sources": list(known_sources)[:10],
            },
        }


# ── Correlation Engine ────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Runs every incoming event through all registered correlation rules
    within a sliding time window. Generates structured alerts for
    detected patterns. Deduplicates repeated alerts within cooldown period.
    """

    def __init__(
        self,
        storage,
        entity_engine,
        sigma_engine,
        five_w,
        window_seconds:      int = 600,
        brute_force_threshold: int = 10,
        lateral_threshold:   int = 3,
        business_start:      int = 7,
        business_end:        int = 18,
    ):
        self.storage        = storage
        self.entity_engine  = entity_engine
        self.sigma_engine   = sigma_engine
        self.five_w         = five_w
        self.window_seconds = window_seconds

        # Window buffer — holds recent events for correlation
        self.buffer = WindowBuffer(window_seconds=window_seconds)

        # Alert deduplicator — 5 minute cooldown per alert type + actor
        self.dedup = AlertDeduplicator(cooldown_seconds=300)

        # Registered correlation rules
        self._rules: List[CorrelationRule] = [
            BruteForceRule(threshold=brute_force_threshold),
            CredentialStuffingRule(failure_threshold=5),
            LateralMovementRule(host_threshold=lateral_threshold),
            PrivilegeEscalationChainRule(),
            PersistenceInstallRule(),
            AuditLogClearedRule(),
            AfterHoursAuthRule(business_start=business_start, business_end=business_end),
            NewDeviceAuthRule(),
        ]

        # WebSocket broadcast callback — set by ws.py
        self._broadcast_cb: Optional[Callable] = None

        # Alert count for stats
        self._alert_count = 0

        log.info(f"[Correlation] {len(self._rules)} rules loaded — window {window_seconds}s")

    def set_broadcast_callback(self, cb: Callable):
        """Register a callback to broadcast alerts to WebSocket clients."""
        self._broadcast_cb = cb

    def register_rule(self, rule: CorrelationRule):
        """Register a custom correlation rule at runtime."""
        self._rules.append(rule)
        log.info(f"[Correlation] Rule registered: {rule.name}")

    # ── Main Processing Pipeline ──────────────────────────────────────────────

    async def process(self, event: Dict[str, Any]) -> List[Dict]:
        """
        Process a single event through the full correlation pipeline.

        Pipeline:
        1. Add event to window buffer
        2. Run entity engine — update entity state, detect deviations
        3. Run Sigma rules — single-event rule matching
        4. Run correlation rules — multi-event temporal patterns
        5. Deduplicate alerts
        6. Persist alerts to storage
        7. Generate 5W+H for each alert
        8. Broadcast to WebSocket subscribers

        Returns list of generated alert dicts.
        """
        all_alerts: List[Dict] = []

        # Step 1: Add to window buffer
        await self.buffer.add(event)

        # Step 2: Entity engine — deviation alerts
        try:
            entity_alerts = await self.entity_engine.process_event(event)
            all_alerts.extend(entity_alerts)
        except Exception as ex:
            log.error(f"[Correlation] Entity engine error: {ex}")

        # Step 3: Sigma engine — single-event rule matching
        try:
            sigma_alerts = await self.sigma_engine.evaluate(event)
            all_alerts.extend(sigma_alerts)
        except Exception as ex:
            log.error(f"[Correlation] Sigma engine error: {ex}")

        # Step 4: Correlation rules — multi-event patterns
        for rule in self._rules:
            try:
                alert = await rule.evaluate(event, self.buffer)
                if alert:
                    all_alerts.append(alert)
            except Exception as ex:
                log.error(f"[Correlation] Rule {rule.name} error: {ex}")

        # Step 5: Lateral movement check via entity engine
        actor = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )
        if actor != "unknown":
            try:
                lm = await self.entity_engine.check_lateral_movement(
                    actor,
                    window_sec=self.window_seconds,
                    threshold=3,
                )
                if lm:
                    all_alerts.append(self._build_alert_from_deviation(lm, event))
            except Exception as ex:
                log.error(f"[Correlation] Lateral movement check error: {ex}")

        # Steps 6-8: Process each alert
        final_alerts = []
        for alert_data in all_alerts:
            alert = await self._finalise_alert(alert_data, event)
            if alert:
                final_alerts.append(alert)

        return final_alerts

    async def _finalise_alert(
        self,
        alert_data: Dict,
        trigger_event: Dict,
    ) -> Optional[Dict]:
        """
        Finalise an alert — deduplicate, add 5W+H, persist, broadcast.
        Returns the final alert dict or None if deduplicated.
        """
        alert_type = alert_data.get("alert_type", "unknown")
        actor      = alert_data.get("actor", "unknown")
        source     = alert_data.get("source_host", "unknown")

        # Deduplicate
        if await self.dedup.is_duplicate(alert_type, actor, source):
            return None

        # Assign UUID
        alert_data["alert_id"] = str(uuid.uuid4())

        # Add timestamp if missing
        if "timestamp" not in alert_data:
            alert_data["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Generate 5W+H
        try:
            five_w = await self.five_w.generate(alert_data, trigger_event)
            alert_data["five_w"] = five_w
        except Exception as ex:
            log.error(f"[Correlation] 5W+H generation error: {ex}")
            alert_data["five_w"] = {}

        # Persist to storage
        try:
            await self.storage.insert_alert(alert_data)
            self._alert_count += 1
        except Exception as ex:
            log.error(f"[Correlation] Alert persist error: {ex}")

        # Broadcast to WebSocket clients
        if self._broadcast_cb:
            try:
                await self._broadcast_cb({
                    "type":  "alert",
                    "data":  alert_data,
                })
            except Exception as ex:
                log.error(f"[Correlation] Broadcast error: {ex}")

        log.info(
            f"[Correlation] ALERT [{alert_data['severity']}] "
            f"{alert_data.get('title', alert_type)}"
        )

        return alert_data

    # ── Maintenance ───────────────────────────────────────────────────────────

    async def prune(self):
        """Prune expired entries from buffer and deduplicator."""
        await self.buffer.prune()
        await self.dedup.prune()

    async def get_stats(self) -> Dict[str, Any]:
        """Return correlation engine statistics."""
        return {
            "rules_count":   len(self._rules),
            "alerts_total":  self._alert_count,
            "window_seconds": self.window_seconds,
            "buffer_actors": await self.buffer.actor_count(),
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_alert_from_deviation(
        self,
        deviation: Dict,
        event:     Dict,
    ) -> Dict:
        """Convert a deviation dict from entity engine into an alert dict."""
        severity = deviation.get("severity", "MEDIUM")
        return {
            "alert_type":    deviation.get("flag", "unknown"),
            "severity":      severity,
            "severity_score": SEVERITY_SCORE.get(severity, 5),
            "title":         deviation.get("description", "Anomaly detected"),
            "description":   deviation.get("description", ""),
            "actor":         deviation.get("actor", "unknown"),
            "source_host":   event.get("source", "unknown"),
            "event_ids":     [event.get("event_id", "")],
            "mitre_technique": event.get("mitre", {}).get("technique_id"),
            "mitre_tactic":    event.get("mitre", {}).get("tactic_name"),
            "metadata":      deviation,
        }