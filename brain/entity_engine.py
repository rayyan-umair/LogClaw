"""
LogClaw Brain - Entity Intelligence Engine
entity_engine.py - Behavioural tracking, risk scoring, baseline deviation

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Tracks every actor seen in the logs as a persistent entity.
          An entity is a user account, IP address, hostname, or service.
          For each entity it maintains a behavioural baseline, a risk
          score, an activity timeline, and deviation detection. When an
          entity behaves outside its normal pattern - logging in at 2AM,
          accessing a new host, executing an unusual process - the engine
          flags it. This is the layer that turns individual log events
          into intelligence about actors over time.
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
import re
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("logclaw.entity_engine")

# ── Risk Score Thresholds ─────────────────────────────────────────────────────

RISK_LABELS = [
    (80.0, "CRITICAL"),
    (60.0, "HIGH"),
    (40.0, "MEDIUM"),
    (20.0, "LOW"),
    (0.0,  "CLEAN"),
]

def score_to_label(score: float) -> str:
    for threshold, label in RISK_LABELS:
        if score >= threshold:
            return label
    return "CLEAN"

# ── Entity Types ──────────────────────────────────────────────────────────────

ENTITY_TYPE_USER    = "user"
ENTITY_TYPE_IP      = "ip"
ENTITY_TYPE_HOST    = "host"
ENTITY_TYPE_SERVICE = "service"

# ── Risk Weights ──────────────────────────────────────────────────────────────
# How much each event type contributes to an entity's risk score.
# These are additive - multiple events compound.

RISK_WEIGHTS = {
    # Authentication failures
    "auth_failure":          3.0,
    "brute_force_detected":  25.0,
    # Privilege operations
    "privilege_escalation":  20.0,
    "admin_group_add":       15.0,
    "new_admin_account":     20.0,
    # Persistence
    "new_service":           15.0,
    "scheduled_task":        10.0,
    # Suspicious behaviour
    "after_hours_access":    8.0,
    "new_host_access":       5.0,
    "stale_account_active":  20.0,
    "audit_log_cleared":     40.0,
    # Lateral movement
    "lateral_movement":      30.0,
    "multi_host_auth":       10.0,
    # Network
    "port_scan_detected":    15.0,
    "unusual_protocol":      10.0,
    # Process
    "suspicious_process":    12.0,
    # Default for unclassified high-severity events
    "high_severity":         5.0,
}

# ── Risk Decay ────────────────────────────────────────────────────────────────
# Risk scores decay over time if no new suspicious activity occurs.
# This prevents old events from permanently flagging entities.

RISK_DECAY_PER_HOUR = 2.0   # Points removed per hour of inactivity
RISK_FLOOR          = 0.0   # Minimum risk score
RISK_CEILING        = 100.0 # Maximum risk score


# ── Entity State ──────────────────────────────────────────────────────────────

class EntityState:
    """
    In-memory state for a single tracked entity.
    Persisted to DuckDB periodically and on shutdown.
    """

    def __init__(self, entity_id: str, entity_type: str):
        self.entity_id   = entity_id
        self.entity_type = entity_type
        self.first_seen  = datetime.now(timezone.utc)
        self.last_seen   = datetime.now(timezone.utc)
        self.last_risk_update = datetime.now(timezone.utc)

        # Risk
        self.risk_score  = 0.0
        self.risk_label  = "CLEAN"

        # Activity counters
        self.event_count       = 0
        self.auth_failure_count = 0
        self.auth_success_count = 0

        # Behavioural baseline
        # Set of hosts this entity has been seen on
        self.known_hosts:    Set[str] = set()
        # Set of hours (0-23) this entity has been active
        self.active_hours:   Set[int] = set()
        # Set of event types seen for this entity
        self.known_event_types: Set[str] = set()
        # Set of targets this entity has interacted with
        self.known_targets:  Set[str] = set()

        # Tags and metadata
        self.tags:     List[str] = []
        self.metadata: Dict[str, Any] = {}

        # Recent activity window - last 100 events for quick access
        self.recent_events: deque = deque(maxlen=100)

        # Deviation flags - set when anomalous behaviour detected
        self.deviation_flags: Set[str] = set()

        # Stale flag - set if entity hasn't been seen for stale_days
        self.is_stale = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id":    self.entity_id,
            "entity_type":  self.entity_type,
            "first_seen":   self.first_seen.isoformat(),
            "last_seen":    self.last_seen.isoformat(),
            "event_count":  self.event_count,
            "risk_score":   round(self.risk_score, 2),
            "risk_label":   self.risk_label,
            "is_stale":     self.is_stale,
            "tags":         self.tags,
            "metadata": {
                **self.metadata,
                "auth_failures":     self.auth_failure_count,
                "auth_successes":    self.auth_success_count,
                "known_hosts":       list(self.known_hosts)[:20],
                "active_hours":      sorted(self.active_hours),
                "deviation_flags":   list(self.deviation_flags),
                "known_event_types": list(self.known_event_types),
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EntityState":
        e = cls(data["entity_id"], data["entity_type"])
        e.first_seen  = datetime.fromisoformat(data["first_seen"])
        e.last_seen   = datetime.fromisoformat(data["last_seen"])
        e.event_count = data.get("event_count", 0)
        e.risk_score  = data.get("risk_score", 0.0)
        e.risk_label  = data.get("risk_label", "CLEAN")
        e.is_stale    = data.get("is_stale", False)
        e.tags        = data.get("tags", [])
        meta          = data.get("metadata", {})
        e.auth_failure_count  = meta.get("auth_failures", 0)
        e.auth_success_count  = meta.get("auth_successes", 0)
        e.known_hosts         = set(meta.get("known_hosts", []))
        e.active_hours        = set(meta.get("active_hours", []))
        e.deviation_flags     = set(meta.get("deviation_flags", []))
        e.known_event_types   = set(meta.get("known_event_types", []))
        return e


# ── Entity Classifier ─────────────────────────────────────────────────────────

def classify_entity(identifier: str) -> str:
    """
    Determine entity type from the identifier string.
    Uses pattern matching - IP regex, hostname patterns, service names.
    """
    if not identifier or identifier == "unknown":
        return ENTITY_TYPE_USER

    # IPv4
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', identifier):
        return ENTITY_TYPE_IP

    # IPv6
    if ':' in identifier and re.match(r'^[0-9a-fA-F:]+$', identifier.split('@')[0]):
        return ENTITY_TYPE_IP

    # IP embedded in "user@ip" format
    if '@' in identifier:
        parts = identifier.split('@')
        if len(parts) == 2 and re.match(r'^\d{1,3}\.\d{1,3}', parts[1]):
            return ENTITY_TYPE_USER  # user with IP context - classify as user

    # Known service account patterns
    service_patterns = [
        r'^svc_', r'^service_', r'^_', r'^\$',
        r'SYSTEM$', r'LOCAL SERVICE$', r'NETWORK SERVICE$',
        r'^NT AUTHORITY',
    ]
    for pattern in service_patterns:
        if re.search(pattern, identifier, re.IGNORECASE):
            return ENTITY_TYPE_SERVICE

    # Hostname patterns - contains dots or dashes, looks like a FQDN
    if '.' in identifier and not identifier.startswith('\\'):
        parts = identifier.split('.')
        if len(parts) >= 2 and all(p for p in parts):
            return ENTITY_TYPE_HOST

    # Computer account (ends with $)
    if identifier.endswith('$'):
        return ENTITY_TYPE_HOST

    return ENTITY_TYPE_USER


# ── Entity Engine ─────────────────────────────────────────────────────────────

class EntityEngine:
    """
    Tracks every actor seen in log events as a persistent entity.
    Maintains behavioural baselines and risk scores.
    Detects deviations from normal behaviour.
    """

    def __init__(self, storage, stale_days: int = 90, decay_hours: int = 24):
        self.storage     = storage
        self.stale_days  = stale_days
        self.decay_hours = decay_hours
        self._entities:  Dict[str, EntityState] = {}
        self._lock       = asyncio.Lock()
        self._dirty:     Set[str] = set()  # Entity IDs that need persisting
        log.info("[EntityEngine] Initialised")

    async def load_state(self):
        """Load entity state from DuckDB on startup."""
        try:
            entities, total = await self.storage.get_entities(limit=10000)
            async with self._lock:
                for e_dict in entities:
                    entity = EntityState.from_dict(e_dict)
                    self._entities[entity.entity_id] = entity
            log.info(f"[EntityEngine] Loaded {len(self._entities)} entities from storage")
        except Exception as ex:
            log.error(f"[EntityEngine] load_state error: {ex}")

    async def save_state(self):
        """Persist all dirty entities to DuckDB."""
        async with self._lock:
            dirty = list(self._dirty)
            self._dirty.clear()

        saved = 0
        for entity_id in dirty:
            async with self._lock:
                entity = self._entities.get(entity_id)
            if entity:
                await self.storage.upsert_entity(entity.to_dict())
                saved += 1

        if saved > 0:
            log.info(f"[EntityEngine] Persisted {saved} entities")

    async def process_event(self, event: Dict[str, Any]) -> List[Dict]:
        """
        Process a single log event and update entity state.
        Returns a list of deviation alerts if any are detected.
        Each alert is a dict ready for insertion into the alerts table.
        """
        alerts = []

        actor  = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or
            "unknown"
        )
        target = (
            event.get("entity", {}).get("target") or
            event.get("target") or
            "unknown"
        )
        source = event.get("source", "unknown")
        ts_str = event.get("timestamp", "")
        ev     = event.get("event", {})
        sev    = ev.get("severity", 1)
        etype  = ev.get("type", "system")
        raw_id = ev.get("raw_event_id", 0)

        # Skip noise
        if actor == "unknown" and sev < 3:
            return alerts

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.now(timezone.utc)

        # Get or create entity for the actor
        entity = await self._get_or_create(actor)

        # Get or create entity for the source host
        if source and source != "unknown" and source != actor:
            await self._get_or_create(source)

        async with self._lock:
            # Update activity
            entity.last_seen   = ts
            entity.event_count += 1
            entity.known_event_types.add(etype)
            self._dirty.add(actor)

            # Track active hours for baseline
            entity.active_hours.add(ts.hour)

            # Track known hosts
            if source and source != "unknown":
                is_new_host = source not in entity.known_hosts
                entity.known_hosts.add(source)
            else:
                is_new_host = False

            # Track known targets
            if target and target != "unknown":
                entity.known_targets.add(target)

            # ── Event-Specific Processing ─────────────────────────────────

            deviations = []

            # Authentication failure (Event ID 4625)
            if raw_id == 4625 or (etype == "auth" and "fail" in ev.get("description", "").lower()):
                entity.auth_failure_count += 1
                entity.risk_score = min(
                    entity.risk_score + RISK_WEIGHTS["auth_failure"],
                    RISK_CEILING,
                )

            # Successful authentication (Event ID 4624)
            elif raw_id == 4624 or (etype == "auth" and "success" in ev.get("description", "").lower()):
                entity.auth_success_count += 1

                # Successful login after failures - suspicious
                if entity.auth_failure_count >= 5:
                    deviations.append({
                        "flag":        "success_after_failures",
                        "description": f"{entity.auth_failure_count} failures before success",
                        "severity":    "HIGH",
                    })
                    entity.auth_failure_count = 0  # Reset counter after detection

                # First time on this host
                if is_new_host:
                    deviations.append({
                        "flag":        "new_host_access",
                        "description": f"First seen on {source}",
                        "severity":    "MEDIUM",
                    })
                    entity.risk_score = min(
                        entity.risk_score + RISK_WEIGHTS["new_host_access"],
                        RISK_CEILING,
                    )

            # Audit log cleared (Event ID 1102) - always critical
            elif raw_id == 1102:
                entity.risk_score = min(
                    entity.risk_score + RISK_WEIGHTS["audit_log_cleared"],
                    RISK_CEILING,
                )
                entity.deviation_flags.add("audit_log_cleared")
                deviations.append({
                    "flag":        "audit_log_cleared",
                    "description": "Security audit log was cleared",
                    "severity":    "CRITICAL",
                })

            # New service installed (Event ID 7045 or 4697)
            elif raw_id in (7045, 4697):
                entity.risk_score = min(
                    entity.risk_score + RISK_WEIGHTS["new_service"],
                    RISK_CEILING,
                )
                deviations.append({
                    "flag":        "new_service",
                    "description": f"New service installed: {ev.get('description', '')}",
                    "severity":    "HIGH",
                })

            # New user account (Event ID 4720)
            elif raw_id == 4720:
                entity.risk_score = min(
                    entity.risk_score + RISK_WEIGHTS["new_admin_account"],
                    RISK_CEILING,
                )
                deviations.append({
                    "flag":        "new_account_created",
                    "description": f"New user account created by {actor}",
                    "severity":    "HIGH",
                })

            # Added to security group (Event IDs 4728, 4732, 4756)
            elif raw_id in (4728, 4732, 4756):
                entity.risk_score = min(
                    entity.risk_score + RISK_WEIGHTS["admin_group_add"],
                    RISK_CEILING,
                )
                deviations.append({
                    "flag":        "group_membership_change",
                    "description": f"{actor} added to security group",
                    "severity":    "HIGH",
                })

            # Scheduled task created (Event ID 4698)
            elif raw_id == 4698:
                entity.risk_score = min(
                    entity.risk_score + RISK_WEIGHTS["scheduled_task"],
                    RISK_CEILING,
                )
                deviations.append({
                    "flag":        "scheduled_task_created",
                    "description": f"Scheduled task created by {actor}",
                    "severity":    "MEDIUM",
                })

            # High severity generic event
            elif sev >= 7:
                entity.risk_score = min(
                    entity.risk_score + RISK_WEIGHTS["high_severity"],
                    RISK_CEILING,
                )

            # ── After-Hours Detection ─────────────────────────────────────
            # Flag auth events outside of 07:00 - 18:00
            if etype == "auth" and entity.event_count > 10:
                if ts.hour >= 22 or ts.hour <= 5:
                    entity.risk_score = min(
                        entity.risk_score + RISK_WEIGHTS["after_hours_access"],
                        RISK_CEILING,
                    )
                    deviations.append({
                        "flag":        "after_hours_access",
                        "description": f"Authentication at {ts.hour:02d}:{ts.minute:02d} UTC",
                        "severity":    "MEDIUM",
                    })

            # ── Stale Account Activity ────────────────────────────────────
            stale_threshold = datetime.now(timezone.utc) - timedelta(days=self.stale_days)
            if entity.last_seen < stale_threshold and etype == "auth":
                entity.risk_score = min(
                    entity.risk_score + RISK_WEIGHTS["stale_account_active"],
                    RISK_CEILING,
                )
                deviations.append({
                    "flag":        "stale_account_active",
                    "description": f"Account inactive for {self.stale_days}+ days, now active",
                    "severity":    "HIGH",
                })

            # Update risk label
            entity.risk_label = score_to_label(entity.risk_score)

            # Add deviation flags to entity state
            for dev in deviations:
                entity.deviation_flags.add(dev["flag"])

            # Record in recent events
            entity.recent_events.append({
                "event_id":  event.get("event_id"),
                "timestamp": ts_str,
                "type":      etype,
                "severity":  sev,
                "source":    source,
            })

        # Build alert objects for detected deviations
        for dev in deviations:
            alerts.append(self._build_deviation_alert(
                dev, entity, event, ts
            ))

        # Persist to timeline
        if sev >= 4 or deviations:
            await self.storage.add_entity_timeline_entry({
                "entity_id":   actor,
                "timestamp":   ts_str,
                "event_id":    event.get("event_id", ""),
                "event_type":  etype,
                "target":      target,
                "source_host": source,
                "severity":    sev,
                "description": ev.get("description", ""),
            })

        # Periodic persist - every 50 events per entity
        if entity.event_count % 50 == 0:
            await self.storage.upsert_entity(entity.to_dict())
            async with self._lock:
                self._dirty.discard(actor)

        return alerts

    # ── Lateral Movement Detection ────────────────────────────────────────────

    async def check_lateral_movement(
        self,
        actor:      str,
        window_sec: int = 600,
        threshold:  int = 3,
    ) -> Optional[Dict]:
        """
        Detect lateral movement - same actor authenticating to multiple
        distinct hosts within a short time window.
        Returns an alert dict if detected, None otherwise.
        """
        async with self._lock:
            entity = self._entities.get(actor)
            if not entity:
                return None
            recent = list(entity.recent_events)

        now    = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_sec)

        # Count distinct hosts in recent window
        recent_hosts: Set[str] = set()
        for ev in recent:
            try:
                ts = datetime.fromisoformat(
                    ev["timestamp"].replace("Z", "+00:00")
                )
                if ts >= cutoff and ev.get("source"):
                    recent_hosts.add(ev["source"])
            except (ValueError, KeyError):
                continue

        if len(recent_hosts) >= threshold:
            async with self._lock:
                entity.risk_score = min(
                    entity.risk_score + RISK_WEIGHTS["lateral_movement"],
                    RISK_CEILING,
                )
                entity.risk_label = score_to_label(entity.risk_score)
                entity.deviation_flags.add("lateral_movement")
                self._dirty.add(actor)

            return {
                "flag":        "lateral_movement",
                "actor":       actor,
                "hosts":       list(recent_hosts),
                "description": (
                    f"{actor} authenticated to {len(recent_hosts)} distinct hosts "
                    f"within {window_sec // 60} minutes: {', '.join(list(recent_hosts)[:5])}"
                ),
                "severity":    "CRITICAL",
            }

        return None

    # ── Risk Decay ────────────────────────────────────────────────────────────

    async def apply_risk_decay(self):
        """
        Reduce risk scores for entities that haven't triggered new
        suspicious activity recently. Called periodically by the scheduler.
        Entities with ongoing activity retain their risk scores.
        """
        now     = datetime.now(timezone.utc)
        decayed = 0

        async with self._lock:
            for entity in self._entities.values():
                hours_inactive = (now - entity.last_risk_update).total_seconds() / 3600
                if hours_inactive >= self.decay_hours:
                    decay = RISK_DECAY_PER_HOUR * hours_inactive
                    old_score = entity.risk_score
                    entity.risk_score = max(
                        entity.risk_score - decay,
                        RISK_FLOOR,
                    )
                    if entity.risk_score < old_score:
                        entity.risk_label      = score_to_label(entity.risk_score)
                        entity.last_risk_update = now
                        self._dirty.add(entity.entity_id)
                        decayed += 1

        if decayed > 0:
            log.debug(f"[EntityEngine] Risk decay applied to {decayed} entities")

    # ── Stale Detection ───────────────────────────────────────────────────────

    async def mark_stale_entities(self):
        """
        Mark entities that haven't been seen in stale_days as stale.
        Called periodically. Stale entities still tracked but flagged.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.stale_days)
        marked = 0

        async with self._lock:
            for entity in self._entities.values():
                was_stale = entity.is_stale
                entity.is_stale = entity.last_seen < cutoff
                if entity.is_stale != was_stale:
                    self._dirty.add(entity.entity_id)
                    marked += 1

        if marked > 0:
            log.info(f"[EntityEngine] Marked {marked} entities as stale/active")

    # ── Getters ───────────────────────────────────────────────────────────────

    async def get_entity(self, entity_id: str) -> Optional[Dict]:
        """Get entity state dict by ID."""
        async with self._lock:
            entity = self._entities.get(entity_id)
            return entity.to_dict() if entity else None

    async def get_top_risk_entities(
        self,
        limit:       int = 20,
        entity_type: Optional[str] = None,
    ) -> List[Dict]:
        """Get entities sorted by risk score descending."""
        async with self._lock:
            entities = list(self._entities.values())

        if entity_type:
            entities = [e for e in entities if e.entity_type == entity_type]

        entities.sort(key=lambda e: e.risk_score, reverse=True)
        return [e.to_dict() for e in entities[:limit]]

    async def get_stats(self) -> Dict[str, Any]:
        """Return entity engine statistics."""
        async with self._lock:
            total    = len(self._entities)
            by_type  = defaultdict(int)
            by_risk  = defaultdict(int)
            stale    = 0
            for e in self._entities.values():
                by_type[e.entity_type] += 1
                by_risk[e.risk_label]  += 1
                if e.is_stale:
                    stale += 1

        return {
            "total_entities": total,
            "by_type":        dict(by_type),
            "by_risk_label":  dict(by_risk),
            "stale":          stale,
            "dirty_queue":    len(self._dirty),
        }

    async def search_entities(
        self,
        query: str,
        limit: int = 20,
    ) -> List[Dict]:
        """Search entities by ID substring."""
        query_lower = query.lower()
        async with self._lock:
            matches = [
                e for e in self._entities.values()
                if query_lower in e.entity_id.lower()
            ]
        matches.sort(key=lambda e: e.risk_score, reverse=True)
        return [e.to_dict() for e in matches[:limit]]

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _get_or_create(self, entity_id: str) -> EntityState:
        """Get existing entity or create a new one."""
        async with self._lock:
            if entity_id not in self._entities:
                entity_type = classify_entity(entity_id)
                entity = EntityState(entity_id, entity_type)
                self._entities[entity_id] = entity
                self._dirty.add(entity_id)
                log.debug(f"[EntityEngine] New entity: {entity_id} ({entity_type})")
            return self._entities[entity_id]

    def _build_deviation_alert(
        self,
        deviation: Dict,
        entity:    EntityState,
        event:     Dict,
        ts:        datetime,
    ) -> Dict:
        """Build an alert dict from a detected deviation."""
        import uuid
        severity_map = {
            "CRITICAL": 10,
            "HIGH":      7,
            "MEDIUM":    5,
            "LOW":       3,
            "INFO":      1,
        }
        sev_str   = deviation.get("severity", "MEDIUM")
        sev_score = severity_map.get(sev_str, 5)

        return {
            "alert_id":      str(uuid.uuid4()),
            "timestamp":     ts.isoformat(),
            "alert_type":    deviation["flag"],
            "severity":      sev_str,
            "severity_score": sev_score,
            "title":         f"{deviation['flag'].replace('_', ' ').title()} - {entity.entity_id}",
            "description":   deviation["description"],
            "actor":         entity.entity_id,
            "target":        event.get("entity", {}).get("target") or event.get("target"),
            "source_host":   event.get("source"),
            "event_ids":     [event.get("event_id", "")],
            "mitre_technique": event.get("mitre", {}).get("technique_id"),
            "mitre_tactic":    event.get("mitre", {}).get("tactic_name"),
        }