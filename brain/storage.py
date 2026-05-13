"""
LogClaw Brain — Storage Layer
storage.py — DuckDB schema, queries, Parquet archiving

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : All database operations for the LogClaw brain. Uses DuckDB
          as the primary local database — fast, embedded, no server
          required. Historical events are archived to Parquet files
          for long-term storage and efficient querying. Every table
          is defined here. Every query goes through this module.
          Nothing else in the codebase touches the database directly.
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
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Third Party ───────────────────────────────────────────────────────────────
import duckdb

log = logging.getLogger("logclaw.storage")


# ── Schema ────────────────────────────────────────────────────────────────────
# All tables defined as constants. Every column is documented.
# DuckDB uses standard SQL with extensions for time-series operations.

SCHEMA_SQL = """
-- ── Events ──────────────────────────────────────────────────────────────────
-- The core events table. Every normalised log event from every source
-- lands here. Partitioned by timestamp for efficient time-range queries.

CREATE TABLE IF NOT EXISTS events (
    event_id        VARCHAR PRIMARY KEY,    -- UUID from harvester
    timestamp       TIMESTAMPTZ NOT NULL,   -- UTC — always UTC
    platform        VARCHAR NOT NULL,       -- windows | linux | network | file
    source          VARCHAR NOT NULL,       -- hostname or device identifier
    actor           VARCHAR,               -- user / service / IP performing action
    target          VARCHAR,               -- host / service / endpoint acted upon
    event_type      VARCHAR NOT NULL,       -- auth | network | config | process | file | system
    severity        INTEGER NOT NULL,       -- 0-10
    raw_event_id    INTEGER,               -- Windows Event ID or syslog facility
    description     VARCHAR,               -- normalised human-readable description
    mitre_technique VARCHAR,               -- T1110, T1078, etc.
    mitre_tactic    VARCHAR,               -- credential-access, lateral-movement, etc.
    raw_payload     VARCHAR,               -- original log line preserved
    ingested_at     TIMESTAMPTZ DEFAULT now() -- when brain received this event
);

-- Index for time-range queries — the most common query pattern
CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON events (timestamp DESC);

-- Index for actor-based queries — entity tracking
CREATE INDEX IF NOT EXISTS idx_events_actor
    ON events (actor, timestamp DESC);

-- Index for source-based queries — per-host analysis
CREATE INDEX IF NOT EXISTS idx_events_source
    ON events (source, timestamp DESC);

-- Index for platform filtering
CREATE INDEX IF NOT EXISTS idx_events_platform
    ON events (platform, timestamp DESC);

-- Index for event type filtering
CREATE INDEX IF NOT EXISTS idx_events_type
    ON events (event_type, timestamp DESC);


-- ── Entities ─────────────────────────────────────────────────────────────────
-- Tracks the state and behaviour history of every actor seen in the logs.
-- An entity can be a user account, an IP address, a hostname, or a service.

CREATE TABLE IF NOT EXISTS entities (
    entity_id       VARCHAR PRIMARY KEY,    -- normalised identifier (lowercase)
    entity_type     VARCHAR NOT NULL,       -- user | ip | host | service
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    event_count     BIGINT DEFAULT 0,
    risk_score      DOUBLE DEFAULT 0.0,     -- 0.0 - 100.0
    risk_label      VARCHAR DEFAULT 'CLEAN',-- CLEAN | LOW | MEDIUM | HIGH | CRITICAL
    is_stale        BOOLEAN DEFAULT false,
    tags            VARCHAR DEFAULT '[]',   -- JSON array of string tags
    metadata        VARCHAR DEFAULT '{}',   -- JSON object for arbitrary fields
    updated_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_entities_type
    ON entities (entity_type, risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_entities_last_seen
    ON entities (last_seen DESC);


-- ── Entity Timeline ───────────────────────────────────────────────────────────
-- Tracks every interaction an entity has had over time.
-- Used to build behavioral baselines and detect deviations.

CREATE TABLE IF NOT EXISTS entity_timeline (
    id              BIGINT PRIMARY KEY,     -- auto-increment
    entity_id       VARCHAR NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    event_id        VARCHAR NOT NULL,       -- FK to events.event_id
    event_type      VARCHAR NOT NULL,
    target          VARCHAR,
    source_host     VARCHAR,
    severity        INTEGER,
    description     VARCHAR
);

CREATE SEQUENCE IF NOT EXISTS entity_timeline_seq START 1;

CREATE INDEX IF NOT EXISTS idx_entity_timeline_entity
    ON entity_timeline (entity_id, timestamp DESC);


-- ── Alerts ───────────────────────────────────────────────────────────────────
-- Correlated alerts generated by the correlation engine.
-- Each alert represents a detected pattern or Sigma rule match.

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        VARCHAR PRIMARY KEY,    -- UUID
    timestamp       TIMESTAMPTZ NOT NULL,   -- when pattern was detected
    alert_type      VARCHAR NOT NULL,       -- brute_force | lateral_movement | etc.
    severity        VARCHAR NOT NULL,       -- INFO | LOW | MEDIUM | HIGH | CRITICAL
    severity_score  INTEGER NOT NULL,       -- 0-10
    title           VARCHAR NOT NULL,       -- short human-readable title
    description     VARCHAR,               -- detailed description
    actor           VARCHAR,               -- primary entity involved
    target          VARCHAR,               -- primary target
    source_host     VARCHAR,               -- originating host
    event_ids       VARCHAR DEFAULT '[]',   -- JSON array of contributing event IDs
    five_w          VARCHAR DEFAULT '{}',   -- JSON 5W+H object
    sigma_rule_id   VARCHAR,               -- which Sigma rule fired (if any)
    mitre_technique VARCHAR,
    mitre_tactic    VARCHAR,
    status          VARCHAR DEFAULT 'open', -- open | acknowledged | resolved | false_positive
    acknowledged_by VARCHAR,
    acknowledged_at TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    ai_narrative    VARCHAR,               -- AI-generated plain-English explanation
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
    ON alerts (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_severity
    ON alerts (severity_score DESC, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alerts (status, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_actor
    ON alerts (actor, timestamp DESC);


-- ── Investigations ────────────────────────────────────────────────────────────
-- Analyst-created investigation cases grouping related alerts and events.

CREATE TABLE IF NOT EXISTS investigations (
    investigation_id VARCHAR PRIMARY KEY,
    title            VARCHAR NOT NULL,
    description      VARCHAR,
    status           VARCHAR DEFAULT 'open', -- open | in_progress | closed
    severity         VARCHAR DEFAULT 'MEDIUM',
    assigned_to      VARCHAR,
    alert_ids        VARCHAR DEFAULT '[]',   -- JSON array
    event_ids        VARCHAR DEFAULT '[]',   -- JSON array
    notes            VARCHAR DEFAULT '[]',   -- JSON array of note objects
    timeline         VARCHAR DEFAULT '[]',   -- JSON array of timeline entries
    created_at       TIMESTAMPTZ DEFAULT now(),
    updated_at       TIMESTAMPTZ DEFAULT now(),
    closed_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_investigations_status
    ON investigations (status, created_at DESC);


-- ── Sigma Rules ───────────────────────────────────────────────────────────────
-- Metadata for loaded Sigma rules. The actual rule YAML is stored on disk.
-- This table tracks which rules are active and their match history.

CREATE TABLE IF NOT EXISTS sigma_rules (
    rule_id         VARCHAR PRIMARY KEY,    -- from Sigma rule id field
    title           VARCHAR NOT NULL,
    description     VARCHAR,
    status          VARCHAR,               -- stable | test | experimental
    level           VARCHAR,               -- critical | high | medium | low | informational
    tags            VARCHAR DEFAULT '[]',   -- JSON array (includes MITRE tags)
    file_path       VARCHAR NOT NULL,       -- path to the .yml file on disk
    is_active       BOOLEAN DEFAULT true,
    match_count     BIGINT DEFAULT 0,
    last_matched    TIMESTAMPTZ,
    loaded_at       TIMESTAMPTZ DEFAULT now()
);


-- ── System Stats ──────────────────────────────────────────────────────────────
-- Internal counters and health metrics for the brain.

CREATE TABLE IF NOT EXISTS system_stats (
    stat_key        VARCHAR PRIMARY KEY,
    stat_value      VARCHAR NOT NULL,
    updated_at      TIMESTAMPTZ DEFAULT now()
);

INSERT OR IGNORE INTO system_stats (stat_key, stat_value)
VALUES
    ('events_total',    '0'),
    ('alerts_total',    '0'),
    ('entities_total',  '0'),
    ('brain_started_at', now()::VARCHAR);
"""


# ── Storage Class ─────────────────────────────────────────────────────────────

class Storage:
    """
    All database operations for LogClaw Brain.
    Uses DuckDB for embedded local storage.
    Thread-safe via asyncio lock for concurrent writes.
    """

    def __init__(self, db_path: str):
        self.db_path  = db_path
        self._conn    = None
        self._lock    = asyncio.Lock()
        self._parquet_dir = Path(db_path).parent / "parquet"
        self._parquet_dir.mkdir(parents=True, exist_ok=True)

    async def initialise(self):
        """Create database connection and apply schema."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._init_sync)
        log.info(f"[Storage] Database: {self.db_path}")

    def _init_sync(self):
        """Synchronous initialisation — runs in executor."""
        self._conn = duckdb.connect(self.db_path)
        self._conn.execute(SCHEMA_SQL)
        self._conn.commit()
        log.info("[Storage] Schema applied")

    async def close(self):
        """Close the database connection cleanly."""
        if self._conn:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._conn.close)
            self._conn = None

    def _exec(self, sql: str, params: tuple = ()) -> duckdb.DuckDBPyRelation:
        """Execute a query synchronously. Always called via run_in_executor."""
        return self._conn.execute(sql, list(params))

    def _fetchall(self, sql: str, params: tuple = ()) -> List[tuple]:
        return self._conn.execute(sql, list(params)).fetchall()

    def _fetchone(self, sql: str, params: tuple = ()) -> Optional[tuple]:
        return self._conn.execute(sql, list(params)).fetchone()

    # ── Event Operations ──────────────────────────────────────────────────────

    async def insert_event(self, event: Dict[str, Any]) -> bool:
        """
        Insert a single normalised event into the events table.
        Returns True on success, False if duplicate (event_id already exists).
        """
        sql = """
            INSERT OR IGNORE INTO events (
                event_id, timestamp, platform, source,
                actor, target, event_type, severity,
                raw_event_id, description, mitre_technique,
                mitre_tactic, raw_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            event.get("event_id"),
            event.get("timestamp"),
            event.get("platform", "unknown"),
            event.get("source", "unknown"),
            event.get("entity", {}).get("actor", "unknown"),
            event.get("entity", {}).get("target", "unknown"),
            event.get("event", {}).get("type", "system"),
            event.get("event", {}).get("severity", 1),
            event.get("event", {}).get("raw_event_id"),
            event.get("event", {}).get("description"),
            event.get("mitre", {}).get("technique_id"),
            event.get("mitre", {}).get("tactic_name"),
            event.get("raw_payload", ""),
        )
        async with self._lock:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._exec, sql, params)
                await loop.run_in_executor(None, self._conn.commit)
                return True
            except Exception as e:
                log.error(f"[Storage] insert_event error: {e}")
                return False

    async def insert_events_batch(self, events: List[Dict[str, Any]]) -> int:
        """
        Batch insert multiple events. Much faster than individual inserts
        for high-volume ingestion. Returns count of successfully inserted events.
        """
        if not events:
            return 0

        rows = []
        for event in events:
            rows.append((
                event.get("event_id"),
                event.get("timestamp"),
                event.get("platform", "unknown"),
                event.get("source", "unknown"),
                event.get("entity", {}).get("actor", "unknown"),
                event.get("entity", {}).get("target", "unknown"),
                event.get("event", {}).get("type", "system"),
                event.get("event", {}).get("severity", 1),
                event.get("event", {}).get("raw_event_id"),
                event.get("event", {}).get("description"),
                event.get("mitre", {}).get("technique_id"),
                event.get("mitre", {}).get("tactic_name"),
                event.get("raw_payload", ""),
            ))

        sql = """
            INSERT OR IGNORE INTO events (
                event_id, timestamp, platform, source,
                actor, target, event_type, severity,
                raw_event_id, description, mitre_technique,
                mitre_tactic, raw_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        async with self._lock:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(
                    None,
                    lambda: self._conn.executemany(sql, rows)
                )
                await loop.run_in_executor(None, self._conn.commit)
                return len(rows)
            except Exception as e:
                log.error(f"[Storage] insert_events_batch error: {e}")
                return 0

    async def get_events(
        self,
        limit:      int = 100,
        offset:     int = 0,
        platform:   Optional[str] = None,
        source:     Optional[str] = None,
        actor:      Optional[str] = None,
        event_type: Optional[str] = None,
        severity_min: int = 0,
        since:      Optional[datetime] = None,
        until:      Optional[datetime] = None,
        search:     Optional[str] = None,
    ) -> Tuple[List[Dict], int]:
        """
        Query events with filtering. Returns (events, total_count).
        All filters are optional and combinable.
        """
        conditions = ["1=1"]
        params     = []

        if platform:
            conditions.append("platform = ?")
            params.append(platform)
        if source:
            conditions.append("source ILIKE ?")
            params.append(f"%{source}%")
        if actor:
            conditions.append("actor ILIKE ?")
            params.append(f"%{actor}%")
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if severity_min > 0:
            conditions.append("severity >= ?")
            params.append(severity_min)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        if until:
            conditions.append("timestamp <= ?")
            params.append(until.isoformat())
        if search:
            conditions.append("(description ILIKE ? OR actor ILIKE ? OR raw_payload ILIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        where = " AND ".join(conditions)

        count_sql = f"SELECT COUNT(*) FROM events WHERE {where}"
        query_sql = f"""
            SELECT
                event_id, timestamp, platform, source,
                actor, target, event_type, severity,
                raw_event_id, description, mitre_technique,
                mitre_tactic, raw_payload, ingested_at
            FROM events
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """

        loop = asyncio.get_event_loop()
        count_params = tuple(params)
        query_params = tuple(params) + (limit, offset)

        total = await loop.run_in_executor(
            None, self._fetchone, count_sql, count_params
        )
        rows = await loop.run_in_executor(
            None, self._fetchall, query_sql, query_params
        )

        events = [self._row_to_event(r) for r in rows]
        return events, (total[0] if total else 0)

    async def get_events_in_window(
        self,
        since: datetime,
        until: Optional[datetime] = None,
        actor: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[Dict]:
        """Get all events within a time window. Used by correlation engine."""
        until = until or datetime.now(timezone.utc)
        conditions = ["timestamp >= ? AND timestamp <= ?"]
        params: List[Any] = [since.isoformat(), until.isoformat()]

        if actor:
            conditions.append("actor = ?")
            params.append(actor)
        if source:
            conditions.append("source = ?")
            params.append(source)

        sql = f"""
            SELECT
                event_id, timestamp, platform, source,
                actor, target, event_type, severity,
                raw_event_id, description, mitre_technique,
                mitre_tactic, raw_payload, ingested_at
            FROM events
            WHERE {" AND ".join(conditions)}
            ORDER BY timestamp ASC
        """
        loop = asyncio.get_event_loop()
        rows = await loop.run_in_executor(None, self._fetchall, sql, tuple(params))
        return [self._row_to_event(r) for r in rows]

    def _row_to_event(self, row: tuple) -> Dict:
        """Convert a database row tuple to an event dict."""
        return {
            "event_id":       row[0],
            "timestamp":      row[1].isoformat() if row[1] else None,
            "platform":       row[2],
            "source":         row[3],
            "actor":          row[4],
            "target":         row[5],
            "event_type":     row[6],
            "severity":       row[7],
            "raw_event_id":   row[8],
            "description":    row[9],
            "mitre_technique": row[10],
            "mitre_tactic":   row[11],
            "raw_payload":    row[12],
            "ingested_at":    row[13].isoformat() if row[13] else None,
        }

    # ── Entity Operations ─────────────────────────────────────────────────────

    async def upsert_entity(self, entity: Dict[str, Any]) -> bool:
        """Insert or update an entity record."""
        sql = """
            INSERT INTO entities (
                entity_id, entity_type, first_seen, last_seen,
                event_count, risk_score, risk_label, tags, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (entity_id) DO UPDATE SET
                last_seen   = excluded.last_seen,
                event_count = entities.event_count + excluded.event_count,
                risk_score  = excluded.risk_score,
                risk_label  = excluded.risk_label,
                tags        = excluded.tags,
                metadata    = excluded.metadata,
                updated_at  = now()
        """
        params = (
            entity["entity_id"],
            entity["entity_type"],
            entity.get("first_seen", datetime.now(timezone.utc).isoformat()),
            entity.get("last_seen",  datetime.now(timezone.utc).isoformat()),
            entity.get("event_count", 1),
            entity.get("risk_score", 0.0),
            entity.get("risk_label", "CLEAN"),
            json.dumps(entity.get("tags", [])),
            json.dumps(entity.get("metadata", {})),
        )
        async with self._lock:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._exec, sql, params)
                await loop.run_in_executor(None, self._conn.commit)
                return True
            except Exception as e:
                log.error(f"[Storage] upsert_entity error: {e}")
                return False

    async def get_entity(self, entity_id: str) -> Optional[Dict]:
        """Get a single entity by ID."""
        sql = """
            SELECT entity_id, entity_type, first_seen, last_seen,
                   event_count, risk_score, risk_label, is_stale,
                   tags, metadata, updated_at
            FROM entities WHERE entity_id = ?
        """
        loop = asyncio.get_event_loop()
        row  = await loop.run_in_executor(None, self._fetchone, sql, (entity_id,))
        if not row:
            return None
        return self._row_to_entity(row)

    async def get_entities(
        self,
        limit:       int = 100,
        offset:      int = 0,
        entity_type: Optional[str] = None,
        risk_min:    float = 0.0,
        is_stale:    Optional[bool] = None,
        search:      Optional[str] = None,
    ) -> Tuple[List[Dict], int]:
        """Query entities with filtering."""
        conditions = ["1=1"]
        params: List[Any] = []

        if entity_type:
            conditions.append("entity_type = ?")
            params.append(entity_type)
        if risk_min > 0:
            conditions.append("risk_score >= ?")
            params.append(risk_min)
        if is_stale is not None:
            conditions.append("is_stale = ?")
            params.append(is_stale)
        if search:
            conditions.append("entity_id ILIKE ?")
            params.append(f"%{search}%")

        where = " AND ".join(conditions)
        count_sql = f"SELECT COUNT(*) FROM entities WHERE {where}"
        query_sql = f"""
            SELECT entity_id, entity_type, first_seen, last_seen,
                   event_count, risk_score, risk_label, is_stale,
                   tags, metadata, updated_at
            FROM entities
            WHERE {where}
            ORDER BY risk_score DESC, last_seen DESC
            LIMIT ? OFFSET ?
        """
        loop = asyncio.get_event_loop()
        total = await loop.run_in_executor(None, self._fetchone, count_sql, tuple(params))
        rows  = await loop.run_in_executor(None, self._fetchall, query_sql, tuple(params) + (limit, offset))
        return [self._row_to_entity(r) for r in rows], (total[0] if total else 0)

    def _row_to_entity(self, row: tuple) -> Dict:
        return {
            "entity_id":   row[0],
            "entity_type": row[1],
            "first_seen":  row[2].isoformat() if row[2] else None,
            "last_seen":   row[3].isoformat() if row[3] else None,
            "event_count": row[4],
            "risk_score":  row[5],
            "risk_label":  row[6],
            "is_stale":    row[7],
            "tags":        json.loads(row[8]) if row[8] else [],
            "metadata":    json.loads(row[9]) if row[9] else {},
            "updated_at":  row[10].isoformat() if row[10] else None,
        }

    async def add_entity_timeline_entry(self, entry: Dict[str, Any]) -> bool:
        """Add an entry to an entity's behavioural timeline."""
        sql = """
            INSERT INTO entity_timeline (
                id, entity_id, timestamp, event_id,
                event_type, target, source_host, severity, description
            ) VALUES (nextval('entity_timeline_seq'), ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            entry["entity_id"],
            entry["timestamp"],
            entry["event_id"],
            entry["event_type"],
            entry.get("target"),
            entry.get("source_host"),
            entry.get("severity", 1),
            entry.get("description"),
        )
        async with self._lock:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._exec, sql, params)
                await loop.run_in_executor(None, self._conn.commit)
                return True
            except Exception as e:
                log.error(f"[Storage] add_entity_timeline_entry error: {e}")
                return False

    async def get_entity_timeline(
        self,
        entity_id: str,
        limit: int = 200,
        since: Optional[datetime] = None,
    ) -> List[Dict]:
        """Get the behavioural timeline for an entity."""
        conditions = ["entity_id = ?"]
        params: List[Any] = [entity_id]
        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        sql = f"""
            SELECT id, entity_id, timestamp, event_id,
                   event_type, target, source_host, severity, description
            FROM entity_timeline
            WHERE {" AND ".join(conditions)}
            ORDER BY timestamp DESC
            LIMIT ?
        """
        params.append(limit)
        loop = asyncio.get_event_loop()
        rows = await loop.run_in_executor(None, self._fetchall, sql, tuple(params))
        return [
            {
                "id":          r[0],
                "entity_id":   r[1],
                "timestamp":   r[2].isoformat() if r[2] else None,
                "event_id":    r[3],
                "event_type":  r[4],
                "target":      r[5],
                "source_host": r[6],
                "severity":    r[7],
                "description": r[8],
            }
            for r in rows
        ]

    # ── Alert Operations ──────────────────────────────────────────────────────

    async def insert_alert(self, alert: Dict[str, Any]) -> bool:
        """Insert a new alert generated by the correlation engine."""
        sql = """
            INSERT OR IGNORE INTO alerts (
                alert_id, timestamp, alert_type, severity, severity_score,
                title, description, actor, target, source_host,
                event_ids, five_w, sigma_rule_id, mitre_technique,
                mitre_tactic, ai_narrative
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            alert["alert_id"],
            alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
            alert["alert_type"],
            alert["severity"],
            alert["severity_score"],
            alert["title"],
            alert.get("description"),
            alert.get("actor"),
            alert.get("target"),
            alert.get("source_host"),
            json.dumps(alert.get("event_ids", [])),
            json.dumps(alert.get("five_w", {})),
            alert.get("sigma_rule_id"),
            alert.get("mitre_technique"),
            alert.get("mitre_tactic"),
            alert.get("ai_narrative"),
        )
        async with self._lock:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._exec, sql, params)
                await loop.run_in_executor(None, self._conn.commit)
                return True
            except Exception as e:
                log.error(f"[Storage] insert_alert error: {e}")
                return False

    async def get_alerts(
        self,
        limit:      int = 100,
        offset:     int = 0,
        severity:   Optional[str] = None,
        status:     Optional[str] = None,
        actor:      Optional[str] = None,
        alert_type: Optional[str] = None,
        since:      Optional[datetime] = None,
    ) -> Tuple[List[Dict], int]:
        """Query alerts with filtering."""
        conditions = ["1=1"]
        params: List[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if actor:
            conditions.append("actor ILIKE ?")
            params.append(f"%{actor}%")
        if alert_type:
            conditions.append("alert_type = ?")
            params.append(alert_type)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())

        where     = " AND ".join(conditions)
        count_sql = f"SELECT COUNT(*) FROM alerts WHERE {where}"
        query_sql = f"""
            SELECT alert_id, timestamp, alert_type, severity, severity_score,
                   title, description, actor, target, source_host,
                   event_ids, five_w, sigma_rule_id, mitre_technique,
                   mitre_tactic, status, acknowledged_by, acknowledged_at,
                   resolved_at, ai_narrative, created_at
            FROM alerts
            WHERE {where}
            ORDER BY severity_score DESC, timestamp DESC
            LIMIT ? OFFSET ?
        """
        loop  = asyncio.get_event_loop()
        total = await loop.run_in_executor(None, self._fetchone, count_sql, tuple(params))
        rows  = await loop.run_in_executor(None, self._fetchall, query_sql, tuple(params) + (limit, offset))
        return [self._row_to_alert(r) for r in rows], (total[0] if total else 0)

    async def update_alert_status(
        self,
        alert_id: str,
        status:   str,
        by:       Optional[str] = None,
    ) -> bool:
        """Update alert status — acknowledge, resolve, or mark false positive."""
        now = datetime.now(timezone.utc).isoformat()
        if status == "acknowledged":
            sql = "UPDATE alerts SET status=?, acknowledged_by=?, acknowledged_at=? WHERE alert_id=?"
            params = (status, by, now, alert_id)
        elif status == "resolved":
            sql = "UPDATE alerts SET status=?, resolved_at=? WHERE alert_id=?"
            params = (status, now, alert_id)
        else:
            sql = "UPDATE alerts SET status=? WHERE alert_id=?"
            params = (status, alert_id)

        async with self._lock:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._exec, sql, params)
                await loop.run_in_executor(None, self._conn.commit)
                return True
            except Exception as e:
                log.error(f"[Storage] update_alert_status error: {e}")
                return False

    async def update_alert_ai_narrative(self, alert_id: str, narrative: str) -> bool:
        """Attach AI-generated narrative to an alert."""
        sql = "UPDATE alerts SET ai_narrative=? WHERE alert_id=?"
        async with self._lock:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._exec, sql, (narrative, alert_id))
                await loop.run_in_executor(None, self._conn.commit)
                return True
            except Exception as e:
                log.error(f"[Storage] update_alert_ai_narrative error: {e}")
                return False

    def _row_to_alert(self, row: tuple) -> Dict:
        return {
            "alert_id":        row[0],
            "timestamp":       row[1].isoformat() if row[1] else None,
            "alert_type":      row[2],
            "severity":        row[3],
            "severity_score":  row[4],
            "title":           row[5],
            "description":     row[6],
            "actor":           row[7],
            "target":          row[8],
            "source_host":     row[9],
            "event_ids":       json.loads(row[10]) if row[10] else [],
            "five_w":          json.loads(row[11]) if row[11] else {},
            "sigma_rule_id":   row[12],
            "mitre_technique": row[13],
            "mitre_tactic":    row[14],
            "status":          row[15],
            "acknowledged_by": row[16],
            "acknowledged_at": row[17].isoformat() if row[17] else None,
            "resolved_at":     row[18].isoformat() if row[18] else None,
            "ai_narrative":    row[19],
            "created_at":      row[20].isoformat() if row[20] else None,
        }

    # ── Investigation Operations ───────────────────────────────────────────────

    async def create_investigation(self, investigation: Dict[str, Any]) -> bool:
        """Create a new investigation case."""
        sql = """
            INSERT INTO investigations (
                investigation_id, title, description, status,
                severity, assigned_to, alert_ids, event_ids
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            investigation["investigation_id"],
            investigation["title"],
            investigation.get("description"),
            investigation.get("status", "open"),
            investigation.get("severity", "MEDIUM"),
            investigation.get("assigned_to"),
            json.dumps(investigation.get("alert_ids", [])),
            json.dumps(investigation.get("event_ids", [])),
        )
        async with self._lock:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._exec, sql, params)
                await loop.run_in_executor(None, self._conn.commit)
                return True
            except Exception as e:
                log.error(f"[Storage] create_investigation error: {e}")
                return False

    async def get_investigations(
        self,
        limit:  int = 50,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> Tuple[List[Dict], int]:
        """Get investigation cases."""
        conditions = ["1=1"]
        params: List[Any] = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        where     = " AND ".join(conditions)
        count_sql = f"SELECT COUNT(*) FROM investigations WHERE {where}"
        query_sql = f"""
            SELECT investigation_id, title, description, status,
                   severity, assigned_to, alert_ids, event_ids,
                   notes, timeline, created_at, updated_at, closed_at
            FROM investigations
            WHERE {where}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """
        loop  = asyncio.get_event_loop()
        total = await loop.run_in_executor(None, self._fetchone, count_sql, tuple(params))
        rows  = await loop.run_in_executor(None, self._fetchall, query_sql, tuple(params) + (limit, offset))
        return [self._row_to_investigation(r) for r in rows], (total[0] if total else 0)

    def _row_to_investigation(self, row: tuple) -> Dict:
        return {
            "investigation_id": row[0],
            "title":            row[1],
            "description":      row[2],
            "status":           row[3],
            "severity":         row[4],
            "assigned_to":      row[5],
            "alert_ids":        json.loads(row[6])  if row[6]  else [],
            "event_ids":        json.loads(row[7])  if row[7]  else [],
            "notes":            json.loads(row[8])  if row[8]  else [],
            "timeline":         json.loads(row[9])  if row[9]  else [],
            "created_at":       row[10].isoformat() if row[10] else None,
            "updated_at":       row[11].isoformat() if row[11] else None,
            "closed_at":        row[12].isoformat() if row[12] else None,
        }

    # ── Sigma Rule Operations ─────────────────────────────────────────────────

    async def upsert_sigma_rule(self, rule: Dict[str, Any]) -> bool:
        """Insert or update a Sigma rule record."""
        sql = """
            INSERT INTO sigma_rules (
                rule_id, title, description, status, level,
                tags, file_path, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (rule_id) DO UPDATE SET
                title     = excluded.title,
                status    = excluded.status,
                level     = excluded.level,
                tags      = excluded.tags,
                file_path = excluded.file_path,
                loaded_at = now()
        """
        params = (
            rule["rule_id"],
            rule["title"],
            rule.get("description"),
            rule.get("status"),
            rule.get("level"),
            json.dumps(rule.get("tags", [])),
            rule["file_path"],
            rule.get("is_active", True),
        )
        async with self._lock:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._exec, sql, params)
                await loop.run_in_executor(None, self._conn.commit)
                return True
            except Exception as e:
                log.error(f"[Storage] upsert_sigma_rule error: {e}")
                return False

    async def increment_sigma_match(self, rule_id: str) -> bool:
        """Increment the match counter for a Sigma rule."""
        sql = """
            UPDATE sigma_rules
            SET match_count = match_count + 1, last_matched = now()
            WHERE rule_id = ?
        """
        async with self._lock:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._exec, sql, (rule_id,))
                await loop.run_in_executor(None, self._conn.commit)
                return True
            except Exception as e:
                log.error(f"[Storage] increment_sigma_match error: {e}")
                return False

    async def get_sigma_rules(self, active_only: bool = True) -> List[Dict]:
        """Get all loaded Sigma rules."""
        sql = """
            SELECT rule_id, title, description, status, level,
                   tags, file_path, is_active, match_count, last_matched, loaded_at
            FROM sigma_rules
        """
        if active_only:
            sql += " WHERE is_active = true"
        sql += " ORDER BY level, title"
        loop = asyncio.get_event_loop()
        rows = await loop.run_in_executor(None, self._fetchall, sql, ())
        return [
            {
                "rule_id":     r[0],
                "title":       r[1],
                "description": r[2],
                "status":      r[3],
                "level":       r[4],
                "tags":        json.loads(r[5]) if r[5] else [],
                "file_path":   r[6],
                "is_active":   r[7],
                "match_count": r[8],
                "last_matched": r[9].isoformat() if r[9] else None,
                "loaded_at":   r[10].isoformat() if r[10] else None,
            }
            for r in rows
        ]

    # ── Statistics ────────────────────────────────────────────────────────────

    async def get_stats(self) -> Dict[str, Any]:
        """Get overall system statistics."""
        loop = asyncio.get_event_loop()

        counts = await loop.run_in_executor(None, self._fetchall, """
            SELECT
                (SELECT COUNT(*) FROM events)        AS events_total,
                (SELECT COUNT(*) FROM alerts)        AS alerts_total,
                (SELECT COUNT(*) FROM alerts WHERE status = 'open') AS alerts_open,
                (SELECT COUNT(*) FROM entities)      AS entities_total,
                (SELECT COUNT(*) FROM sigma_rules WHERE is_active = true) AS rules_active,
                (SELECT COUNT(*) FROM investigations WHERE status != 'closed') AS investigations_open
        """, ())

        row = counts[0] if counts else (0, 0, 0, 0, 0, 0)

        recent = await loop.run_in_executor(None, self._fetchall, """
            SELECT COUNT(*) FROM events
            WHERE timestamp >= now() - INTERVAL '1 hour'
        """, ())

        return {
            "events_total":        row[0],
            "alerts_total":        row[1],
            "alerts_open":         row[2],
            "entities_total":      row[3],
            "rules_active":        row[4],
            "investigations_open": row[5],
            "events_last_hour":    recent[0][0] if recent else 0,
        }

    # ── Parquet Archiving ─────────────────────────────────────────────────────

    async def archive_old_events(self, retention_days: int = 90) -> int:
        """
        Archive events older than retention_days to Parquet files,
        then delete them from DuckDB to keep the database lean.
        Returns number of events archived.
        """
        cutoff    = datetime.now(timezone.utc) - timedelta(days=retention_days)
        date_str  = cutoff.strftime("%Y%m%d")
        parquet_path = self._parquet_dir / f"events_{date_str}.parquet"

        loop = asyncio.get_event_loop()

        async with self._lock:
            try:
                # Count events to archive
                count_row = await loop.run_in_executor(
                    None,
                    self._fetchone,
                    "SELECT COUNT(*) FROM events WHERE timestamp < ?",
                    (cutoff.isoformat(),),
                )
                count = count_row[0] if count_row else 0
                if count == 0:
                    return 0

                # Export to Parquet
                await loop.run_in_executor(None, lambda: self._conn.execute(f"""
                    COPY (
                        SELECT * FROM events WHERE timestamp < '{cutoff.isoformat()}'
                        ORDER BY timestamp
                    ) TO '{parquet_path}' (FORMAT PARQUET, COMPRESSION ZSTD)
                """))

                # Delete archived events from DuckDB
                await loop.run_in_executor(None, lambda: self._conn.execute(
                    "DELETE FROM events WHERE timestamp < ?",
                    [cutoff.isoformat()]
                ))
                await loop.run_in_executor(None, self._conn.commit)

                log.info(f"[Storage] Archived {count} events to {parquet_path.name}")
                return count

            except Exception as e:
                log.error(f"[Storage] archive error: {e}")
                return 0

    async def query_parquet(
        self,
        parquet_glob: str,
        since: datetime,
        until: datetime,
        actor: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query historical events from Parquet archives.
        parquet_glob: e.g. './data/parquet/events_*.parquet'
        """
        conditions = [
            f"timestamp >= '{since.isoformat()}'",
            f"timestamp <= '{until.isoformat()}'",
        ]
        if actor:
            conditions.append(f"actor = '{actor}'")

        where = " AND ".join(conditions)
        sql   = f"""
            SELECT event_id, timestamp, platform, source,
                   actor, target, event_type, severity,
                   raw_event_id, description, mitre_technique,
                   mitre_tactic, raw_payload, ingested_at
            FROM read_parquet('{parquet_glob}')
            WHERE {where}
            ORDER BY timestamp ASC
        """
        loop = asyncio.get_event_loop()
        try:
            rows = await loop.run_in_executor(None, self._fetchall, sql, ())
            return [self._row_to_event(r) for r in rows]
        except Exception as e:
            log.error(f"[Storage] parquet query error: {e}")
            return []