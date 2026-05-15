"""
LogClaw Brain - Sigma Rule Engine
sigma_engine.py - Sigma rule loader, parser, and evaluator

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Loads Sigma-format YAML detection rules from disk, converts
          them into evaluable rule objects, and matches them against
          every incoming log event. Sigma is the open standard for
          SIEM detection rules - thousands of community rules are
          available and importable directly. This engine handles the
          full Sigma condition grammar: keywords, field mappings,
          AND/OR/NOT logic, wildcards, and CIDR matching. Rules that
          fire generate structured alerts identical in format to
          correlation engine alerts - one unified alert pipeline.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import asyncio
import fnmatch
import ipaddress
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Third Party ───────────────────────────────────────────────────────────────
import yaml

log = logging.getLogger("logclaw.sigma")

# ── Sigma Level to Severity Mapping ──────────────────────────────────────────

SIGMA_LEVEL_MAP = {
    "critical":      ("CRITICAL", 10),
    "high":          ("HIGH",      7),
    "medium":        ("MEDIUM",    5),
    "low":           ("LOW",       3),
    "informational": ("INFO",      1),
}

# ── LogClaw Field Mappings ────────────────────────────────────────────────────
# Maps Sigma field names to LogClaw event schema paths.
# Sigma rules reference Windows Event Log field names -
# we map them to our normalised schema.

FIELD_MAPPINGS = {
    # Authentication fields
    "EventID":             "event.raw_event_id",
    "EventId":             "event.raw_event_id",
    "event_id":            "event.raw_event_id",
    "SubjectUserName":     "entity.actor",
    "TargetUserName":      "entity.actor",
    "IpAddress":           "entity.actor",
    "WorkstationName":     "source",
    "ComputerName":        "source",
    "Computer":            "source",

    # Process fields
    "CommandLine":         "raw_payload",
    "NewProcessName":      "raw_payload",
    "ParentProcessName":   "raw_payload",
    "Image":               "raw_payload",

    # Service fields
    "ServiceName":         "raw_payload",
    "ServiceFileName":     "raw_payload",

    # Network fields
    "DestinationIp":       "entity.target",
    "DestinationPort":     "raw_payload",
    "SourceIp":            "entity.actor",

    # Generic
    "Description":         "event.description",
    "Channel":             "raw_payload",
    "Provider_Name":       "raw_payload",
    "LogonType":           "raw_payload",
    "FailureReason":       "raw_payload",

    # Syslog fields
    "Message":             "raw_payload",
    "Hostname":            "source",
    "Facility":            "raw_payload",
    "Severity":            "event.severity",

    # Platform
    "Platform":            "platform",
}


# ── Field Extractor ───────────────────────────────────────────────────────────

def extract_field(event: Dict, field_path: str) -> Optional[str]:
    """
    Extract a value from a LogClaw event dict using a dot-notation path.
    e.g. "event.raw_event_id" -> event["event"]["raw_event_id"]
    Returns string representation or None if not found.
    """
    parts = field_path.split(".")
    current = event

    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None

    if current is None:
        return None

    return str(current)


def get_event_value(event: Dict, sigma_field: str) -> Optional[str]:
    """
    Get a value from an event using a Sigma field name.
    Tries the field mapping first, then falls back to direct key lookup
    in the raw_payload for unmapped fields.
    """
    # Check field mapping
    mapped_path = FIELD_MAPPINGS.get(sigma_field)
    if mapped_path:
        val = extract_field(event, mapped_path)
        if val is not None:
            return val

    # Direct lookup in event dict
    val = event.get(sigma_field)
    if val is not None:
        return str(val)

    # Search in raw_payload for field=value patterns
    raw = event.get("raw_payload", "") or ""
    pattern = rf'{re.escape(sigma_field)}[=:\s]+([^\s,|]+)'
    match   = re.search(pattern, raw, re.IGNORECASE)
    if match:
        return match.group(1)

    return None


# ── Condition Evaluators ──────────────────────────────────────────────────────

def match_value(event_val: Optional[str], rule_val: Any) -> bool:
    """
    Match an event field value against a Sigma rule value.
    Handles: exact match, wildcards (*,?), null checks, numeric comparison.
    """
    if rule_val is None:
        return event_val is None

    if event_val is None:
        return False

    rule_str = str(rule_val)

    # Null keyword
    if rule_str.lower() == "null":
        return event_val is None or event_val == "" or event_val == "null"

    # Wildcard matching
    if "*" in rule_str or "?" in rule_str:
        return fnmatch.fnmatch(event_val.lower(), rule_str.lower())

    # Case-insensitive exact match
    return event_val.lower() == rule_str.lower()


def match_field_condition(
    event:      Dict,
    field_name: str,
    condition:  Any,
) -> bool:
    """
    Evaluate a single field condition from a Sigma detection block.

    Handles:
    - Single value:  field: value
    - List (OR):     field: [val1, val2]  - any match
    - Contains:      field|contains: val
    - Startswith:    field|startswith: val
    - Endswith:      field|endswith: val
    - Contains all:  field|contains|all: [val1, val2]
    - CIDR:          field|cidr: 192.168.0.0/16
    - Re:            field|re: regex pattern
    - All:           field|all: [val1, val2]
    """
    # Parse modifiers from field name (e.g. "CommandLine|contains")
    parts     = field_name.split("|")
    base_field = parts[0]
    modifiers  = [m.lower() for m in parts[1:]] if len(parts) > 1 else []

    event_val = get_event_value(event, base_field)

    # ── CIDR matching ─────────────────────────────────────────────────────────
    if "cidr" in modifiers:
        if event_val is None:
            return False
        try:
            ip  = ipaddress.ip_address(event_val.split("@")[-1])
            net = ipaddress.ip_network(str(condition), strict=False)
            return ip in net
        except ValueError:
            return False

    # ── Regex matching ────────────────────────────────────────────────────────
    if "re" in modifiers:
        if event_val is None:
            return False
        try:
            return bool(re.search(str(condition), event_val, re.IGNORECASE))
        except re.error:
            return False

    # ── All modifier - all values must match ──────────────────────────────────
    if "all" in modifiers:
        values = condition if isinstance(condition, list) else [condition]
        return all(
            _apply_text_modifiers(event_val, str(v), modifiers)
            for v in values
        )

    # ── List condition - any value matches (OR logic) ─────────────────────────
    if isinstance(condition, list):
        return any(
            _apply_text_modifiers(event_val, str(v), modifiers)
            for v in condition
        )

    # ── Single value ──────────────────────────────────────────────────────────
    return _apply_text_modifiers(event_val, str(condition), modifiers)


def _apply_text_modifiers(
    event_val: Optional[str],
    rule_val:  str,
    modifiers: List[str],
) -> bool:
    """Apply text modifiers (contains, startswith, endswith) to a comparison."""
    if event_val is None:
        return False

    ev_lower  = event_val.lower()
    rv_lower  = rule_val.lower()

    if "contains" in modifiers:
        return rv_lower in ev_lower
    if "startswith" in modifiers:
        return ev_lower.startswith(rv_lower)
    if "endswith" in modifiers:
        return ev_lower.endswith(rv_lower)

    # Default: wildcard or exact
    return match_value(event_val, rule_val)


# ── Detection Block Evaluator ─────────────────────────────────────────────────

def evaluate_detection_block(
    event: Dict,
    block: Dict,
) -> bool:
    """
    Evaluate a single Sigma detection block (named selection/filter).
    All field conditions within a block are ANDed together.
    """
    if not isinstance(block, dict):
        return False

    for field_name, condition in block.items():
        if not match_field_condition(event, field_name, condition):
            return False

    return True


def evaluate_keywords(event: Dict, keywords: Any) -> bool:
    """
    Evaluate Sigma keywords - plain text strings matched
    against the full raw_payload. OR logic between keywords.
    """
    raw = event.get("raw_payload", "") or ""
    raw_lower = raw.lower()

    if isinstance(keywords, list):
        return any(str(kw).lower() in raw_lower for kw in keywords)
    return str(keywords).lower() in raw_lower


# ── Condition Parser ──────────────────────────────────────────────────────────

class ConditionParser:
    """
    Parses and evaluates Sigma condition expressions.

    Sigma conditions reference named detection blocks with boolean logic:
        selection and not filter
        selection1 or selection2
        keywords
        1 of selection*
        all of them
    """

    def __init__(self, detection: Dict):
        self.detection = detection
        # Separate keywords from named selections
        self.keywords  = detection.get("keywords")
        self.selections = {
            k: v for k, v in detection.items()
            if k not in ("condition", "keywords", "timeframe")
        }

    def evaluate(self, event: Dict, condition_str: str) -> bool:
        """Evaluate a condition string against an event."""
        condition_str = condition_str.strip()

        # Handle "all of them"
        if condition_str == "all of them":
            return all(
                evaluate_detection_block(event, block)
                for block in self.selections.values()
                if isinstance(block, dict)
            )

        # Handle "1 of selection*" or "N of pattern*"
        of_match = re.match(r'^(\d+|all)\s+of\s+(\S+)$', condition_str)
        if of_match:
            return self._evaluate_of_condition(
                event,
                of_match.group(1),
                of_match.group(2),
            )

        # Handle "keywords" reference
        if condition_str == "keywords":
            return evaluate_keywords(event, self.keywords)

        # Tokenise and evaluate boolean expression
        return self._evaluate_expr(event, condition_str)

    def _evaluate_of_condition(
        self,
        event:       Dict,
        count_str:   str,
        pattern:     str,
    ) -> bool:
        """Evaluate '1 of selection*' style conditions."""
        # Find matching selection names
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            matching = [
                k for k in self.selections
                if k.startswith(prefix)
            ]
        elif pattern == "them":
            matching = list(self.selections.keys())
        else:
            matching = [pattern] if pattern in self.selections else []

        if not matching:
            return False

        match_count = sum(
            1 for name in matching
            if evaluate_detection_block(event, self.selections.get(name, {}))
        )

        if count_str == "all":
            return match_count == len(matching)
        try:
            required = int(count_str)
            return match_count >= required
        except ValueError:
            return False

    def _evaluate_expr(self, event: Dict, expr: str) -> bool:
        """
        Evaluate a boolean expression with AND, OR, NOT operators
        and parentheses. Handles nested expressions recursively.
        """
        expr = expr.strip()

        # Handle parentheses - find innermost first
        paren_match = re.search(r'\(([^()]+)\)', expr)
        if paren_match:
            inner_result = self._evaluate_expr(event, paren_match.group(1))
            # Replace the parenthesised expression with its boolean result
            replacement = "TRUE" if inner_result else "FALSE"
            new_expr    = expr[:paren_match.start()] + replacement + expr[paren_match.end():]
            return self._evaluate_expr(event, new_expr)

        # Handle OR - lowest precedence
        # Split on OR but not inside words (avoid "SORT" etc.)
        or_parts = re.split(r'\bor\b', expr, flags=re.IGNORECASE)
        if len(or_parts) > 1:
            return any(self._evaluate_expr(event, part) for part in or_parts)

        # Handle AND
        and_parts = re.split(r'\band\b', expr, flags=re.IGNORECASE)
        if len(and_parts) > 1:
            return all(self._evaluate_expr(event, part) for part in and_parts)

        # Handle NOT
        not_match = re.match(r'\bnot\s+(.+)', expr, re.IGNORECASE)
        if not_match:
            return not self._evaluate_expr(event, not_match.group(1))

        # Terminal - selection name or boolean literal
        token = expr.strip()
        if token.upper() == "TRUE":
            return True
        if token.upper() == "FALSE":
            return False
        if token == "keywords":
            return evaluate_keywords(event, self.keywords)

        # Look up named selection
        if token in self.selections:
            block = self.selections[token]
            if isinstance(block, dict):
                return evaluate_detection_block(event, block)
            if isinstance(block, list):
                # List of blocks - OR between them
                return any(
                    evaluate_detection_block(event, b)
                    for b in block
                    if isinstance(b, dict)
                )
        return False


# ── Compiled Sigma Rule ───────────────────────────────────────────────────────

class CompiledSigmaRule:
    """
    A parsed and compiled Sigma rule ready for evaluation.
    Created once at load time and reused for every event.
    """

    def __init__(self, raw: Dict, file_path: str):
        self.rule_id     = raw.get("id", str(uuid.uuid4()))
        self.title       = raw.get("title", "Unnamed Rule")
        self.description = raw.get("description", "")
        self.status      = raw.get("status", "experimental")
        self.level       = raw.get("level", "medium")
        self.tags        = raw.get("tags", [])
        self.author      = raw.get("author", "")
        self.file_path   = file_path

        # Severity from level
        level_lower       = self.level.lower()
        self.severity, self.severity_score = SIGMA_LEVEL_MAP.get(
            level_lower, ("MEDIUM", 5)
        )

        # MITRE from tags
        self.mitre_technique = ""
        self.mitre_tactic    = ""
        for tag in self.tags:
            tag_str = str(tag)
            if tag_str.startswith("attack.t") or tag_str.startswith("attack.T"):
                tech = tag_str.split(".")[-1].upper()
                if re.match(r'^T\d{4}', tech):
                    self.mitre_technique = tech
            elif tag_str.startswith("attack."):
                self.mitre_tactic = tag_str[7:].replace("_", "-")

        # Detection
        detection = raw.get("detection", {})
        self.condition_str = detection.get("condition", "selection")
        self.condition_parser = ConditionParser(detection)

        # Log source filtering
        logsource = raw.get("logsource", {})
        self.logsource_product  = logsource.get("product", "").lower()
        self.logsource_category = logsource.get("category", "").lower()
        self.logsource_service  = logsource.get("service", "").lower()

        # Match counter
        self.match_count = 0
        self.last_matched: Optional[datetime] = None

    def matches_logsource(self, event: Dict) -> bool:
        """Check if this rule applies to the given event's log source."""
        platform = event.get("platform", "").lower()
        ev_type  = event.get("event", {}).get("type", "").lower()

        # Product filter
        if self.logsource_product:
            product = self.logsource_product
            if product == "windows" and platform != "windows":
                return False
            if product == "linux" and platform != "linux":
                return False

        # Category / service filter
        if self.logsource_category:
            cat = self.logsource_category
            if cat in ("process_creation", "process_access") and ev_type != "process":
                return False
            if cat in ("network_connection", "network_traffic") and ev_type != "network":
                return False

        if self.logsource_service:
            svc = self.logsource_service
            if svc == "security" and platform != "windows":
                return False
            if svc == "system" and platform != "windows":
                return False
            if svc in ("syslog", "auth") and platform not in ("linux", "network"):
                return False

        return True

    def evaluate(self, event: Dict) -> bool:
        """
        Evaluate this rule against a single event.
        Returns True if the rule fires.
        """
        # Log source pre-filter - fast rejection before condition evaluation
        if not self.matches_logsource(event):
            return False

        # Evaluate condition
        try:
            result = self.condition_parser.evaluate(event, self.condition_str)
        except Exception as ex:
            log.debug(f"[Sigma] Rule {self.rule_id} evaluation error: {ex}")
            return False

        if result:
            self.match_count += 1
            self.last_matched = datetime.now(timezone.utc)

        return result

    def to_alert(self, event: Dict) -> Dict:
        """Build an alert dict from a Sigma rule match."""
        actor  = (
            event.get("entity", {}).get("actor") or
            event.get("actor") or "unknown"
        )
        source = event.get("source", "unknown")

        return {
            "alert_id":      str(uuid.uuid4()),
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "alert_type":    f"sigma:{self.rule_id}",
            "severity":      self.severity,
            "severity_score": self.severity_score,
            "title":         self.title,
            "description":   self.description or f"Sigma rule matched: {self.title}",
            "actor":         actor,
            "source_host":   source,
            "event_ids":     [event.get("event_id", "")],
            "sigma_rule_id": self.rule_id,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic":    self.mitre_tactic,
            "metadata": {
                "sigma_rule_id":    self.rule_id,
                "sigma_title":      self.title,
                "sigma_status":     self.status,
                "sigma_level":      self.level,
                "sigma_tags":       self.tags,
                "sigma_match_count": self.match_count,
            },
        }

    def to_dict(self) -> Dict:
        return {
            "rule_id":     self.rule_id,
            "title":       self.title,
            "description": self.description,
            "status":      self.status,
            "level":       self.level,
            "tags":        self.tags,
            "file_path":   self.file_path,
            "is_active":   True,
            "match_count": self.match_count,
            "last_matched": self.last_matched.isoformat() if self.last_matched else None,
        }


# ── Built-In Rules ────────────────────────────────────────────────────────────
# Hardcoded rules that work without any YAML files on disk.
# These are always loaded regardless of the rules directory.

BUILTIN_RULES_YAML = """
- id: logclaw-builtin-001
  title: Windows Security Audit Log Cleared
  description: The Windows Security Event Log was cleared. This is a common anti-forensic technique used after a compromise.
  status: stable
  level: critical
  tags:
    - attack.defense_evasion
    - attack.T1070.001
  logsource:
    product: windows
    service: security
  detection:
    selection:
      EventID: 1102
    condition: selection

- id: logclaw-builtin-002
  title: New Service Installed on Windows Host
  description: A new Windows service was installed. Services are a common persistence mechanism.
  status: stable
  level: high
  tags:
    - attack.persistence
    - attack.T1543.003
  logsource:
    product: windows
    service: system
  detection:
    selection:
      EventID: 7045
    condition: selection

- id: logclaw-builtin-003
  title: User Account Created
  description: A new local or domain user account was created.
  status: stable
  level: medium
  tags:
    - attack.persistence
    - attack.T1136
  logsource:
    product: windows
    service: security
  detection:
    selection:
      EventID: 4720
    condition: selection

- id: logclaw-builtin-004
  title: User Added to Security-Enabled Group
  description: A user account was added to a security group. Admin group additions are high risk.
  status: stable
  level: high
  tags:
    - attack.persistence
    - attack.T1098
  logsource:
    product: windows
    service: security
  detection:
    selection:
      EventID:
        - 4728
        - 4732
        - 4756
    condition: selection

- id: logclaw-builtin-005
  title: Scheduled Task Created
  description: A scheduled task was created. Common persistence and execution mechanism.
  status: stable
  level: medium
  tags:
    - attack.persistence
    - attack.T1053.005
  logsource:
    product: windows
    service: security
  detection:
    selection:
      EventID: 4698
    condition: selection

- id: logclaw-builtin-006
  title: SSH Authentication Failure
  description: An SSH authentication failure was detected on a Linux host.
  status: stable
  level: low
  tags:
    - attack.credential_access
    - attack.T1110
  logsource:
    product: linux
    service: auth
  detection:
    keywords:
      - failed password
      - authentication failure
      - invalid user
    condition: keywords

- id: logclaw-builtin-007
  title: Sudo Command Executed
  description: A user executed a command with elevated privileges via sudo.
  status: stable
  level: medium
  tags:
    - attack.privilege_escalation
    - attack.T1548.003
  logsource:
    product: linux
  detection:
    keywords:
      - sudo:
      - sudo
    condition: keywords

- id: logclaw-builtin-008
  title: Account Locked Out
  description: A Windows user account was locked out - may indicate brute force activity.
  status: stable
  level: medium
  tags:
    - attack.credential_access
    - attack.T1110
  logsource:
    product: windows
    service: security
  detection:
    selection:
      EventID: 4740
    condition: selection

- id: logclaw-builtin-009
  title: Windows Service Installed via Registry
  description: A service was installed via direct registry modification - stealthier than normal service creation.
  status: stable
  level: high
  tags:
    - attack.persistence
    - attack.T1543.003
  logsource:
    product: windows
    service: security
  detection:
    selection:
      EventID: 4697
    condition: selection

- id: logclaw-builtin-010
  title: Network Share Accessed
  description: A network share was accessed. Bulk share access may indicate data collection.
  status: stable
  level: low
  tags:
    - attack.collection
    - attack.T1039
  logsource:
    product: windows
    service: security
  detection:
    selection:
      EventID:
        - 5140
        - 5145
    condition: selection
"""


# ── Sigma Engine ──────────────────────────────────────────────────────────────

class SigmaEngine:
    """
    Loads, manages, and evaluates Sigma detection rules.

    Rule loading order:
    1. Built-in hardcoded rules (always loaded)
    2. Rules from rules/builtin/ directory
    3. Rules from rules/community/ directory

    Rules are reloaded automatically on a configurable interval.
    """

    def __init__(self, rules_dir: str):
        self.rules_dir   = Path(rules_dir)
        self._rules:     List[CompiledSigmaRule] = []
        self._rule_index: Dict[str, CompiledSigmaRule] = {}
        self._lock       = asyncio.Lock()
        self._load_errors: List[str] = []

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    async def load_rules(self):
        """Load all Sigma rules from built-ins and disk."""
        rules    = []
        errors   = []

        # Load built-in rules
        builtin_rules = self._load_builtin_rules()
        rules.extend(builtin_rules)
        log.info(f"[Sigma] Loaded {len(builtin_rules)} built-in rules")

        # Load from disk
        for subdir in ["builtin", "community"]:
            rule_dir = self.rules_dir / subdir
            if not rule_dir.exists():
                continue
            disk_rules, disk_errors = self._load_from_directory(rule_dir)
            rules.extend(disk_rules)
            errors.extend(disk_errors)
            if disk_rules:
                log.info(f"[Sigma] Loaded {len(disk_rules)} rules from {subdir}/")

        # Build index
        index = {r.rule_id: r for r in rules}

        async with self._lock:
            self._rules       = rules
            self._rule_index  = index
            self._load_errors = errors

        log.info(f"[Sigma] Total: {len(rules)} rules active")
        if errors:
            log.warning(f"[Sigma] {len(errors)} rule(s) failed to load")

    def _load_builtin_rules(self) -> List[CompiledSigmaRule]:
        """Load hardcoded built-in rules from the YAML string."""
        compiled = []
        try:
            raw_list = yaml.safe_load(BUILTIN_RULES_YAML)
            for raw in raw_list:
                try:
                    rule = CompiledSigmaRule(raw, file_path="builtin")
                    compiled.append(rule)
                except Exception as ex:
                    log.error(f"[Sigma] Built-in rule compile error: {ex}")
        except yaml.YAMLError as ex:
            log.error(f"[Sigma] Built-in YAML parse error: {ex}")
        return compiled

    def _load_from_directory(
        self,
        directory: Path,
    ) -> Tuple[List[CompiledSigmaRule], List[str]]:
        """Load all .yml and .yaml files from a directory recursively."""
        compiled = []
        errors   = []

        for path in sorted(directory.rglob("*.y*ml")):
            if not path.is_file():
                continue
            try:
                content = path.read_text(encoding="utf-8")
                raw     = yaml.safe_load(content)

                if not isinstance(raw, dict):
                    errors.append(f"{path.name}: not a valid Sigma rule (expected dict)")
                    continue

                # Validate minimum required fields
                if "title" not in raw or "detection" not in raw:
                    errors.append(f"{path.name}: missing required fields (title, detection)")
                    continue

                rule = CompiledSigmaRule(raw, file_path=str(path))
                compiled.append(rule)

            except yaml.YAMLError as ex:
                errors.append(f"{path.name}: YAML parse error: {ex}")
            except Exception as ex:
                errors.append(f"{path.name}: {ex}")

        return compiled, errors

    async def evaluate(self, event: Dict[str, Any]) -> List[Dict]:
        """
        Evaluate all active rules against a single event.
        Returns list of alert dicts for every rule that fired.
        """
        async with self._lock:
            rules = list(self._rules)

        alerts = []
        for rule in rules:
            try:
                if rule.evaluate(event):
                    alert = rule.to_alert(event)
                    alerts.append(alert)
            except Exception as ex:
                log.debug(f"[Sigma] Rule {rule.rule_id} error: {ex}")

        return alerts

    async def import_rule(self, yaml_content: str) -> Tuple[bool, str]:
        """
        Import a new Sigma rule from a YAML string at runtime.
        Validates the rule before adding it to the active set.
        Returns (success, message).
        """
        try:
            raw = yaml.safe_load(yaml_content)
            if not isinstance(raw, dict):
                return False, "Invalid YAML - expected a Sigma rule dict"
            if "title" not in raw or "detection" not in raw:
                return False, "Missing required fields: title and detection"

            rule = CompiledSigmaRule(raw, file_path="imported")

            async with self._lock:
                # Remove existing rule with same ID if present
                self._rules = [
                    r for r in self._rules
                    if r.rule_id != rule.rule_id
                ]
                self._rules.append(rule)
                self._rule_index[rule.rule_id] = rule

            log.info(f"[Sigma] Rule imported: {rule.title} ({rule.rule_id})")
            return True, f"Rule imported successfully: {rule.title}"

        except yaml.YAMLError as ex:
            return False, f"YAML parse error: {ex}"
        except Exception as ex:
            return False, f"Import error: {ex}"

    async def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID - removes from active evaluation."""
        async with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.rule_id != rule_id]
            self._rule_index.pop(rule_id, None)
            removed = before - len(self._rules)

        if removed:
            log.info(f"[Sigma] Rule disabled: {rule_id}")
        return bool(removed)

    async def get_rule(self, rule_id: str) -> Optional[Dict]:
        """Get a rule dict by ID."""
        async with self._lock:
            rule = self._rule_index.get(rule_id)
            return rule.to_dict() if rule else None

    async def get_all_rules(self) -> List[Dict]:
        """Get all active rules as dicts."""
        async with self._lock:
            return [r.to_dict() for r in self._rules]

    async def get_stats(self) -> Dict[str, Any]:
        """Return Sigma engine statistics."""
        async with self._lock:
            total      = len(self._rules)
            by_level   = {}
            top_matched = []
            for r in self._rules:
                by_level[r.level] = by_level.get(r.level, 0) + 1
                if r.match_count > 0:
                    top_matched.append({
                        "rule_id":     r.rule_id,
                        "title":       r.title,
                        "match_count": r.match_count,
                        "last_matched": r.last_matched.isoformat() if r.last_matched else None,
                    })

        top_matched.sort(key=lambda x: x["match_count"], reverse=True)

        return {
            "total_rules":   total,
            "by_level":      by_level,
            "load_errors":   len(self._load_errors),
            "top_matched":   top_matched[:10],
        }

    async def test_rule(
        self,
        yaml_content: str,
        test_events:  List[Dict],
    ) -> Dict[str, Any]:
        """
        Test a Sigma rule against a list of events without adding it
        to the active rule set. Used by the API for rule testing.
        Returns match results per event.
        """
        try:
            raw  = yaml.safe_load(yaml_content)
            rule = CompiledSigmaRule(raw, file_path="test")
        except Exception as ex:
            return {"error": str(ex), "matches": []}

        results = []
        for i, event in enumerate(test_events):
            matched = rule.evaluate(event)
            results.append({
                "event_index": i,
                "matched":     matched,
                "event_id":    event.get("event_id"),
                "timestamp":   event.get("timestamp"),
            })

        match_count = sum(1 for r in results if r["matched"])
        return {
            "rule_id":    rule.rule_id,
            "rule_title": rule.title,
            "tested":     len(test_events),
            "matched":    match_count,
            "results":    results,
        }