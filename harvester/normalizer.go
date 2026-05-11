/*
LogClaw Harvester — Universal Schema Normaliser
normalizer.go — Enforces the universal LogClaw log schema

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Every collector calls this before publishing. Raw log data
          from any platform — Windows, Linux, network device — gets
          converted into the universal LogClaw schema. Timestamps are
          forced to UTC. Missing fields get safe defaults. Nothing
          leaves the harvester in a raw or inconsistent format.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
  No analysis logic here. Normalise and publish — that is all.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
*/

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ── MITRE ATT&CK Mappings ─────────────────────────────────────────────────────
// Maps known Windows Event IDs and Linux log patterns to MITRE techniques.
// This is the harvester-level mapping — coarse but immediate.
// The Brain refines these further during correlation.

type MITREMapping struct {
	TechniqueID string
	TacticName  string
}

var windowsEventMITRE = map[int]MITREMapping{
	4625: {TechniqueID: "T1110", TacticName: "credential-access"}, // Failed logon
	4624: {TechniqueID: "T1078", TacticName: "defense-evasion"},   // Successful logon
	4720: {TechniqueID: "T1136", TacticName: "persistence"},       // Account created
	4726: {TechniqueID: "T1531", TacticName: "impact"},            // Account deleted
	4728: {TechniqueID: "T1098", TacticName: "persistence"},       // Added to security group
	4732: {TechniqueID: "T1098", TacticName: "persistence"},       // Added to local group
	4776: {TechniqueID: "T1110", TacticName: "credential-access"}, // Credential validation
	4698: {TechniqueID: "T1053", TacticName: "persistence"},       // Scheduled task created
	7045: {TechniqueID: "T1543", TacticName: "persistence"},       // New service installed
	1102: {TechniqueID: "T1070", TacticName: "defense-evasion"},   // Audit log cleared
	4688: {TechniqueID: "T1059", TacticName: "execution"},         // New process created
	4697: {TechniqueID: "T1543", TacticName: "persistence"},       // Service installed
	4740: {TechniqueID: "T1110", TacticName: "credential-access"}, // Account locked out
	4756: {TechniqueID: "T1098", TacticName: "persistence"},       // Member added to group
	4767: {TechniqueID: "T1531", TacticName: "impact"},            // Account unlocked
	4800: {TechniqueID: "T1078", TacticName: "defense-evasion"},   // Workstation locked
	4801: {TechniqueID: "T1078", TacticName: "defense-evasion"},   // Workstation unlocked
	5140: {TechniqueID: "T1039", TacticName: "collection"},        // Network share accessed
	5145: {TechniqueID: "T1039", TacticName: "collection"},        // Network share object checked
}

// ── Windows Event ID Descriptions ────────────────────────────────────────────
// Human-readable descriptions for every monitored Windows Event ID.
// Used by the normaliser to populate the description field.

var windowsEventDescriptions = map[int]string{
	4625: "Failed logon attempt",
	4624: "Successful logon",
	4720: "User account created",
	4726: "User account deleted",
	4728: "User added to global security group",
	4732: "User added to local security group",
	4776: "Credential validation attempt",
	4698: "Scheduled task created",
	7045: "New service installed on system",
	1102: "Security audit log cleared",
	4688: "New process created",
	4697: "Service installed in system",
	4740: "User account locked out",
	4756: "Member added to universal security group",
	4767: "User account unlocked",
	4800: "Workstation locked",
	4801: "Workstation unlocked",
	5140: "Network share object accessed",
	5145: "Network share object access checked",
}

// ── Severity Mapping ──────────────────────────────────────────────────────────
// Maps known Event IDs and event types to a 0–10 severity score.
// 10 = immediate action required. 0 = informational only.

var windowsEventSeverity = map[int]int{
	4625: 6,  // Failed logon — medium, pattern-dependent
	4624: 2,  // Successful logon — low by itself
	4720: 7,  // Account created — high
	4726: 7,  // Account deleted — high
	4728: 8,  // Added to security group — high
	4732: 7,  // Added to local group — high
	4776: 5,  // Credential validation — medium
	4698: 8,  // Scheduled task created — high
	7045: 9,  // New service installed — critical
	1102: 10, // Audit log cleared — critical, always
	4688: 4,  // New process created — low-medium
	4697: 9,  // Service installed — critical
	4740: 7,  // Account locked out — high
	4756: 8,  // Added to universal group — high
	4767: 5,  // Account unlocked — medium
	4800: 2,  // Workstation locked — informational
	4801: 2,  // Workstation unlocked — informational
	5140: 5,  // Share accessed — medium
	5145: 4,  // Share access checked — low-medium
}

// ── Linux Log Patterns ────────────────────────────────────────────────────────
// Keyword patterns used to classify Linux syslog lines into event types
// and assign MITRE mappings at the harvester level.

type LinuxPattern struct {
	Keywords    []string
	EventType   string
	Severity    int
	Description string
	MITRE       MITREMapping
}

var linuxPatterns = []LinuxPattern{
	{
		Keywords:    []string{"failed password", "authentication failure", "invalid user"},
		EventType:   "auth",
		Severity:    6,
		Description: "Failed SSH authentication attempt",
		MITRE:       MITREMapping{TechniqueID: "T1110", TacticName: "credential-access"},
	},
	{
		Keywords:    []string{"accepted password", "accepted publickey", "session opened for user"},
		EventType:   "auth",
		Severity:    2,
		Description: "Successful SSH authentication",
		MITRE:       MITREMapping{TechniqueID: "T1078", TacticName: "defense-evasion"},
	},
	{
		Keywords:    []string{"sudo:", "sudo "},
		EventType:   "process",
		Severity:    5,
		Description: "Sudo command executed",
		MITRE:       MITREMapping{TechniqueID: "T1548", TacticName: "privilege-escalation"},
	},
	{
		Keywords:    []string{"useradd", "adduser", "new user"},
		EventType:   "config",
		Severity:    8,
		Description: "New user account created",
		MITRE:       MITREMapping{TechniqueID: "T1136", TacticName: "persistence"},
	},
	{
		Keywords:    []string{"userdel", "deluser"},
		EventType:   "config",
		Severity:    7,
		Description: "User account deleted",
		MITRE:       MITREMapping{TechniqueID: "T1531", TacticName: "impact"},
	},
	{
		Keywords:    []string{"cron", "crond"},
		EventType:   "process",
		Severity:    4,
		Description: "Cron job executed",
		MITRE:       MITREMapping{TechniqueID: "T1053", TacticName: "persistence"},
	},
	{
		Keywords:    []string{"connection refused", "port scan", "nmap"},
		EventType:   "network",
		Severity:    7,
		Description: "Potential port scan or connection probe detected",
		MITRE:       MITREMapping{TechniqueID: "T1046", TacticName: "discovery"},
	},
	{
		Keywords:    []string{"kernel", "segfault", "oom-killer"},
		EventType:   "system",
		Severity:    6,
		Description: "Kernel or system-level event",
		MITRE:       MITREMapping{},
	},
	{
		Keywords:    []string{"passwd", "chpasswd", "password changed"},
		EventType:   "config",
		Severity:    6,
		Description: "Password change event",
		MITRE:       MITREMapping{TechniqueID: "T1098", TacticName: "persistence"},
	},
}

// ── UUID Generator ────────────────────────────────────────────────────────────

func generateEventID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("evt-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ── UTC Enforcer ──────────────────────────────────────────────────────────────
// This is critical. Windows logs in local time. Linux varies.
// pfSense uses UTC. Everything MUST become UTC before leaving the harvester.
// A broken timeline is the most common cause of missed correlations.

func enforceUTC(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func nowUTC() string {
	return enforceUTC(time.Now())
}

// ── Windows Event Normaliser ──────────────────────────────────────────────────

type WindowsRawEvent struct {
	EventID     int
	TimeCreated time.Time
	Computer    string
	SubjectUser string
	TargetUser  string
	LogonType   string
	IPAddress   string
	ProcessName string
	ServiceName string
	RawXML      string
}

// NormaliseWindowsEvent converts a raw Windows Event into a universal LogEvent.
// Called by winrm.go and evtx_fallthrough.go — same schema regardless of source.
func NormaliseWindowsEvent(raw *WindowsRawEvent) *LogEvent {
	evt := &LogEvent{
		EventID:    generateEventID(),
		Timestamp:  enforceUTC(raw.TimeCreated),
		Platform:   "windows",
		Source:     raw.Computer,
		RawPayload: raw.RawXML,
	}

	// Actor — prefer TargetUser for auth events, SubjectUser otherwise
	actor := raw.SubjectUser
	if raw.TargetUser != "" && raw.TargetUser != "-" {
		actor = raw.TargetUser
	}
	if raw.IPAddress != "" && raw.IPAddress != "-" && raw.IPAddress != "::1" {
		actor = fmt.Sprintf("%s@%s", actor, raw.IPAddress)
	}
	evt.Entity.Actor = sanitise(actor)
	evt.Entity.Target = sanitise(raw.Computer)

	// Process name as target for process events
	if raw.ProcessName != "" {
		evt.Entity.Target = sanitise(raw.ProcessName)
	}

	// Event type classification
	evt.Event.RawEventID = raw.EventID
	evt.Event.Type = classifyWindowsEventType(raw.EventID)
	evt.Event.Severity = windowsEventSeverity[raw.EventID]
	evt.Event.Description = windowsEventDescriptions[raw.EventID]

	// Service events
	if raw.ServiceName != "" {
		evt.Entity.Target = sanitise(raw.ServiceName)
		evt.Event.Description = fmt.Sprintf("%s: %s", evt.Event.Description, raw.ServiceName)
	}

	// Defaults for unmapped events
	if evt.Event.Description == "" {
		evt.Event.Description = fmt.Sprintf("Windows Event ID %d", raw.EventID)
	}
	if evt.Event.Severity == 0 {
		evt.Event.Severity = 2
	}

	// MITRE mapping
	if m, ok := windowsEventMITRE[raw.EventID]; ok {
		evt.MITRE.TechniqueID = m.TechniqueID
		evt.MITRE.TacticName = m.TacticName
	}

	return evt
}

func classifyWindowsEventType(eventID int) string {
	switch {
	case eventID >= 4624 && eventID <= 4634:
		return "auth"
	case eventID >= 4688 && eventID <= 4699:
		return "process"
	case eventID == 7045 || eventID == 4697:
		return "config"
	case eventID == 1102:
		return "config"
	case eventID >= 5140 && eventID <= 5145:
		return "network"
	case eventID >= 4720 && eventID <= 4767:
		return "config"
	default:
		return "system"
	}
}

// ── Linux Syslog Normaliser ───────────────────────────────────────────────────

type LinuxRawEvent struct {
	Timestamp time.Time
	Hostname  string
	Process   string
	PID       string
	Message   string
	LogFile   string // source file: auth.log, syslog, kern.log etc.
}

// NormaliseLinuxEvent converts a raw syslog line into a universal LogEvent.
// Called by ssh_tail.go and syslog_udp.go.
func NormaliseLinuxEvent(raw *LinuxRawEvent) *LogEvent {
	evt := &LogEvent{
		EventID:    generateEventID(),
		Timestamp:  enforceUTC(raw.Timestamp),
		Platform:   "linux",
		Source:     raw.Hostname,
		RawPayload: raw.Message,
	}

	evt.Entity.Actor = sanitise(raw.Process)
	evt.Entity.Target = sanitise(raw.Hostname)

	// Extract actor from common log patterns
	actor, target := extractLinuxActors(raw.Message, raw.Process)
	if actor != "" {
		evt.Entity.Actor = sanitise(actor)
	}
	if target != "" {
		evt.Entity.Target = sanitise(target)
	}

	// Pattern matching for event classification
	matched := false
	msgLower := strings.ToLower(raw.Message)
	for _, pattern := range linuxPatterns {
		for _, kw := range pattern.Keywords {
			if strings.Contains(msgLower, kw) {
				evt.Event.Type = pattern.EventType
				evt.Event.Severity = pattern.Severity
				evt.Event.Description = pattern.Description
				evt.MITRE.TechniqueID = pattern.MITRE.TechniqueID
				evt.MITRE.TacticName = pattern.MITRE.TacticName
				matched = true
				break
			}
		}
		if matched {
			break
		}
	}

	// Default for unmatched patterns
	if !matched {
		evt.Event.Type = "system"
		evt.Event.Severity = 1
		evt.Event.Description = fmt.Sprintf("%s: %s", raw.Process, truncate(raw.Message, 120))
	}

	return evt
}

// extractLinuxActors parses common syslog message formats to find
// the actor (user/IP) and target (hostname/service).
func extractLinuxActors(message, process string) (actor, target string) {
	msgLower := strings.ToLower(message)

	// SSH patterns: "for user X from IP" or "from IP port N"
	if strings.Contains(msgLower, "for user ") {
		if parts := strings.SplitN(message, "for user ", 2); len(parts) == 2 {
			rest := strings.Fields(parts[1])
			if len(rest) > 0 {
				actor = rest[0]
			}
		}
	}
	if strings.Contains(msgLower, " from ") {
		if parts := strings.SplitN(message, " from ", 2); len(parts) == 2 {
			rest := strings.Fields(parts[1])
			if len(rest) > 0 {
				// Could be IP or hostname
				if looksLikeIP(rest[0]) {
					target = rest[0]
				}
			}
		}
	}

	// Sudo pattern: "sudo: username :"
	if strings.HasPrefix(strings.ToLower(process), "sudo") {
		parts := strings.Fields(message)
		if len(parts) > 0 {
			actor = parts[0]
		}
	}

	return actor, target
}

// ── Network / Syslog Device Normaliser ───────────────────────────────────────

type NetworkRawEvent struct {
	Timestamp  time.Time
	Source     string // sending device IP or hostname
	Facility   int
	Severity   int
	Message    string
	DeviceType string // pfsense | iptables | generic
}

// NormaliseNetworkEvent converts a syslog message from a network device
// into a universal LogEvent.
func NormaliseNetworkEvent(raw *NetworkRawEvent) *LogEvent {
	evt := &LogEvent{
		EventID:    generateEventID(),
		Timestamp:  enforceUTC(raw.Timestamp),
		Platform:   "network",
		Source:     raw.Source,
		RawPayload: raw.Message,
	}

	evt.Entity.Actor = raw.Source
	evt.Entity.Target = extractNetworkTarget(raw.Message)
	evt.Event.Type = "network"

	// Map syslog severity (0-7) to LogClaw severity (0-10)
	// Syslog: 0=emergency, 7=debug. We invert and scale.
	evt.Event.Severity = mapSyslogSeverity(raw.Severity)

	// Device-specific parsing
	switch raw.DeviceType {
	case "pfsense":
		evt.Event.Description = parsePfSenseMessage(raw.Message)
		evt.MITRE.TechniqueID = "T1562"
		evt.MITRE.TacticName = "defense-evasion"
	case "iptables":
		evt.Event.Description = parseIPTablesMessage(raw.Message)
		evt.MITRE.TechniqueID = "T1046"
		evt.MITRE.TacticName = "discovery"
	default:
		evt.Event.Description = truncate(raw.Message, 160)
	}

	return evt
}

func mapSyslogSeverity(syslogSev int) int {
	// Syslog severity 0 (emergency) → LogClaw 10
	// Syslog severity 7 (debug)     → LogClaw 1
	mapping := map[int]int{
		0: 10, // emergency
		1: 9,  // alert
		2: 8,  // critical
		3: 7,  // error
		4: 5,  // warning
		5: 3,  // notice
		6: 2,  // informational
		7: 1,  // debug
	}
	if v, ok := mapping[syslogSev]; ok {
		return v
	}
	return 2
}

func parsePfSenseMessage(msg string) string {
	if strings.Contains(msg, "block") {
		return fmt.Sprintf("pfSense firewall block: %s", truncate(msg, 120))
	}
	if strings.Contains(msg, "pass") {
		return fmt.Sprintf("pfSense firewall allow: %s", truncate(msg, 120))
	}
	return fmt.Sprintf("pfSense: %s", truncate(msg, 140))
}

func parseIPTablesMessage(msg string) string {
	if strings.Contains(msg, "DROP") {
		return fmt.Sprintf("iptables DROP: %s", truncate(msg, 120))
	}
	if strings.Contains(msg, "ACCEPT") {
		return fmt.Sprintf("iptables ACCEPT: %s", truncate(msg, 120))
	}
	return fmt.Sprintf("iptables: %s", truncate(msg, 140))
}

func extractNetworkTarget(msg string) string {
	// Look for DST= in iptables logs
	if idx := strings.Index(msg, "DST="); idx != -1 {
		rest := msg[idx+4:]
		if fields := strings.Fields(rest); len(fields) > 0 {
			return fields[0]
		}
	}
	return "unknown"
}

// ── Utility Functions ─────────────────────────────────────────────────────────

func sanitise(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" || s == "N/A" {
		return "unknown"
	}
	// Remove control characters
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	return truncate(b.String(), 128)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func looksLikeIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) == 4 {
		return true
	}
	// IPv6 basic check
	return strings.Contains(s, ":")
}
