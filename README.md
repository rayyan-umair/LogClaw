# LogClaw

**Local-First Cybersecurity Intelligence Engine**

The first telemetry system that turns raw logs into **investigative narratives instead of noise**.

Built by Rayyan Umair - *Technology evolves quickly. Responsibility does not.*

---

# What it does

LogClaw collects logs from Windows, Linux, and network devices and transforms them into:

* structured security events
* tracked behavioral entities
* correlated attack chains
* explainable 5W+H investigations

Every event is compressed into a **human-readable security narrative**:

### Instead of raw logs:

```
4625 Failed login from 10.0.0.5
```

### You get:

* WHO did it
* WHAT happened
* WHERE it happened
* WHEN it happened
* WHY it matters
* HOW to respond

No SIEM complexity. No log noise. No manual correlation.

---

# System Overview

LogClaw is split into two core components:

## Brain (Python)

The intelligence layer.

Handles:

* log ingestion (ZeroMQ subscriber)
* entity tracking (users, hosts, IPs)
* correlation engine (attack chain detection)
* Sigma rule evaluation
* 5W+H narrative generation
* API + WebSocket backend

Storage:

* DuckDB (primary)
* Parquet (historical compression)
* Ring buffer (real-time events)

---

## Harvester (Go)

The ingestion layer.

Handles:

* Windows Event Logs (WinRM / EVTX fallback)
* Linux logs (SSH tail / syslog)
* Network syslog streams
* normalization into universal schema
* ZeroMQ publishing to Brain

No analysis. No storage. No intelligence.

---

# Core Concept

LogClaw does NOT treat logs as events.

It treats them as:

> **behavioral evidence of systems and actors over time**

---

# Universal Event Schema

Every log becomes:

```json
{
  "event_id": "uuid",
  "timestamp": "UTC ISO8601",
  "platform": "windows | linux | network",
  "source": "hostname",

  "entity": {
    "actor": "user / ip / service",
    "target": "host / endpoint"
  },

  "event": {
    "type": "auth | process | network | config",
    "severity": 0-10
  },

  "mitre": {
    "technique_id": "optional"
  },

  "raw_payload": "original log line"
}
```

---

# Quick Start

## 1. Start Brain

```bash
cd brain
python main.py
```

Runs:

* FastAPI server
* ZeroMQ subscriber
* correlation engine
* entity tracking system

---

## 2. Start Harvester

```bash
cd harvester
go run main.go
```

Publishes logs to Brain via ZeroMQ.

---

## 3. Connect Both

Default:

```
tcp://127.0.0.1:5555
```

No cloud required. Fully local.

---

# Features

## Entity Tracking

LogClaw tracks systems as living objects:

* users
* IP addresses
* hosts
* services

Each entity maintains:

* activity timeline
* risk score
* interaction graph

---

## Correlation Engine

Detects:

* brute-force patterns
* privilege escalation chains
* lateral movement
* suspicious login sequences
* firewall → login → execution chains

Outputs:

> attack chain reconstruction

---

## 5W+H Investigation Engine

Every alert is transformed into:

* WHO
* WHAT
* WHERE
* WHEN
* WHY
* HOW

Designed for analysts, not raw logs.

---

## Sigma Rule Support

* YAML-based detection rules
* real-time evaluation
* community rule compatibility

---

## Real-Time Streaming

* ZeroMQ pub/sub pipeline
* sub-second ingestion latency
* ring buffer live state

---

# Harvester Inputs

LogClaw supports:

## Windows

* WinRM log streaming
* EVTX file fallback mode

## Linux

* SSH log tailing
* /var/log/auth.log
* journald/syslog

## Network

* syslog UDP ingestion
* firewall logs (pfSense, iptables)

---

# AI Layer (Optional)

AI is NOT required.

When enabled, it acts as:

> a SOC analyst assistant — not a detector

It can:

* explain alerts
* summarize incidents
* generate reports
* assist investigations

It cannot:

* define detection logic
* replace correlation engine
* fabricate logs

Supported providers:

* Local LLMs (Ollama / llama.cpp)
* OpenAI
* Gemini
* Groq
* Disabled mode (fully offline)

---

# Timeline Integrity

All timestamps are normalized to:

```
UTC (RFC3339Nano)
```

This ensures:

* cross-platform consistency
* correct correlation ordering
* reliable attack reconstruction

---

# Security Model

* fully local-first capable
* no cloud dependency required
* optional external AI only
* raw payloads preserved for forensics
* sensitive ingestion channels isolated

---

# Performance Design

LogClaw is optimized for:

* streaming ingestion
* minimal memory pressure
* batch processing pipelines
* compressed historical storage

---

# Plugin System

Planned extensibility:

### Input plugins

* new log sources

### Detection plugins

* Sigma packs
* custom rules

### AI plugins

* local or cloud models

### Output plugins

* webhook alerts
* SIEM export
* reporting systems

---

# Risk Philosophy

LogClaw does NOT:

* replace SIEMs
* rely on cloud correlation
* require external APIs
* store raw logs indefinitely

LogClaw IS:

> a local investigative intelligence engine that converts telemetry into structured understanding.

---

# Hard Constraints

* Harvester performs ingestion only
* Brain performs all analysis
* ZeroMQ is the transport layer
* No cross-layer business logic
* UTC is mandatory everywhere
* Events must remain schema-compliant

---

# Legal Notice

LogClaw is a defensive cybersecurity tool.

Only use it on systems you own or are authorized to monitor.

Unauthorized monitoring or interception may be illegal in your jurisdiction.