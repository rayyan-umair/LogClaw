/*
LogClaw Harvester — UDP Syslog Listener
syslog_udp.go — Network device log ingestion via UDP/TCP syslog

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Listens for incoming syslog messages on UDP port 514 (and
          optionally TCP). Accepts logs from any syslog-capable device
          — firewalls, switches, routers, Linux hosts, IoT devices.
          Detects device type from the sending IP and message format,
          normalises into the universal LogClaw schema, and publishes
          to the ZeroMQ pipe. Handles RFC3164 and RFC5424 formats.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
  Ingestion only. No analysis. No storage. No correlation.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
*/

package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Syslog Constants ──────────────────────────────────────────────────────────

const (
	maxUDPPacketSize = 65536 // maximum UDP datagram size
	maxTCPLineSize   = 65536 // maximum TCP syslog line size
	readTimeout      = 30 * time.Second
)

// ── RFC3164 / RFC5424 Parser ──────────────────────────────────────────────────
// Syslog messages arrive in two main formats.
//
// RFC3164 (BSD syslog — most network devices):
//   <priority>Jan 15 02:33:47 hostname process: message
//
// RFC5424 (modern syslog):
//   <priority>1 2024-01-15T02:33:47.000Z hostname appname procid msgid - message

type SyslogMessage struct {
	Facility  int
	Severity  int
	Timestamp time.Time
	Hostname  string
	AppName   string
	ProcID    string
	Message   string
	Raw       string
	Format    string // "rfc3164" | "rfc5424" | "raw"
}

// ParseSyslogMessage parses a raw syslog datagram into a SyslogMessage.
// Never returns nil — falls back to a raw message on parse failure.
func ParseSyslogMessage(data string) *SyslogMessage {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil
	}

	msg := &SyslogMessage{Raw: data}

	// Extract priority value from <PRI> prefix
	if strings.HasPrefix(data, "<") {
		endBracket := strings.Index(data, ">")
		if endBracket > 1 && endBracket < 6 {
			priStr := data[1:endBracket]
			if pri, err := strconv.Atoi(priStr); err == nil {
				msg.Facility = pri / 8
				msg.Severity = pri % 8
				data = data[endBracket+1:]
			}
		}
	}

	// Detect RFC5424 by version digit after priority
	if len(data) > 0 && data[0] == '1' && len(data) > 1 && data[1] == ' ' {
		if parsed := parseRFC5424(data[2:], msg); parsed {
			msg.Format = "rfc5424"
			return msg
		}
	}

	// Try RFC3164
	if parsed := parseRFC3164(data, msg); parsed {
		msg.Format = "rfc3164"
		return msg
	}

	// Raw fallback — treat entire remaining string as the message
	msg.Format = "raw"
	msg.Timestamp = time.Now().UTC()
	msg.Message = data
	if msg.Hostname == "" {
		msg.Hostname = "unknown"
	}
	return msg
}

// parseRFC3164 parses BSD syslog format:
//
//	Jan 15 02:33:47 hostname process[pid]: message
func parseRFC3164(data string, msg *SyslogMessage) bool {
	// Timestamp: first 15 or 16 characters
	// "Jan  2 15:04:05" (single digit day has extra space)
	// "Jan 02 15:04:05" (zero-padded day)
	tsFormats := []string{
		"Jan  2 15:04:05",
		"Jan 02 15:04:05",
	}

	var ts time.Time
	var rest string
	parsed := false

	for _, f := range tsFormats {
		if len(data) < len(f) {
			continue
		}
		candidate := data[:len(f)]
		// RFC3164 has no year — use current year
		yearStr := fmt.Sprintf("%d ", time.Now().Year())
		t, err := time.Parse("2006 "+f, yearStr+candidate)
		if err == nil {
			ts = t.UTC()
			rest = strings.TrimSpace(data[len(f):])
			parsed = true
			break
		}
	}

	if !parsed {
		return false
	}

	msg.Timestamp = ts

	// Next field: hostname
	fields := strings.SplitN(rest, " ", 3)
	if len(fields) < 2 {
		msg.Hostname = rest
		msg.Message = rest
		return true
	}

	msg.Hostname = fields[0]
	rest = strings.TrimSpace(strings.Join(fields[1:], " "))

	// Next field: process[pid]: message
	colonIdx := strings.Index(rest, ":")
	if colonIdx == -1 {
		msg.AppName = "unknown"
		msg.Message = rest
		return true
	}

	procPart := rest[:colonIdx]
	if bracketIdx := strings.Index(procPart, "["); bracketIdx != -1 {
		msg.AppName = procPart[:bracketIdx]
		msg.ProcID = strings.Trim(procPart[bracketIdx:], "[]")
	} else {
		msg.AppName = procPart
	}

	msg.Message = strings.TrimSpace(rest[colonIdx+1:])
	return true
}

// parseRFC5424 parses modern syslog format (after version digit removed):
//
//	2024-01-15T02:33:47.000Z hostname appname procid msgid [structured-data] message
func parseRFC5424(data string, msg *SyslogMessage) bool {
	fields := strings.SplitN(data, " ", 7)
	if len(fields) < 6 {
		return false
	}

	// Timestamp
	ts, err := time.Parse(time.RFC3339Nano, fields[0])
	if err != nil {
		ts, err = time.Parse(time.RFC3339, fields[0])
		if err != nil {
			return false
		}
	}
	msg.Timestamp = ts.UTC()
	msg.Hostname = nilDash(fields[1])
	msg.AppName = nilDash(fields[2])
	msg.ProcID = nilDash(fields[3])
	// fields[4] = msgid, fields[5] = structured data — skip both
	if len(fields) == 7 {
		msg.Message = strings.TrimSpace(fields[6])
	}
	return true
}

// nilDash replaces RFC5424 nil value "-" with empty string.
func nilDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// ── Device Type Detection ─────────────────────────────────────────────────────
// Detects the type of device that sent a syslog message.
// Used by the normaliser to apply device-specific parsing.

func detectDeviceType(sourceIP, hostname, appName, message string) string {
	msgLower := strings.ToLower(message)
	appLower := strings.ToLower(appName)
	hostLower := strings.ToLower(hostname)

	// pfSense detection
	if strings.Contains(hostLower, "pfsense") ||
		strings.Contains(appLower, "filterlog") ||
		strings.Contains(msgLower, "filterlog") ||
		strings.Contains(msgLower, "pf:") {
		return "pfsense"
	}

	// iptables / Linux firewall
	if strings.Contains(msgLower, "iptables") ||
		strings.Contains(msgLower, "dst=") ||
		strings.Contains(msgLower, "src=") && strings.Contains(msgLower, "dpt=") {
		return "iptables"
	}

	// Cisco IOS / NX-OS
	if strings.Contains(msgLower, "%cisco") ||
		strings.Contains(msgLower, "%sec-") ||
		strings.Contains(msgLower, "%aaa-") ||
		strings.Contains(appLower, "cisco") {
		return "cisco"
	}

	// Juniper
	if strings.Contains(appLower, "junos") ||
		strings.Contains(msgLower, "junos") {
		return "juniper"
	}

	// Ubiquiti / UniFi
	if strings.Contains(hostLower, "ubnt") ||
		strings.Contains(appLower, "ubnt") ||
		strings.Contains(msgLower, "ubnt") {
		return "ubiquiti"
	}

	// Windows Event Forwarding via syslog
	if strings.Contains(msgLower, "eventid=") ||
		strings.Contains(msgLower, "security id:") {
		return "windows-forwarded"
	}

	return "generic"
}

// ── Cisco Log Parser ──────────────────────────────────────────────────────────
// Cisco syslog messages follow a specific format:
//   %FACILITY-SEVERITY-MNEMONIC: message

func parseCiscoMessage(msg string) (description, eventType string, severity int) {
	eventType = "network"
	severity = 5

	if !strings.Contains(msg, "%") {
		return msg, eventType, severity
	}

	// Extract mnemonic
	parts := strings.SplitN(msg, ":", 2)
	if len(parts) < 2 {
		return msg, eventType, severity
	}

	mnemonic := strings.TrimPrefix(strings.TrimSpace(parts[0]), "%")
	description = strings.TrimSpace(parts[1])

	// Map known mnemonics to severity and type
	mnemonicUpper := strings.ToUpper(mnemonic)
	switch {
	case strings.Contains(mnemonicUpper, "SEC-LOGIN") ||
		strings.Contains(mnemonicUpper, "AAA"):
		eventType = "auth"
		severity = 7
	case strings.Contains(mnemonicUpper, "OSPF") ||
		strings.Contains(mnemonicUpper, "BGP"):
		eventType = "network"
		severity = 4
	case strings.Contains(mnemonicUpper, "ACL") ||
		strings.Contains(mnemonicUpper, "DENY"):
		eventType = "network"
		severity = 6
	case strings.Contains(mnemonicUpper, "CONFIG"):
		eventType = "config"
		severity = 7
	case strings.Contains(mnemonicUpper, "LINK") ||
		strings.Contains(mnemonicUpper, "LINEPROTO"):
		eventType = "network"
		severity = 5
	}

	description = fmt.Sprintf("[%s] %s", mnemonic, description)
	return description, eventType, severity
}

// ── Message to NetworkRawEvent ────────────────────────────────────────────────

func syslogToNetworkRaw(msg *SyslogMessage, sourceIP, deviceType string) *NetworkRawEvent {
	hostname := msg.Hostname
	if hostname == "" || hostname == "unknown" {
		hostname = sourceIP
	}

	raw := &NetworkRawEvent{
		Timestamp:  msg.Timestamp,
		Source:     hostname,
		Facility:   msg.Facility,
		Severity:   msg.Severity,
		Message:    msg.Message,
		DeviceType: deviceType,
	}

	// Cisco gets special message treatment
	if deviceType == "cisco" {
		desc, _, sev := parseCiscoMessage(msg.Message)
		raw.Message = desc
		raw.Severity = sev
	}

	return raw
}

// ── UDP Listener ──────────────────────────────────────────────────────────────

type UDPListener struct {
	port int
	pub  *Publisher
}

func (l *UDPListener) listen(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", l.port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("udp listen %s: %w", addr, err)
	}
	defer conn.Close()

	log.Printf("[Syslog/UDP] listening on %s", addr)

	buf := make([]byte, maxUDPPacketSize)
	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	for {
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				close(done)
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Normal timeout — just loop again
			}
			log.Printf("[Syslog/UDP] read error: %v", err)
			continue
		}

		data := string(buf[:n])
		sourceIP := extractIP(remoteAddr.String())

		go l.processMessage(data, sourceIP)
	}
}

func (l *UDPListener) processMessage(data, sourceIP string) {
	msg := ParseSyslogMessage(data)
	if msg == nil {
		return
	}

	deviceType := detectDeviceType(sourceIP, msg.Hostname, msg.AppName, msg.Message)
	raw := syslogToNetworkRaw(msg, sourceIP, deviceType)

	// Windows-forwarded events need special handling
	if deviceType == "windows-forwarded" {
		l.handleWindowsForwarded(msg, sourceIP)
		return
	}

	normalised := NormaliseNetworkEvent(raw)
	if err := l.pub.Publish(normalised); err != nil {
		log.Printf("[Syslog/UDP] publish error from %s: %v", sourceIP, err)
	}
}

// handleWindowsForwarded handles Windows Event Log messages forwarded
// via syslog. Parses EventID from the message and normalises as a
// Windows event rather than a network event.
func (l *UDPListener) handleWindowsForwarded(msg *SyslogMessage, sourceIP string) {
	eventID := extractWindowsEventID(msg.Message)
	raw := &WindowsRawEvent{
		EventID:     eventID,
		TimeCreated: msg.Timestamp,
		Computer:    msg.Hostname,
		RawXML:      msg.Message,
	}
	if raw.Computer == "" {
		raw.Computer = sourceIP
	}
	normalised := NormaliseWindowsEvent(raw)
	if err := l.pub.Publish(normalised); err != nil {
		log.Printf("[Syslog/UDP] windows-forwarded publish error: %v", err)
	}
}

func extractWindowsEventID(message string) int {
	msgLower := strings.ToLower(message)
	// Look for "eventid=4625" or "event id: 4625" patterns
	for _, prefix := range []string{"eventid=", "event id:", "event id ="} {
		idx := strings.Index(msgLower, prefix)
		if idx != -1 {
			rest := message[idx+len(prefix):]
			rest = strings.TrimSpace(rest)
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				if id, err := strconv.Atoi(strings.Trim(fields[0], ",:;")); err == nil {
					return id
				}
			}
		}
	}
	return 0
}

// ── TCP Listener ──────────────────────────────────────────────────────────────
// RFC5424 recommends TCP for reliable delivery.
// Some devices (pfSense, Cisco) can be configured to use TCP syslog.

type TCPListener struct {
	port int
	pub  *Publisher
}

func (l *TCPListener) listen(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", l.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp listen %s: %w", addr, err)
	}
	defer listener.Close()

	log.Printf("[Syslog/TCP] listening on %s", addr)

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()

	var connWg sync.WaitGroup
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				close(done)
				connWg.Wait()
				return nil
			}
			log.Printf("[Syslog/TCP] accept error: %v", err)
			continue
		}

		connWg.Add(1)
		go func() {
			defer connWg.Done()
			l.handleConnection(ctx, conn)
		}()
	}
}

func (l *TCPListener) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	sourceIP := extractIP(conn.RemoteAddr().String())
	log.Printf("[Syslog/TCP] connection from %s", sourceIP)

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, maxTCPLineSize), maxTCPLineSize)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		msg := ParseSyslogMessage(line)
		if msg == nil {
			continue
		}

		deviceType := detectDeviceType(sourceIP, msg.Hostname, msg.AppName, msg.Message)
		raw := syslogToNetworkRaw(msg, sourceIP, deviceType)
		normalised := NormaliseNetworkEvent(raw)

		if err := l.pub.Publish(normalised); err != nil {
			log.Printf("[Syslog/TCP] publish error from %s: %v", sourceIP, err)
		}
	}

	if err := scanner.Err(); err != nil {
		if !isClosedError(err) && !isContextError(err) {
			log.Printf("[Syslog/TCP] %s scanner error: %v", sourceIP, err)
		}
	}
}

// ── Syslog Collector ──────────────────────────────────────────────────────────

type SyslogCollector struct {
	cfg *Config
}

func NewSyslogCollector(cfg *Config) *SyslogCollector {
	return &SyslogCollector{cfg: cfg}
}

func (c *SyslogCollector) Name() string {
	return "Syslog"
}

func (c *SyslogCollector) Start(ctx context.Context, pub *Publisher) error {
	udpListener := &UDPListener{port: c.cfg.SyslogPort, pub: pub}
	tcpListener := &TCPListener{port: c.cfg.SyslogPort, pub: pub}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := udpListener.listen(ctx); err != nil {
			errCh <- fmt.Errorf("UDP: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := tcpListener.listen(ctx); err != nil {
			// TCP failure is not fatal — UDP alone is sufficient
			log.Printf("[Syslog] TCP listener failed (non-fatal): %v", err)
		}
	}()

	wg.Wait()
	close(errCh)

	// Only return error if UDP failed — TCP is optional
	for err := range errCh {
		if strings.Contains(err.Error(), "UDP") {
			return err
		}
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
