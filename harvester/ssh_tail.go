/*
LogClaw Harvester - Linux Log Collector
ssh_tail.go - Remote Linux log ingestion via SSH

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Connects to Linux hosts via SSH, tails security-relevant
          log files in real time, normalises each line into the
          universal LogClaw schema, and publishes to the ZeroMQ pipe.
          Supports key-based and password authentication. Handles
          reconnection automatically if the SSH session drops.
          Monitored files: auth.log, syslog, secure, kern.log,
          audit.log, cron, and journald via journalctl.
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
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ── Default Log Files ─────────────────────────────────────────────────────────
// Tailed on every Linux host unless overridden in config.
// Files that don't exist on a host are silently skipped.

var defaultLinuxLogFiles = []string{
	"/var/log/auth.log",        // Debian / Ubuntu SSH and PAM events
	"/var/log/secure",          // RHEL / CentOS SSH and PAM events
	"/var/log/syslog",          // General system events (Debian/Ubuntu)
	"/var/log/messages",        // General system events (RHEL/CentOS)
	"/var/log/kern.log",        // Kernel events
	"/var/log/audit/audit.log", // Linux audit daemon - highest fidelity
	"/var/log/cron",            // Scheduled task execution
	"/var/log/faillog",         // Failed login tracking
}

// ── Syslog RFC3164 Timestamp Formats ─────────────────────────────────────────
// Linux syslog uses multiple timestamp formats depending on distro and config.
// We try all of them before falling back to now().

var syslogTimestampFormats = []string{
	"Jan  2 15:04:05",                     // RFC3164 - single-digit day with space
	"Jan 02 15:04:05",                     // RFC3164 - zero-padded day
	"2006-01-02T15:04:05.999999999Z07:00", // RFC5424 / ISO8601
	"2006-01-02T15:04:05Z07:00",
	time.RFC3339Nano,
	time.RFC3339,
}

// ── SSH Auth ──────────────────────────────────────────────────────────────────

// buildSSHAuth constructs the SSH authentication methods from config.
// Prefers key-based auth. Falls back to password if no key is provided.
func buildSSHAuth(cfg *Config) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if cfg.SSHKeyPath != "" {
		key, err := os.ReadFile(cfg.SSHKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read SSH key %s: %w", cfg.SSHKeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse SSH key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
		log.Printf("[SSH] using key authentication: %s", cfg.SSHKeyPath)
	}

	// Password auth as fallback - not recommended for production
	// but needed for lab environments and initial setup
	if cfg.WinRMPassword != "" {
		methods = append(methods, ssh.Password(cfg.WinRMPassword))
		if cfg.SSHKeyPath == "" {
			log.Println("[SSH] WARNING: using password authentication - key-based auth recommended")
		}
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH authentication method configured - provide --ssh-key or --winrm-pass")
	}

	return methods, nil
}

// ── Log Line Parser ───────────────────────────────────────────────────────────

// parseSyslogLine parses a standard syslog line into a LinuxRawEvent.
// Handles RFC3164 and RFC5424 formats. Falls back gracefully on parse errors.
//
// Standard syslog format:
//
//	Jan 15 02:33:47 hostname process[pid]: message
func parseSyslogLine(line, sourceHost, logFile string) *LinuxRawEvent {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	raw := &LinuxRawEvent{
		Hostname: sourceHost,
		Message:  line,
		LogFile:  logFile,
	}

	// Try to parse timestamp from the beginning of the line
	ts, rest := extractSyslogTimestamp(line)
	raw.Timestamp = ts

	// After timestamp: hostname process[pid]: message
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		raw.Process = "unknown"
		return raw
	}

	// Field 0 may be the hostname if RFC5424 format
	fieldIdx := 0
	if len(fields) > 1 && !strings.Contains(fields[0], ":") {
		// Skip hostname field - we already know the source host
		fieldIdx = 1
	}

	if fieldIdx < len(fields) {
		// Process field: "sshd[12345]:" or "sudo:" or "kernel:"
		proc := fields[fieldIdx]
		proc = strings.TrimSuffix(proc, ":")
		if bracketIdx := strings.Index(proc, "["); bracketIdx != -1 {
			raw.PID = proc[bracketIdx+1 : strings.Index(proc, "]")]
			raw.Process = proc[:bracketIdx]
		} else {
			raw.Process = proc
		}
		// Rest is the message
		if fieldIdx+1 < len(fields) {
			raw.Message = strings.Join(fields[fieldIdx+1:], " ")
		}
	}

	return raw
}

// extractSyslogTimestamp attempts to parse a timestamp from the start
// of a syslog line. Returns the parsed time and the remainder of the line.
func extractSyslogTimestamp(line string) (time.Time, string) {
	// Try each format - shortest to longest prefix
	for _, format := range syslogTimestampFormats {
		prefixLen := len(format)
		if len(line) < prefixLen {
			continue
		}
		candidate := line[:prefixLen]
		t, err := time.Parse(format, candidate)
		if err != nil {
			// Also try with the actual current year for RFC3164
			// which doesn't include the year
			if !strings.Contains(format, "2006") {
				yearPrefix := fmt.Sprintf("%d ", time.Now().Year())
				t, err = time.Parse("2006 "+format, yearPrefix+candidate)
			}
			if err != nil {
				continue
			}
		}
		// Enforce UTC
		t = t.UTC()
		// If year is zero (RFC3164 has no year), use current year
		if t.Year() == 0 {
			t = t.AddDate(time.Now().Year(), 0, 0)
		}
		rest := strings.TrimSpace(line[prefixLen:])
		return t, rest
	}

	// No timestamp found - use now() and treat entire line as message
	return time.Now().UTC(), line
}

// ── SSH Session Manager ───────────────────────────────────────────────────────
// Manages the SSH connection lifecycle for a single host.
// Handles reconnection with exponential backoff.

type SSHSession struct {
	host   string
	port   int
	config *ssh.ClientConfig
	client *ssh.Client
	mu     sync.Mutex
}

func newSSHSession(host string, port int, cfg *ssh.ClientConfig) *SSHSession {
	return &SSHSession{
		host:   host,
		port:   port,
		config: cfg,
	}
}

func (s *SSHSession) connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", s.host, port22(s.port))
	client, err := ssh.Dial("tcp", addr, s.config)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	if s.client != nil {
		s.client.Close()
	}
	s.client = client
	log.Printf("[SSH] connected to %s", addr)
	return nil
}

func (s *SSHSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		s.client.Close()
		s.client = nil
	}
}

// runCommand executes a command on the remote host and returns stdout.
func (s *SSHSession) runCommand(cmd string) (io.Reader, *ssh.Session, error) {
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()

	if client == nil {
		return nil, nil, fmt.Errorf("not connected")
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("new session: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := session.Start(cmd); err != nil {
		session.Close()
		return nil, nil, fmt.Errorf("start command: %w", err)
	}

	return stdout, session, nil
}

func port22(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

// ── File Tailer ───────────────────────────────────────────────────────────────
// Tails a single log file on a remote host via SSH.
// Uses `tail -F` which follows file rotation automatically.

type FileTailer struct {
	session *SSHSession
	logFile string
	host    string
	pub     *Publisher
}

func (ft *FileTailer) tail(ctx context.Context) error {
	// Check if file exists first
	checkCmd := fmt.Sprintf("test -f %s && echo exists || echo missing", ft.logFile)
	checkOut, checkSess, err := ft.session.runCommand(checkCmd)
	if err != nil {
		return fmt.Errorf("check file: %w", err)
	}
	scanner := bufio.NewScanner(checkOut)
	scanner.Scan()
	exists := strings.TrimSpace(scanner.Text())
	checkSess.Close()

	if exists != "exists" {
		// File doesn't exist on this host - skip silently
		return nil
	}

	// tail -n 0 means start from now, not from the beginning
	// -F follows file rotation (better than -f for log files)
	tailCmd := fmt.Sprintf("tail -n 0 -F %s 2>/dev/null", ft.logFile)
	stdout, session, err := ft.session.runCommand(tailCmd)
	if err != nil {
		return fmt.Errorf("tail command: %w", err)
	}
	defer session.Close()

	log.Printf("[SSH] tailing %s:%s", ft.host, ft.logFile)

	scanner = bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			session.Close()
		case <-done:
		}
	}()

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			close(done)
			return nil
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		raw := parseSyslogLine(line, ft.host, ft.logFile)
		if raw == nil {
			continue
		}

		// Skip debug and noise lines
		if shouldSkipLine(line) {
			continue
		}

		normalised := NormaliseLinuxEvent(raw)
		if err := ft.pub.Publish(normalised); err != nil {
			log.Printf("[SSH] publish error %s:%s: %v", ft.host, ft.logFile, err)
		}
	}

	close(done)

	if err := scanner.Err(); err != nil {
		if !isClosedError(err) {
			return fmt.Errorf("scanner: %w", err)
		}
	}
	return nil
}

// ── Journald Support ──────────────────────────────────────────────────────────
// On systemd-based systems, journalctl provides richer structured output.
// We use it as an additional source alongside traditional log files.

type JournaldTailer struct {
	session *SSHSession
	host    string
	pub     *Publisher
}

func (jt *JournaldTailer) tail(ctx context.Context) error {
	// Check if journalctl is available
	checkOut, checkSess, err := jt.session.runCommand("which journalctl 2>/dev/null && echo yes || echo no")
	if err != nil {
		return nil // journald not available - not an error
	}
	sc := bufio.NewScanner(checkOut)
	sc.Scan()
	available := strings.TrimSpace(sc.Text())
	checkSess.Close()

	if available != "yes" {
		return nil
	}

	// Follow journal from now, output as short format
	// Filter to security-relevant units
	cmd := "journalctl -f -n 0 --output=short-iso " +
		"-u sshd -u sudo -u cron -u auditd -u systemd " +
		"2>/dev/null"

	stdout, session, err := jt.session.runCommand(cmd)
	if err != nil {
		return nil // journald available but failed - not fatal
	}
	defer session.Close()

	log.Printf("[SSH] journald stream active on %s", jt.host)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			session.Close()
		case <-done:
		}
	}()

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			close(done)
			return nil
		default:
		}

		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}

		raw := parseSyslogLine(line, jt.host, "journald")
		if raw == nil {
			continue
		}
		if shouldSkipLine(line) {
			continue
		}

		normalised := NormaliseLinuxEvent(raw)
		if err := jt.pub.Publish(normalised); err != nil {
			log.Printf("[SSH] journald publish error %s: %v", jt.host, err)
		}
	}

	close(done)
	return nil
}

// ── SSH Collector ─────────────────────────────────────────────────────────────

type SSHCollector struct {
	cfg *Config
}

func NewSSHCollector(cfg *Config) *SSHCollector {
	return &SSHCollector{cfg: cfg}
}

func (c *SSHCollector) Name() string {
	return "SSH"
}

func (c *SSHCollector) Start(ctx context.Context, pub *Publisher) error {
	authMethods, err := buildSSHAuth(c.cfg)
	if err != nil {
		return fmt.Errorf("SSH auth: %w", err)
	}

	sshCfg := &ssh.ClientConfig{
		User:            c.cfg.SSHUser,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: known_hosts in v1.1
		Timeout:         15 * time.Second,
	}

	log.Printf("[SSH] monitoring %d host(s): %v", len(c.cfg.SSHHosts), c.cfg.SSHHosts)

	var wg sync.WaitGroup
	for _, host := range c.cfg.SSHHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			c.monitorHost(ctx, h, sshCfg, pub)
		}(host)
	}
	wg.Wait()
	return nil
}

// monitorHost manages the full lifecycle of monitoring a single Linux host.
// Connects via SSH, starts file tailers and journald stream, and reconnects
// automatically if the connection drops. Uses exponential backoff.
func (c *SSHCollector) monitorHost(
	ctx context.Context,
	host string,
	sshCfg *ssh.ClientConfig,
	pub *Publisher,
) {
	backoff := 5 * time.Second
	maxBackoff := 5 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		session := newSSHSession(host, 22, sshCfg)
		if err := session.connect(); err != nil {
			log.Printf("[SSH] %s: connection failed: %v - retrying in %s", host, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = minDuration(backoff*2, maxBackoff)
				continue
			}
		}

		// Connection successful - reset backoff
		backoff = 5 * time.Second

		// Run all tailers concurrently under a sub-context
		hostCtx, hostCancel := context.WithCancel(ctx)
		var hostWg sync.WaitGroup

		// File tailers
		logFiles := c.cfg.SSHLogPaths
		if len(logFiles) == 0 {
			logFiles = defaultLinuxLogFiles
		}
		for _, logFile := range logFiles {
			hostWg.Add(1)
			go func(lf string) {
				defer hostWg.Done()
				tailer := &FileTailer{
					session: session,
					logFile: lf,
					host:    host,
					pub:     pub,
				}
				if err := tailer.tail(hostCtx); err != nil {
					if !isContextError(err) {
						log.Printf("[SSH] %s:%s tailer error: %v", host, lf, err)
					}
				}
			}(logFile)
		}

		// Journald stream
		hostWg.Add(1)
		go func() {
			defer hostWg.Done()
			jt := &JournaldTailer{session: session, host: host, pub: pub}
			if err := jt.tail(hostCtx); err != nil {
				if !isContextError(err) {
					log.Printf("[SSH] %s: journald error: %v", host, err)
				}
			}
		}()

		// Wait for all tailers to finish
		// They finish when context is cancelled or connection drops
		hostWg.Wait()
		hostCancel()
		session.close()

		select {
		case <-ctx.Done():
			return
		default:
			log.Printf("[SSH] %s: reconnecting in %s", host, backoff)
			time.Sleep(backoff)
			backoff = minDuration(backoff*2, maxBackoff)
		}
	}
}

// ── Filter ────────────────────────────────────────────────────────────────────
// Skip high-volume noise lines that add no security value.
// Keep this list tight - when in doubt, include the line.

var skipPatterns = []string{
	"last message repeated",
	"CRON[",
	"systemd-logind",
	"pam_unix(cron",
	"session opened for user root by (uid=0)", // cron root sessions - noise
	"session closed for user root",
	"ntpd[",
	"rsyslogd",
	"dbus-daemon",
}

func shouldSkipLine(line string) bool {
	lineLower := strings.ToLower(line)
	for _, pattern := range skipPatterns {
		if strings.Contains(lineLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// ── Error Helpers ─────────────────────────────────────────────────────────────

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "broken pipe")
}

func isContextError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "context canceled") ||
		strings.Contains(s, "context deadline")
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// Ensure net package is used for potential future DNS resolution
var _ = net.LookupHost
