/*
LogClaw Harvester — Windows Event Log Collector
winrm.go — Remote Windows Event Log ingestion via WinRM

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Connects to Windows hosts via WinRM, queries Security,
          System, and Application event logs, normalises each event
          into the universal LogClaw schema, and publishes to the
          ZeroMQ pipe. Runs on a configurable polling interval.
          Tracks the last seen event timestamp per host so it never
          re-sends events already processed.
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
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/masterzen/winrm"
)

// ── Monitored Event IDs ───────────────────────────────────────────────────────
// Only these Event IDs are pulled. Pulling everything would flood the pipe.
// This list covers every security-relevant event LogClaw tracks.

var monitoredEventIDs = []int{
	// Authentication
	4624, // Successful logon
	4625, // Failed logon
	4634, // Logoff
	4647, // User-initiated logoff
	4648, // Logon with explicit credentials
	4672, // Special privileges assigned to new logon
	4776, // Credential validation

	// Account management
	4720, // Account created
	4722, // Account enabled
	4723, // Password change attempt
	4724, // Password reset
	4725, // Account disabled
	4726, // Account deleted
	4728, // Member added to global group
	4732, // Member added to local group
	4740, // Account locked out
	4756, // Member added to universal group
	4767, // Account unlocked

	// Process and service
	4688, // New process created
	4697, // Service installed
	7045, // New service installed (System log)

	// Scheduled tasks
	4698, // Scheduled task created
	4702, // Scheduled task updated

	// Audit and policy
	1102, // Audit log cleared
	4719, // System audit policy changed

	// Object access
	5140, // Network share accessed
	5145, // Network share object checked
}

// buildEventIDFilter generates an XPath filter string for WinRM queries.
// Batches all monitored Event IDs into a single query to minimise round trips.
func buildEventIDFilter() string {
	var parts []string
	for _, id := range monitoredEventIDs {
		parts = append(parts, fmt.Sprintf("EventID=%d", id))
	}
	return strings.Join(parts, " or ")
}

// ── WinRM XML Structures ──────────────────────────────────────────────────────
// Windows returns events as XML. These structs decode the relevant fields.
// We only decode what we need — raw XML is preserved in RawPayload.

type WinEvent struct {
	XMLName   xml.Name     `xml:"Event"`
	System    WinSystem    `xml:"System"`
	EventData WinEventData `xml:"EventData"`
}

type WinSystem struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	} `xml:"Provider"`
	EventID     int `xml:"EventID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	Computer string `xml:"Computer"`
	Channel  string `xml:"Channel"`
}

type WinEventData struct {
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"Data"`
}

// getDataValue extracts a named field from Windows EventData by name.
func (e *WinEventData) getDataValue(name string) string {
	for _, d := range e.Data {
		if strings.EqualFold(d.Name, name) {
			return strings.TrimSpace(d.Value)
		}
	}
	return ""
}

// ── Host State ────────────────────────────────────────────────────────────────
// Tracks the last event timestamp seen per host per log channel.
// Prevents duplicate events across polling intervals.

type HostState struct {
	mu       sync.Mutex
	lastSeen map[string]time.Time // key: "host:channel"
}

func newHostState() *HostState {
	return &HostState{lastSeen: make(map[string]time.Time)}
}

func (s *HostState) getLastSeen(host, channel string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := host + ":" + channel
	if t, ok := s.lastSeen[key]; ok {
		return t
	}
	// Default: look back 60 seconds on first poll
	return time.Now().UTC().Add(-60 * time.Second)
}

func (s *HostState) updateLastSeen(host, channel string, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := host + ":" + channel
	if existing, ok := s.lastSeen[key]; !ok || t.After(existing) {
		s.lastSeen[key] = t
	}
}

// ── WinRM Collector ───────────────────────────────────────────────────────────

type WinRMCollector struct {
	cfg         *Config
	state       *HostState
	eventFilter string
}

func NewWinRMCollector(cfg *Config) *WinRMCollector {
	return &WinRMCollector{
		cfg:         cfg,
		state:       newHostState(),
		eventFilter: buildEventIDFilter(),
	}
}

func (c *WinRMCollector) Name() string {
	return "WinRM"
}

func (c *WinRMCollector) Start(ctx context.Context, pub *Publisher) error {
	log.Printf("[WinRM] monitoring %d host(s): %v", len(c.cfg.WinRMHosts), c.cfg.WinRMHosts)

	ticker := time.NewTicker(c.cfg.WinRMInterval)
	defer ticker.Stop()

	// Initial poll immediately on start
	c.pollAllHosts(ctx, pub)

	for {
		select {
		case <-ctx.Done():
			log.Println("[WinRM] context cancelled — stopping")
			return nil
		case <-ticker.C:
			c.pollAllHosts(ctx, pub)
		}
	}
}

// pollAllHosts polls every configured host concurrently.
// Each host gets its own goroutine so a slow or unreachable host
// does not block the others.
func (c *WinRMCollector) pollAllHosts(ctx context.Context, pub *Publisher) {
	var wg sync.WaitGroup
	for _, host := range c.cfg.WinRMHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			if err := c.pollHost(ctx, h, pub); err != nil {
				log.Printf("[WinRM] %s: poll error: %v", h, err)
			}
		}(host)
	}
	wg.Wait()
}

// pollHost connects to a single Windows host and pulls new events
// from Security, System, and Application channels.
func (c *WinRMCollector) pollHost(ctx context.Context, host string, pub *Publisher) error {
	endpoint := winrm.NewEndpoint(
		host,
		c.cfg.WinRMPort,
		false, // HTTPS — set to true in production with a real cert
		false, // insecure skip verify
		nil,   // CA cert
		nil,   // client cert
		nil,   // client key
		30*time.Second,
	)

	client, err := winrm.NewClient(endpoint, c.cfg.WinRMUser, c.cfg.WinRMPassword)
	if err != nil {
		return fmt.Errorf("winrm client: %w", err)
	}

	channels := []string{"Security", "System", "Application"}
	for _, channel := range channels {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if err := c.pullChannel(ctx, client, host, channel, pub); err != nil {
			log.Printf("[WinRM] %s/%s: %v", host, channel, err)
			// Continue to next channel — one failure should not stop others
		}
	}
	return nil
}

// pullChannel queries a specific event log channel on a remote host
// and publishes all new events since the last poll.
func (c *WinRMCollector) pullChannel(
	ctx context.Context,
	client *winrm.Client,
	host, channel string,
	pub *Publisher,
) error {
	lastSeen := c.state.getLastSeen(host, channel)
	tsFilter := lastSeen.UTC().Format("2006-01-02T15:04:05.000Z")

	query := fmt.Sprintf(
		`Get-WinEvent -FilterXml '<QueryList><Query><Select Path="%s">*[System[(%s) and TimeCreated[@SystemTime>"%s"]]]</Select></Query></QueryList>' -ErrorAction SilentlyContinue | ConvertTo-Xml -As String -NoTypeInformation`,
		channel,
		c.eventFilter,
		tsFilter,
	)

	outBuf := new(strings.Builder)
	errBuf := new(strings.Builder)

	exitCode, err := client.Run(query, outBuf, errBuf)
	if err != nil {
		return fmt.Errorf("winrm run (exit %d): %w", exitCode, err)
	}

	outStr := outBuf.String()
	if strings.TrimSpace(outStr) == "" {
		return nil
	}

	return c.parseAndPublish(outStr, host, channel, pub)
}

// parseAndPublish decodes the XML response from Get-WinEvent,
// normalises each event, and publishes it to the ZeroMQ pipe.
func (c *WinRMCollector) parseAndPublish(
	xmlData, host, channel string,
	pub *Publisher,
) error {
	// Get-WinEvent | ConvertTo-Xml wraps events in <Objects><Object>
	// We need to extract individual Event XML blocks
	eventBlocks := extractEventBlocks(xmlData)
	if len(eventBlocks) == 0 {
		return nil
	}

	published := 0
	var latestTime time.Time

	for _, block := range eventBlocks {
		var evt WinEvent
		if err := xml.Unmarshal([]byte(block), &evt); err != nil {
			// Log and skip malformed events — never crash on bad input
			log.Printf("[WinRM] xml parse error on %s/%s: %v", host, channel, err)
			continue
		}

		// Parse timestamp — enforce UTC
		ts, err := parseWindowsTimestamp(evt.System.TimeCreated.SystemTime)
		if err != nil {
			ts = time.Now().UTC()
		}

		// Track latest timestamp for this host/channel
		if ts.After(latestTime) {
			latestTime = ts
		}

		// Build raw event struct for normaliser
		raw := &WindowsRawEvent{
			EventID:     evt.System.EventID,
			TimeCreated: ts,
			Computer:    evt.System.Computer,
			SubjectUser: evt.EventData.getDataValue("SubjectUserName"),
			TargetUser:  evt.EventData.getDataValue("TargetUserName"),
			LogonType:   evt.EventData.getDataValue("LogonType"),
			IPAddress:   evt.EventData.getDataValue("IpAddress"),
			ProcessName: evt.EventData.getDataValue("NewProcessName"),
			ServiceName: evt.EventData.getDataValue("ServiceName"),
			RawXML:      block,
		}

		// Use hostname from config if Computer field is empty
		if raw.Computer == "" {
			raw.Computer = host
		}

		normalised := NormaliseWindowsEvent(raw)
		if err := pub.Publish(normalised); err != nil {
			log.Printf("[WinRM] publish error: %v", err)
		} else {
			published++
		}
	}

	if published > 0 {
		log.Printf("[WinRM] %s/%s: published %d event(s)", host, channel, published)
	}

	// Update last seen timestamp
	if !latestTime.IsZero() {
		// Add 1ms to avoid re-fetching the last event on next poll
		c.state.updateLastSeen(host, channel, latestTime.Add(time.Millisecond))
	}

	return nil
}

// ── XML Helpers ───────────────────────────────────────────────────────────────

// extractEventBlocks pulls individual <Event>...</Event> XML blocks
// from a ConvertTo-Xml response. ConvertTo-Xml wraps each event in
// <Object> tags which we strip before passing to xml.Unmarshal.
func extractEventBlocks(data string) []string {
	var blocks []string
	start := 0
	tag := "<Event "
	endTag := "</Event>"

	for {
		si := strings.Index(data[start:], tag)
		if si == -1 {
			break
		}
		si += start

		ei := strings.Index(data[si:], endTag)
		if ei == -1 {
			break
		}
		ei += si + len(endTag)

		blocks = append(blocks, data[si:ei])
		start = ei
	}
	return blocks
}

// parseWindowsTimestamp parses the SystemTime attribute format used by
// Windows Event Log: "2024-01-15T02:33:47.123456700Z"
func parseWindowsTimestamp(s string) (time.Time, error) {
	formats := []string{
		"2006-01-02T15:04:05.9999999Z",
		"2006-01-02T15:04:05.999999999Z07:00",
		time.RFC3339Nano,
		time.RFC3339,
	}
	s = strings.TrimSpace(s)
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse timestamp: %q", s)
}
