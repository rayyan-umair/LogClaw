/*
LogClaw Harvester — EVTX File Fallthrough Parser
evtx_fallthrough.go — Offline Windows Event Log ingestion

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : Parses exported Windows Event Log (.evtx) files directly.
          This is the fallthrough path for Windows hosts where WinRM
          is disabled, unavailable, or blocked by firewall policy.
          Accepts one or more .evtx file paths, parses every event,
          normalises into the universal LogClaw schema, and publishes
          to the ZeroMQ pipe. Also useful for post-incident forensic
          analysis of exported logs from a compromised host.
          Supports both single-file and directory watch mode.
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
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// ── EVTX File Format Constants ────────────────────────────────────────────────
// Windows Event Log (.evtx) is a binary format with a specific structure.
// We parse it directly without external libraries for zero-dependency operation.
//
// File layout:
//   ElfFileHeader (4096 bytes)
//   ChunkHeader   (512 bytes) × N chunks
//   Each chunk contains records in BinXml format

const (
	evtxFileSignature   = "ElfFile\x00" // 8-byte file magic
	evtxChunkSignature  = "ElfChnk\x00" // 8-byte chunk magic
	evtxFileHeaderSize  = 4096          // fixed file header size
	evtxChunkHeaderSize = 512           // fixed chunk header size
	evtxChunkDataSize   = 65536         // chunk data area
	evtxChunkSize       = evtxChunkHeaderSize + evtxChunkDataSize
)

// ── EVTX File Header ──────────────────────────────────────────────────────────

type evtxFileHeader struct {
	Signature       [8]byte  // "ElfFile\x00"
	OldestChunk     uint64   // oldest chunk number
	CurrentChunkNum uint64   // current chunk number
	NextRecordNum   uint64   // next record number
	HeaderSize      uint32   // always 128
	MinorVersion    uint16   // always 1
	MajorVersion    uint16   // always 3
	HeaderBlockSize uint16   // always 4096
	ChunkCount      uint16   // number of chunks
	_               [76]byte // reserved
	Flags           uint32
	Checksum        uint32
}

// ── EVTX Chunk Header ─────────────────────────────────────────────────────────

type evtxChunkHeader struct {
	Signature        [8]byte // "ElfChnk\x00"
	FirstEventRecNum uint64  // first event record number in chunk
	LastEventRecNum  uint64  // last event record number in chunk
	FirstEventLogID  uint64  // first event log file offset
	LastEventLogID   uint64  // last event log file offset
	HeaderSize       uint32  // always 128
	LastEventRecOff  uint32  // offset of last event record
	FreeSpaceOffset  uint32  // start of free space in chunk
	EventRecChecksum uint32  // CRC32 of event records
	_                [64]byte
	Flags            uint32
	Checksum         uint32
}

// ── EVTX Record ───────────────────────────────────────────────────────────────

type evtxRecord struct {
	Signature   uint32 // always 0x00002a2a ("**")
	Size        uint32 // total record size including this header
	RecordID    uint64 // sequential record identifier
	TimeCreated uint64 // FILETIME — 100-nanosecond intervals since 1601-01-01
}

// ── Parsed Event ──────────────────────────────────────────────────────────────
// Intermediate representation after BinXML parsing,
// before conversion to LogClaw universal schema.

type parsedEVTXEvent struct {
	EventID     int
	TimeCreated time.Time
	Computer    string
	Channel     string
	SubjectUser string
	TargetUser  string
	IPAddress   string
	LogonType   string
	ProcessName string
	ServiceName string
	TaskName    string
	RawData     string // reconstructed as text for RawPayload
}

// ── FILETIME Converter ────────────────────────────────────────────────────────
// Windows FILETIME is 100-nanosecond intervals since January 1, 1601.
// Convert to Go time.Time in UTC.

func filetimeToTime(ft uint64) time.Time {
	// Windows epoch to Unix epoch offset in 100ns intervals
	// (1601-01-01 to 1970-01-01 = 116444736000000000 × 100ns)
	const windowsEpochOffset uint64 = 116444736000000000
	if ft < windowsEpochOffset {
		return time.Now().UTC()
	}
	unixNano := int64((ft - windowsEpochOffset) * 100)
	return time.Unix(0, unixNano).UTC()
}

// ── BinXML Parser ─────────────────────────────────────────────────────────────
// Windows Event Log records are stored in Binary XML (BinXML) format.
// Full BinXML parsing is extremely complex. We use a practical approach:
// scan the binary data for UTF-16LE strings containing known field names
// and extract their values. This covers all monitored Event IDs reliably
// without implementing a full BinXML parser.

// extractUTF16Strings scans binary data for UTF-16LE encoded strings
// and returns them as a slice of Go strings. UTF-16LE strings in EVTX
// are null-terminated pairs of bytes where the second byte is usually 0.
func extractUTF16Strings(data []byte) []string {
	var results []string
	i := 0
	for i < len(data)-1 {
		// Look for sequences of printable ASCII chars in UTF-16LE
		// (byte pairs where second byte is 0x00)
		if data[i] >= 0x20 && data[i] <= 0x7e && i+1 < len(data) && data[i+1] == 0x00 {
			// Potential start of a UTF-16LE string
			var chars []uint16
			j := i
			for j < len(data)-1 {
				lo := data[j]
				hi := data[j+1]
				if lo == 0 && hi == 0 {
					break // null terminator
				}
				if hi == 0 && lo >= 0x20 {
					chars = append(chars, uint16(lo))
					j += 2
				} else if hi != 0 {
					// Non-ASCII UTF-16 character
					chars = append(chars, uint16(lo)|uint16(hi)<<8)
					j += 2
				} else {
					break
				}
			}
			if len(chars) >= 3 {
				s := string(utf16.Decode(chars))
				if isPrintableString(s) {
					results = append(results, s)
				}
			}
			i = j + 2
		} else {
			i++
		}
	}
	return results
}

func isPrintableString(s string) bool {
	if len(s) < 2 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// extractFieldValue looks for a known field name in a list of extracted strings
// and returns the value that follows it. Windows event data fields appear as
// name/value pairs in the string stream.
func extractFieldValue(strs []string, fieldName string) string {
	fieldLower := strings.ToLower(fieldName)
	for i, s := range strs {
		if strings.ToLower(s) == fieldLower && i+1 < len(strs) {
			val := strs[i+1]
			if !looksLikeFieldName(val) {
				return val
			}
		}
	}
	return ""
}

func looksLikeFieldName(s string) bool {
	if len(s) > 40 || len(s) < 2 {
		return false
	}
	// Field names are CamelCase, no spaces, mostly ASCII
	spaceCount := strings.Count(s, " ")
	return spaceCount == 0 && s[0] >= 'A' && s[0] <= 'Z'
}

// ── Record Parser ─────────────────────────────────────────────────────────────

// parseEVTXRecord extracts a parsedEVTXEvent from raw record bytes.
// Uses the string extraction approach for reliable field recovery
// without a full BinXML implementation.
func parseEVTXRecord(data []byte) (*parsedEVTXEvent, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("record too small: %d bytes", len(data))
	}

	evt := &parsedEVTXEvent{}

	// Read record header
	sig := binary.LittleEndian.Uint32(data[0:4])
	if sig != 0x00002a2a {
		return nil, fmt.Errorf("invalid record signature: 0x%08x", sig)
	}

	// TimeCreated is at offset 8 as a FILETIME (uint64)
	if len(data) >= 16 {
		ft := binary.LittleEndian.Uint64(data[8:16])
		evt.TimeCreated = filetimeToTime(ft)
	} else {
		evt.TimeCreated = time.Now().UTC()
	}

	// Extract all UTF-16LE strings from the record payload
	// Skip the 24-byte record header
	payload := data[24:]
	extracted := extractUTF16Strings(payload)

	// Reconstruct as readable text for RawPayload
	evt.RawData = strings.Join(extracted, " | ")

	// Extract Event ID — look for numeric strings near "EventID" or standalone
	evt.EventID = extractEventID(extracted, payload)

	// Extract known fields
	evt.Computer = extractFieldValue(extracted, "Computer")
	evt.Channel = extractFieldValue(extracted, "Channel")
	evt.SubjectUser = extractFieldValue(extracted, "SubjectUserName")
	evt.TargetUser = extractFieldValue(extracted, "TargetUserName")
	evt.IPAddress = extractFieldValue(extracted, "IpAddress")
	evt.LogonType = extractFieldValue(extracted, "LogonType")
	evt.ProcessName = extractFieldValue(extracted, "NewProcessName")
	evt.ServiceName = extractFieldValue(extracted, "ServiceName")
	evt.TaskName = extractFieldValue(extracted, "TaskName")

	// Clean up common noise values
	evt.SubjectUser = cleanEVTXValue(evt.SubjectUser)
	evt.TargetUser = cleanEVTXValue(evt.TargetUser)
	evt.IPAddress = cleanEVTXValue(evt.IPAddress)

	return evt, nil
}

// extractEventID finds the Event ID from extracted strings or binary data.
func extractEventID(strs []string, data []byte) int {
	// Look for "EventID" followed by a numeric string
	for i, s := range strs {
		if strings.EqualFold(s, "EventID") || strings.EqualFold(s, "EventRecordID") {
			if i+1 < len(strs) {
				var id int
				if _, err := fmt.Sscanf(strs[i+1], "%d", &id); err == nil && id > 0 && id < 65536 {
					return id
				}
			}
		}
	}

	// Fallback: scan binary data for uint16 values at typical Event ID offsets
	// Event ID is typically stored at a fixed offset within the System element
	for offset := 24; offset < len(data)-2; offset += 2 {
		val := binary.LittleEndian.Uint16(data[offset : offset+2])
		if _, ok := windowsEventDescriptions[int(val)]; ok {
			return int(val)
		}
	}

	return 0
}

func cleanEVTXValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "-" || s == "N/A" || s == "NULL" || s == "" {
		return ""
	}
	return s
}

// ── EVTX File Reader ──────────────────────────────────────────────────────────

// EVTXReader reads and parses a single .evtx file.
type EVTXReader struct {
	path string
	pub  *Publisher
}

func (r *EVTXReader) parse(ctx context.Context, hostname string) (int, error) {
	f, err := os.Open(r.path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", r.path, err)
	}
	defer f.Close()

	// Validate file signature
	sig := make([]byte, 8)
	if _, err := io.ReadFull(f, sig); err != nil {
		return 0, fmt.Errorf("read signature: %w", err)
	}
	if string(sig) != evtxFileSignature {
		return 0, fmt.Errorf("not a valid .evtx file: %s", r.path)
	}

	// Read file header
	headerBuf := make([]byte, evtxFileHeaderSize-8)
	if _, err := io.ReadFull(f, headerBuf); err != nil {
		return 0, fmt.Errorf("read file header: %w", err)
	}

	// Extract chunk count from header (at offset 40 from start of file)
	// chunkCount is at offset 40 in the full header
	var chunkCount uint16
	if len(headerBuf) >= 34 {
		chunkCount = binary.LittleEndian.Uint16(headerBuf[32:34])
	}
	if chunkCount == 0 {
		chunkCount = 256 // reasonable default if header is corrupted
	}

	log.Printf("[EVTX] parsing %s (%d chunk(s))", filepath.Base(r.path), chunkCount)

	published := 0
	chunkBuf := make([]byte, evtxChunkSize)

	for chunkNum := uint16(0); chunkNum < chunkCount; chunkNum++ {
		select {
		case <-ctx.Done():
			return published, nil
		default:
		}

		n, err := io.ReadFull(f, chunkBuf)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break // End of file — normal
			}
			log.Printf("[EVTX] chunk %d read error: %v", chunkNum, err)
			break
		}
		if n < evtxChunkHeaderSize {
			break
		}

		// Validate chunk signature
		if string(chunkBuf[:8]) != evtxChunkSignature {
			continue // Skip invalid chunks
		}

		// Parse records from chunk data area
		count := r.parseChunk(ctx, chunkBuf[evtxChunkHeaderSize:n], hostname)
		published += count
	}

	return published, nil
}

// parseChunk processes the data area of a single EVTX chunk,
// extracting all event records it contains.
func (r *EVTXReader) parseChunk(ctx context.Context, data []byte, hostname string) int {
	published := 0
	offset := 0

	for offset < len(data)-8 {
		select {
		case <-ctx.Done():
			return published
		default:
		}

		// Look for record signature 0x00002a2a ("**")
		if offset+4 > len(data) {
			break
		}
		sig := binary.LittleEndian.Uint32(data[offset : offset+4])
		if sig != 0x00002a2a {
			offset++
			continue
		}

		// Read record size
		if offset+8 > len(data) {
			break
		}
		recordSize := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		if recordSize < 24 || recordSize > 65000 {
			offset++
			continue
		}

		end := offset + int(recordSize)
		if end > len(data) {
			break
		}

		recordData := data[offset:end]
		evt, err := parseEVTXRecord(recordData)
		if err != nil {
			offset += int(recordSize)
			continue
		}

		// Skip events with EventID 0 — likely padding or parse failure
		if evt.EventID == 0 {
			offset += int(recordSize)
			continue
		}

		// Only process monitored Event IDs
		if !isMonitoredEventID(evt.EventID) {
			offset += int(recordSize)
			continue
		}

		// Use filename as source if Computer field not extracted
		source := evt.Computer
		if source == "" {
			source = hostname
		}

		raw := &WindowsRawEvent{
			EventID:     evt.EventID,
			TimeCreated: evt.TimeCreated,
			Computer:    source,
			SubjectUser: evt.SubjectUser,
			TargetUser:  evt.TargetUser,
			IPAddress:   evt.IPAddress,
			LogonType:   evt.LogonType,
			ProcessName: evt.ProcessName,
			ServiceName: evt.ServiceName,
			RawXML:      evt.RawData,
		}

		normalised := NormaliseWindowsEvent(raw)
		if err := r.pub.Publish(normalised); err != nil {
			log.Printf("[EVTX] publish error: %v", err)
		} else {
			published++
		}

		offset += int(recordSize)
	}

	return published
}

func isMonitoredEventID(id int) bool {
	for _, monitored := range monitoredEventIDs {
		if id == monitored {
			return true
		}
	}
	return false
}

// ── Directory Watcher ─────────────────────────────────────────────────────────
// Watches a directory for new .evtx files dropped in for analysis.
// Useful for forensic workflows where analysts export logs from
// compromised hosts and drop them into a watched folder.

type EVTXWatcher struct {
	dir      string
	pub      *Publisher
	seen     map[string]bool
	seenMu   sync.Mutex
	interval time.Duration
}

func newEVTXWatcher(dir string, pub *Publisher) *EVTXWatcher {
	return &EVTXWatcher{
		dir:      dir,
		pub:      pub,
		seen:     make(map[string]bool),
		interval: 10 * time.Second,
	}
}

func (w *EVTXWatcher) watch(ctx context.Context) error {
	log.Printf("[EVTX] watching directory: %s", w.dir)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Initial scan
	w.scanDirectory(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.scanDirectory(ctx)
		}
	}
}

func (w *EVTXWatcher) scanDirectory(ctx context.Context) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		log.Printf("[EVTX] directory scan error: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".evtx") {
			continue
		}

		fullPath := filepath.Join(w.dir, entry.Name())

		w.seenMu.Lock()
		alreadySeen := w.seen[fullPath]
		w.seenMu.Unlock()

		if alreadySeen {
			continue
		}

		// New .evtx file found
		hostname := strings.TrimSuffix(entry.Name(), ".evtx")
		reader := &EVTXReader{path: fullPath, pub: w.pub}

		log.Printf("[EVTX] new file detected: %s", entry.Name())
		count, err := reader.parse(ctx, hostname)
		if err != nil {
			log.Printf("[EVTX] parse error %s: %v", entry.Name(), err)
		} else {
			log.Printf("[EVTX] %s: published %d event(s)", entry.Name(), count)
		}

		w.seenMu.Lock()
		w.seen[fullPath] = true
		w.seenMu.Unlock()
	}
}

// ── EVTX Collector ────────────────────────────────────────────────────────────

type EVTXCollector struct {
	cfg *Config
}

func NewEVTXCollector(cfg *Config) *EVTXCollector {
	return &EVTXCollector{cfg: cfg}
}

func (c *EVTXCollector) Name() string {
	return "EVTX"
}

func (c *EVTXCollector) Start(ctx context.Context, pub *Publisher) error {
	var wg sync.WaitGroup

	for _, path := range c.cfg.EVTXPaths {
		info, err := os.Stat(path)
		if err != nil {
			log.Printf("[EVTX] path not found: %s — skipping", path)
			continue
		}

		if info.IsDir() {
			// Directory mode — watch for new .evtx files
			wg.Add(1)
			go func(dir string) {
				defer wg.Done()
				watcher := newEVTXWatcher(dir, pub)
				if err := watcher.watch(ctx); err != nil {
					log.Printf("[EVTX] watcher error: %v", err)
				}
			}(path)
		} else {
			// Single file mode — parse immediately and finish
			wg.Add(1)
			go func(filePath string) {
				defer wg.Done()
				hostname := strings.TrimSuffix(filepath.Base(filePath), ".evtx")
				reader := &EVTXReader{path: filePath, pub: pub}
				count, err := reader.parse(ctx, hostname)
				if err != nil {
					log.Printf("[EVTX] %s: %v", filepath.Base(filePath), err)
				} else {
					log.Printf("[EVTX] %s: published %d event(s)", filepath.Base(filePath), count)
				}
			}(path)
		}
	}

	wg.Wait()
	return nil
}

// Ensure utf16 package is used
var _ = utf16.Decode
