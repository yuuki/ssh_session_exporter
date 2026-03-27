//go:build linux

package utmp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"
)

const (
	recordSize  = 384 // size of a utmp record on Linux x86_64
	userProcess int16 = 7

	utNameSize = 32
	utLineSize = 32
	utHostSize = 256
	utIDSize   = 4
)

// rawRecord mirrors the Linux utmp struct (384 bytes on x86_64).
type rawRecord struct {
	Type    int16
	_       [2]byte // padding for alignment
	PID     int32
	Line    [utLineSize]byte
	ID      [utIDSize]byte
	User    [utNameSize]byte
	Host    [utHostSize]byte
	ExitT   int16
	ExitE   int16
	Session int32
	TvSec   int32
	TvUsec  int32
	AddrV6  [4]int32
	_       [20]byte // unused
}

type FileReader struct {
	path   string
	logger *slog.Logger
}

func NewFileReader(path string, logger *slog.Logger) *FileReader {
	return &FileReader{path: path, logger: logger}
}

func (r *FileReader) ReadSessions() ([]Session, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return nil, fmt.Errorf("read utmp file %s: %w", r.path, err)
	}
	return parseRecords(data)
}

// parseRecords parses raw utmp binary data into SSH sessions.
func parseRecords(data []byte) ([]Session, error) {
	reader := bytes.NewReader(data)
	var sessions []Session

	for {
		var rec rawRecord
		if err := binary.Read(reader, binary.LittleEndian, &rec); err != nil {
			if err == io.EOF {
				break
			}
			return sessions, fmt.Errorf("parse utmp record: %w", err)
		}

		if rec.Type != userProcess {
			continue
		}

		host := cString(rec.Host[:])
		if host == "" {
			continue // local login, not SSH
		}

		sessions = append(sessions, Session{
			User:      cString(rec.User[:]),
			TTY:       cString(rec.Line[:]),
			Host:      host,
			LoginTime: time.Unix(int64(rec.TvSec), int64(rec.TvUsec)*1000),
			PID:       rec.PID,
		})
	}

	return sessions, nil
}

// cString extracts a null-terminated string from a byte slice.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
