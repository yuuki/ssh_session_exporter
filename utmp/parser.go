package utmp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	recordSize       = 384
	recordSizeTime64 = 400
	userProcess      = 7

	utNameSize = 32
	utLineSize = 32
	utHostSize = 256
	utIDSize   = 4
)

// rawRecord mirrors the Linux utmp layout used on x86_64.
type rawRecord struct {
	Type    int16
	_       [2]byte
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
	_       [20]byte
}

// rawRecordTime64 mirrors the Linux utmp layout used on aarch64/time64 systems.
type rawRecordTime64 struct {
	Type    int16
	_       [2]byte
	PID     int32
	Line    [utLineSize]byte
	ID      [utIDSize]byte
	User    [utNameSize]byte
	Host    [utHostSize]byte
	ExitT   int16
	ExitE   int16
	Session int32
	_       int32
	TvSec   int64
	TvUsec  int64
	AddrV6  [4]int32
	_       [20]byte
	_       [4]byte
}

// parseRecords parses raw utmp binary data into SSH sessions.
func parseRecords(data []byte) ([]Session, error) {
	switch {
	case len(data) == 0:
		return nil, nil
	case len(data)%recordSizeTime64 == 0:
		return parseRecordsTime64(data)
	case len(data)%recordSize == 0:
		return parseRecords32(data)
	default:
		return nil, fmt.Errorf("parse utmp record: unexpected EOF")
	}
}

func parseRecords32(data []byte) ([]Session, error) {
	n := len(data) / recordSize
	sessions := make([]Session, 0, n)
	reader := bytes.NewReader(data)
	for i := 0; i < n; i++ {
		var rec rawRecord
		if err := binary.Read(reader, binary.LittleEndian, &rec); err != nil {
			return sessions, fmt.Errorf("parse utmp record: %w", err)
		}
		sessions = appendSession32(sessions, rec)
	}
	return sessions, nil
}

func parseRecordsTime64(data []byte) ([]Session, error) {
	n := len(data) / recordSizeTime64
	sessions := make([]Session, 0, n)
	reader := bytes.NewReader(data)
	for i := 0; i < n; i++ {
		var rec rawRecordTime64
		if err := binary.Read(reader, binary.LittleEndian, &rec); err != nil {
			return sessions, fmt.Errorf("parse utmp record: %w", err)
		}
		sessions = appendSessionTime64(sessions, rec)
	}
	return sessions, nil
}

func appendSession32(sessions []Session, rec rawRecord) []Session {
	if rec.Type != userProcess {
		return sessions
	}
	host := cString(rec.Host[:])
	if host == "" {
		return sessions
	}
	return append(sessions, Session{
		User:      cString(rec.User[:]),
		TTY:       cString(rec.Line[:]),
		Host:      host,
		LoginTime: time.Unix(int64(rec.TvSec), int64(rec.TvUsec)*1000),
		PID:       rec.PID,
	})
}

func appendSessionTime64(sessions []Session, rec rawRecordTime64) []Session {
	if rec.Type != userProcess {
		return sessions
	}
	host := cString(rec.Host[:])
	if host == "" {
		return sessions
	}
	return append(sessions, Session{
		User:      cString(rec.User[:]),
		TTY:       cString(rec.Line[:]),
		Host:      host,
		LoginTime: time.Unix(rec.TvSec, rec.TvUsec*1000),
		PID:       rec.PID,
	})
}

// cString extracts a null-terminated string from a byte slice.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
