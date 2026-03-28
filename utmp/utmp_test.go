package utmp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func makeRecord(typ int16, pid int32, user, line, host string, sec int32) []byte {
	rec := rawRecord{
		Type:  typ,
		PID:   pid,
		TvSec: sec,
	}
	copy(rec.User[:], user)
	copy(rec.Line[:], line)
	copy(rec.Host[:], host)

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &rec); err != nil {
		panic(err)
	}
	if buf.Len() != recordSize {
		panic("unexpected record size")
	}
	return buf.Bytes()
}

func makeRecordTime64(typ int16, pid int32, user, line, host string, sec int64) []byte {
	rec := rawRecordTime64{
		Type:  typ,
		PID:   pid,
		TvSec: sec,
	}
	copy(rec.User[:], user)
	copy(rec.Line[:], line)
	copy(rec.Host[:], host)

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &rec); err != nil {
		panic(err)
	}
	if buf.Len() != recordSizeTime64 {
		panic("unexpected time64 record size")
	}
	return buf.Bytes()
}

func TestParseRecords_SSHSessions(t *testing.T) {
	data := make([]byte, 0)
	data = append(data, makeRecord(userProcess, 1234, "alice", "pts/0", "192.168.1.10", 1700000000)...)
	data = append(data, makeRecord(userProcess, 5678, "bob", "pts/1", "10.0.0.5", 1700001000)...)

	sessions, err := parseRecords(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	s := sessions[0]
	if s.User != "alice" || s.TTY != "pts/0" || s.Host != "192.168.1.10" || s.PID != 1234 {
		t.Errorf("unexpected session[0]: %+v", s)
	}
	expected := time.Unix(1700000000, 0)
	if !s.LoginTime.Equal(expected) {
		t.Errorf("expected login time %v, got %v", expected, s.LoginTime)
	}

	s = sessions[1]
	if s.User != "bob" || s.TTY != "pts/1" || s.Host != "10.0.0.5" || s.PID != 5678 {
		t.Errorf("unexpected session[1]: %+v", s)
	}
}

func TestParseRecords_SkipsNonUserProcess(t *testing.T) {
	data := make([]byte, 0)
	// Type 1 = RUN_LVL, should be skipped
	data = append(data, makeRecord(1, 0, "runlevel", "~", "", 1700000000)...)
	// Type 6 = INIT_PROCESS, should be skipped
	data = append(data, makeRecord(6, 100, "init", "si", "", 1700000000)...)
	// Valid SSH session
	data = append(data, makeRecord(userProcess, 999, "root", "pts/2", "172.16.0.1", 1700000000)...)

	sessions, err := parseRecords(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].User != "root" {
		t.Errorf("expected user root, got %s", sessions[0].User)
	}
}

func TestParseRecords_SkipsLocalLogin(t *testing.T) {
	data := make([]byte, 0)
	// Local login (empty host) should be skipped
	data = append(data, makeRecord(userProcess, 1000, "local", "tty1", "", 1700000000)...)
	// SSH session
	data = append(data, makeRecord(userProcess, 2000, "remote", "pts/0", "10.0.0.1", 1700000000)...)

	sessions, err := parseRecords(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].User != "remote" {
		t.Errorf("expected user remote, got %s", sessions[0].User)
	}
}

func TestParseRecords_EmptyInput(t *testing.T) {
	sessions, err := parseRecords(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestParseRecords_TruncatedInput(t *testing.T) {
	// Less than one full record
	data := make([]byte, 100)
	sessions, err := parseRecords(data)
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
	// Should return whatever was parsed before the error
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestParseRecords_Time64Record(t *testing.T) {
	data := make([]byte, 0)
	data = append(data, makeRecordTime64(userProcess, 1234, "probe", "pts/0", "192.168.5.2", 1700000000)...)

	sessions, err := parseRecords(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].User != "probe" || sessions[0].Host != "192.168.5.2" || sessions[0].PID != 1234 {
		t.Fatalf("unexpected session: %+v", sessions[0])
	}
}

func TestCString(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello\x00\x00\x00"), "hello"},
		{[]byte("\x00padding"), ""},
		{[]byte("full"), "full"},
	}
	for _, tt := range tests {
		got := cString(tt.input)
		if got != tt.expected {
			t.Errorf("cString(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
