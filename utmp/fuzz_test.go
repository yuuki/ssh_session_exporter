package utmp

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

const deadProcess = 8

// makeNativeRecord writes a record in the layout of the platform the tests
// run on, which is the layout of the utmp file the exporter reads.
func makeNativeRecord(typ int16, pid int32, user, line, host string, sec int32) []byte {
	if nativeTime64 {
		return makeRecordTime64(typ, pid, user, line, host, int64(sec))
	}
	return makeRecord(typ, pid, user, line, host, sec)
}

// utmp is world-readable and written by more than sshd (libutempter lets
// local users add records), so parseRecords must cope with any content.
func FuzzParseRecords(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 100))
	f.Add(makeRecord(userProcess, 1234, "alice", "pts/0", "192.168.1.10", 1700000000))
	f.Add(makeRecordTime64(userProcess, 1234, "probe", "pts/0", "192.168.5.2", 1700000000))
	f.Add(makeRecord(userProcess, 1234, "al\xffice", "pts/\xfe0", "192.168.\x801.10", 1700000000))
	f.Add(bytes.Repeat(makeRecord(userProcess, 1, "a", "pts/1", "h", 1), 25)) // fits both layouts

	f.Fuzz(func(t *testing.T, data []byte) {
		sessions, err := parseRecords(data)
		fits := len(data)%recordSize == 0 || len(data)%recordSizeTime64 == 0
		if fits != (err == nil) {
			t.Fatalf("len %d: err = %v", len(data), err)
		}
		if limit := len(data) / recordSize; len(sessions) > limit {
			t.Fatalf("%d sessions from at most %d records", len(sessions), limit)
		}
		for _, s := range sessions {
			if s.Host == "" {
				t.Fatalf("session without host: %+v", s)
			}
			// The fields become Prometheus label values, which must be
			// valid UTF-8; each replaced byte grows to at most 3 bytes.
			for _, field := range []struct {
				name  string
				value string
				size  int
			}{{"user", s.User, utNameSize}, {"tty", s.TTY, utLineSize}, {"host", s.Host, utHostSize}} {
				if !utf8.ValidString(field.value) {
					t.Fatalf("%s %q is not valid UTF-8", field.name, field.value)
				}
				if strings.IndexByte(field.value, 0) >= 0 || len(field.value) > 3*field.size {
					t.Fatalf("%s %q escapes its %d-byte field", field.name, field.value, field.size)
				}
			}
		}
	})
}

// FuzzParseRecordsRoundTrip writes n records in the native layout and checks
// that parsing returns exactly the SSH sessions among them, whatever n is.
func FuzzParseRecordsRoundTrip(f *testing.F) {
	f.Add(uint8(1), "alice", "pts/0", "192.168.1.10", int32(1700000000))
	f.Add(uint8(7), "bob", "pts/1", "2001:db8::1", int32(0))
	f.Add(uint8(25), "carol", "pts/2", "10.0.0.5", int32(-1)) // 9600 bytes fit both layouts

	f.Fuzz(func(t *testing.T, n uint8, user, tty, host string, sec int32) {
		user = cleanField(user, utNameSize)
		tty = cleanField(tty, utLineSize-4) // leave room for the suffix below
		host = cleanField(host, utHostSize)

		var data []byte
		var want []Session
		for i := range int32(n) {
			typ, h := int16(userProcess), host
			switch {
			case i%5 == 4:
				typ = deadProcess // logged out: not a session
			case i%4 == 3:
				h = "" // local login: not an SSH session
			}
			line := fmt.Sprintf("%s%d", tty, i)
			data = append(data, makeNativeRecord(typ, i+1, user, line, h, sec+i)...)
			if typ == userProcess && h != "" {
				want = append(want, Session{User: user, TTY: line, Host: h, PID: i + 1})
			}
		}

		got, err := parseRecords(data)
		if err != nil {
			t.Fatalf("%d records: %v", n, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%d records: got %d sessions, want %d", n, len(got), len(want))
		}
		for i := range want {
			g, w := got[i], want[i]
			if g.User != w.User || g.TTY != w.TTY || g.Host != w.Host || g.PID != w.PID {
				t.Fatalf("session %d: got %+v, want %+v", i, g, w)
			}
			if wantSec := int64(sec) + int64(w.PID-1); g.LoginTime.Unix() != wantSec {
				t.Fatalf("session %d: login time %d, want %d", i, g.LoginTime.Unix(), wantSec)
			}
		}
	})
}

// cleanField turns fuzz input into a value that a record field holds intact:
// valid UTF-8, without NUL, and short enough for the field.
func cleanField(s string, size int) string {
	s = strings.ReplaceAll(strings.ToValidUTF8(s, ""), "\x00", "")
	for len(s) > size {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

func TestParseRecords_LengthFittingBothLayouts(t *testing.T) {
	// 9600 bytes are 25 records of 384 bytes and 24 of 400 bytes.
	size := recordSize
	if nativeTime64 {
		size = recordSizeTime64
	}
	n := int32(9600 / size)
	var data []byte
	for i := range n {
		data = append(data, makeNativeRecord(userProcess, 1000+i, "alice", fmt.Sprintf("pts/%d", i), "192.0.2.1", 1700000000+i)...)
	}
	sessions, err := parseRecords(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != int(n) {
		t.Fatalf("expected %d sessions, got %d", n, len(sessions))
	}
	last := sessions[n-1]
	if last.PID != 1000+n-1 || last.TTY != fmt.Sprintf("pts/%d", n-1) || last.LoginTime.Unix() != int64(1700000000+n-1) {
		t.Errorf("unexpected last session: %+v", last)
	}
}

func TestParseRecords_ReplacesInvalidUTF8(t *testing.T) {
	sessions, err := parseRecords(makeRecord(userProcess, 1, "al\xffice", "pts/0", "192.0.2.\xfe1", 1700000000))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 1 || sessions[0].User != "al\uFFFDice" || sessions[0].Host != "192.0.2.\uFFFD1" {
		t.Errorf("expected invalid bytes replaced by U+FFFD, got %+v", sessions)
	}
}
