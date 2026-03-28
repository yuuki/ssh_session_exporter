package authlog

import (
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantType EventType
		wantUser string
		wantIP   string
		wantMeth string
		wantPID  int32
		wantNil  bool
	}{
		// --- EventAuthFailure ---
		{
			name:     "failed password",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 192.168.1.10 port 22 ssh2`,
			wantType: EventAuthFailure,
			wantUser: "alice",
			wantIP:   "192.168.1.10",
			wantMeth: "password",
			wantPID:  1234,
		},
		{
			name:     "failed password invalid user",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 49876 ssh2`,
			wantType: EventAuthFailure,
			wantUser: "admin",
			wantIP:   "10.0.0.5",
			wantMeth: "password",
			wantPID:  1234,
		},
		{
			name:     "failed publickey",
			line:     `Jan  1 12:00:00 server sshd[5678]: Failed publickey for bob from 172.16.0.1 port 54321 ssh2`,
			wantType: EventAuthFailure,
			wantUser: "bob",
			wantIP:   "172.16.0.1",
			wantMeth: "publickey",
			wantPID:  5678,
		},
		{
			name:     "failed keyboard-interactive",
			line:     `Jan  1 12:00:00 server sshd[9999]: Failed keyboard-interactive for alice from 10.0.0.1 port 22 ssh2`,
			wantType: EventAuthFailure,
			wantUser: "alice",
			wantIP:   "10.0.0.1",
			wantMeth: "keyboard-interactive",
			wantPID:  9999,
		},
		{
			name:     "failed ipv6 address",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 2001:db8::1 port 22 ssh2`,
			wantType: EventAuthFailure,
			wantUser: "alice",
			wantIP:   "2001:db8::1",
			wantMeth: "password",
			wantPID:  1234,
		},
		{
			name:     "failed keyboard-interactive/pam",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed keyboard-interactive/pam for alice from 10.0.0.1 port 22 ssh2`,
			wantType: EventAuthFailure,
			wantUser: "alice",
			wantIP:   "10.0.0.1",
			wantMeth: "keyboard-interactive/pam",
			wantPID:  1234,
		},
		// --- EventAuthSuccess ---
		{
			name:     "accepted password",
			line:     `Jan  1 12:00:00 server sshd[2001]: Accepted password for alice from 192.168.1.10 port 22 ssh2`,
			wantType: EventAuthSuccess,
			wantUser: "alice",
			wantIP:   "192.168.1.10",
			wantMeth: "password",
			wantPID:  2001,
		},
		{
			name:     "accepted publickey",
			line:     `Jan  1 12:00:00 server sshd[2002]: Accepted publickey for bob from 172.16.0.1 port 54321 ssh2`,
			wantType: EventAuthSuccess,
			wantUser: "bob",
			wantIP:   "172.16.0.1",
			wantMeth: "publickey",
			wantPID:  2002,
		},
		{
			name:     "accepted keyboard-interactive",
			line:     `Jan  1 12:00:00 server sshd[2003]: Accepted keyboard-interactive for carol from 10.0.0.1 port 22 ssh2`,
			wantType: EventAuthSuccess,
			wantUser: "carol",
			wantIP:   "10.0.0.1",
			wantMeth: "keyboard-interactive",
			wantPID:  2003,
		},
		{
			name:     "accepted keyboard-interactive/pam",
			line:     `Jan  1 12:00:00 server sshd[2004]: Accepted keyboard-interactive/pam for carol from 10.0.0.1 port 22 ssh2`,
			wantType: EventAuthSuccess,
			wantUser: "carol",
			wantIP:   "10.0.0.1",
			wantMeth: "keyboard-interactive/pam",
			wantPID:  2004,
		},
		// --- EventInvalidUser ---
		{
			name:     "invalid user",
			line:     `Jan  1 12:00:00 server sshd[3001]: Invalid user admin from 10.0.0.5 port 22`,
			wantType: EventInvalidUser,
			wantUser: "admin",
			wantIP:   "10.0.0.5",
			wantPID:  3001,
		},
		{
			name:     "invalid user ipv6",
			line:     `Jan  1 12:00:00 server sshd[3002]: Invalid user test from 2001:db8::1 port 22`,
			wantType: EventInvalidUser,
			wantUser: "test",
			wantIP:   "2001:db8::1",
			wantPID:  3002,
		},
		// --- EventPreauthDisconnect ---
		{
			name:     "preauth disconnected from",
			line:     `Jan  1 12:00:00 server sshd[4001]: Disconnected from authenticating user root 10.0.0.1 port 22 [preauth]`,
			wantType: EventPreauthDisconnect,
			wantUser: "root",
			wantIP:   "10.0.0.1",
			wantPID:  4001,
		},
		{
			name:     "preauth connection closed by",
			line:     `Jan  1 12:00:00 server sshd[4002]: Connection closed by authenticating user alice 192.168.1.10 port 54321 [preauth]`,
			wantType: EventPreauthDisconnect,
			wantUser: "alice",
			wantIP:   "192.168.1.10",
			wantPID:  4002,
		},
		// --- nil cases ---
		{
			name:    "disconnect without preauth is ignored",
			line:    `Jan  1 12:05:00 server sshd[1234]: Disconnected from user alice 192.168.1.10 port 22`,
			wantNil: true,
		},
		{
			name:    "connection closed without preauth is ignored",
			line:    `Jan  1 12:05:00 server sshd[1234]: Connection closed by 10.0.0.5 port 54321`,
			wantNil: true,
		},
		{
			name:    "non-sshd line",
			line:    `Jan  1 12:00:00 server systemd[1]: Started Session 1 of user alice.`,
			wantNil: true,
		},
		{
			name:    "empty line",
			line:    ``,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := ParseLine(tt.line)

			if tt.wantNil {
				if event != nil {
					t.Fatalf("expected nil, got %+v", event)
				}
				return
			}

			if event == nil {
				t.Fatal("expected non-nil event, got nil")
			}
			if event.Type != tt.wantType {
				t.Errorf("Type = %d, want %d", event.Type, tt.wantType)
			}
			if event.User != tt.wantUser {
				t.Errorf("User = %q, want %q", event.User, tt.wantUser)
			}
			if event.RemoteIP != tt.wantIP {
				t.Errorf("RemoteIP = %q, want %q", event.RemoteIP, tt.wantIP)
			}
			if event.Method != tt.wantMeth {
				t.Errorf("Method = %q, want %q", event.Method, tt.wantMeth)
			}
			if event.PID != tt.wantPID {
				t.Errorf("PID = %d, want %d", event.PID, tt.wantPID)
			}
		})
	}
}

func TestParseLine_Timestamp(t *testing.T) {
	line := `Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 192.168.1.10 port 22 ssh2`
	event := ParseLine(line)
	if event == nil {
		t.Fatal("expected non-nil event")
	}
	if event.Timestamp.IsZero() {
		t.Fatal("expected non-zero timestamp")
	}
	if event.Timestamp.Month() != time.January || event.Timestamp.Day() != 1 {
		t.Errorf("Timestamp month/day = %v/%v, want January/1", event.Timestamp.Month(), event.Timestamp.Day())
	}
	if event.Timestamp.Hour() != 12 || event.Timestamp.Minute() != 0 || event.Timestamp.Second() != 0 {
		t.Errorf("Timestamp time = %02d:%02d:%02d, want 12:00:00",
			event.Timestamp.Hour(), event.Timestamp.Minute(), event.Timestamp.Second())
	}
}

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantZero bool
		wantMon  time.Month
		wantDay  int
	}{
		{
			name:    "standard syslog format",
			line:    "Mar 27 09:15:30 server sshd[1234]: something",
			wantMon: time.March,
			wantDay: 27,
		},
		{
			name:    "single digit day with double space",
			line:    "Jan  1 12:00:00 server sshd[1234]: something",
			wantMon: time.January,
			wantDay: 1,
		},
		{
			name:     "no timestamp",
			line:     "no timestamp here",
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := parseTimestamp(tt.line)
			if tt.wantZero {
				if !ts.IsZero() {
					t.Errorf("expected zero time, got %v", ts)
				}
				return
			}
			if ts.IsZero() {
				t.Fatal("expected non-zero time")
			}
			if ts.Month() != tt.wantMon {
				t.Errorf("Month = %v, want %v", ts.Month(), tt.wantMon)
			}
			if ts.Day() != tt.wantDay {
				t.Errorf("Day = %d, want %d", ts.Day(), tt.wantDay)
			}
		})
	}
}

func TestParseTimestamp_UsesLocalTimezone(t *testing.T) {
	originalLocal := time.Local
	time.Local = time.FixedZone("JST", 9*60*60)
	t.Cleanup(func() {
		time.Local = originalLocal
	})

	ts := parseTimestamp("Mar 28 16:48:13 server sshd[1234]: something")
	if ts.IsZero() {
		t.Fatal("expected non-zero time")
	}

	if got, want := ts.Location(), time.Local; got != want {
		t.Fatalf("Location = %v, want %v", got, want)
	}

	want := time.Date(ts.Year(), time.March, 28, 16, 48, 13, 0, time.Local)
	if !ts.Equal(want) {
		t.Fatalf("Timestamp = %v, want %v", ts, want)
	}
}
