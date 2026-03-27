package authlog

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// "Failed password for user from 192.168.1.1 port 22 ssh2"
	// "Failed keyboard-interactive/pam for user from 192.168.1.1 port 22 ssh2"
	reFailedAuth = regexp.MustCompile(
		`sshd\[(\d+)\]: Failed ([\w-]+(?:/\w+)*) for (?:invalid user )?(\S+) from (\S+) port (\d+)`,
	)
	// "Accepted publickey for alice from 192.168.1.10 port 54321 ssh2"
	// "Accepted keyboard-interactive/pam for alice from 192.168.1.10 port 22 ssh2"
	reAcceptedAuth = regexp.MustCompile(
		`sshd\[(\d+)\]: Accepted ([\w-]+(?:/\w+)*) for (\S+) from (\S+) port (\d+)`,
	)
	// "Invalid user admin from 10.0.0.5 port 22"
	reInvalidUser = regexp.MustCompile(
		`sshd\[(\d+)\]: Invalid user (\S+) from (\S+)`,
	)
	// "Disconnected from authenticating user root 10.0.0.1 port 22 [preauth]"
	// "Connection closed by authenticating user root 10.0.0.1 port 22 [preauth]"
	rePreauthDisconn = regexp.MustCompile(
		`sshd\[(\d+)\]: (?:Disconnected from|Connection closed by) authenticating user (\S+) (\S+) port \d+ \[preauth\]`,
	)
)

func parsePID(s string) int32 {
	n, _ := strconv.Atoi(s)
	return int32(n)
}

var reTimestamp = regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)

// parseTimestamp extracts the syslog timestamp from a log line.
// Auth log timestamps lack a year, so the current year is assumed.
func parseTimestamp(line string) time.Time {
	m := reTimestamp.FindStringSubmatch(line)
	if m == nil {
		return time.Time{}
	}
	t, err := time.Parse("Jan  2 15:04:05", m[1])
	if err != nil {
		// Try single-digit day with single space (e.g., "Jan 1 12:00:00").
		t, err = time.Parse("Jan 2 15:04:05", m[1])
		if err != nil {
			return time.Time{}
		}
	}
	now := time.Now()
	t = t.AddDate(now.Year(), 0, 0)
	// Handle year boundary: if parsed month is after current month,
	// the log line likely belongs to the previous year.
	if t.Month() > now.Month()+1 {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}

// ParseLine parses a single auth log line and returns an AuthEvent if it
// matches a recognised SSH authentication pattern. Returns nil for non-matching lines.
func ParseLine(line string) *AuthEvent {
	if !strings.Contains(line, "sshd[") {
		return nil
	}

	if m := reFailedAuth.FindStringSubmatch(line); m != nil {
		return &AuthEvent{
			Type:      EventAuthFailure,
			PID:       parsePID(m[1]),
			Method:    m[2],
			User:      m[3],
			RemoteIP:  m[4],
			Timestamp: parseTimestamp(line),
		}
	}

	if m := reAcceptedAuth.FindStringSubmatch(line); m != nil {
		return &AuthEvent{
			Type:      EventAuthSuccess,
			PID:       parsePID(m[1]),
			Method:    m[2],
			User:      m[3],
			RemoteIP:  m[4],
			Timestamp: parseTimestamp(line),
		}
	}

	if m := reInvalidUser.FindStringSubmatch(line); m != nil {
		return &AuthEvent{
			Type:      EventInvalidUser,
			PID:       parsePID(m[1]),
			User:      m[2],
			RemoteIP:  m[3],
			Timestamp: parseTimestamp(line),
		}
	}

	if m := rePreauthDisconn.FindStringSubmatch(line); m != nil {
		return &AuthEvent{
			Type:      EventPreauthDisconnect,
			PID:       parsePID(m[1]),
			User:      m[2],
			RemoteIP:  m[3],
			Timestamp: parseTimestamp(line),
		}
	}

	return nil
}
