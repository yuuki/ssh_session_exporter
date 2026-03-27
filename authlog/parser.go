package authlog

import (
	"regexp"
	"strings"
)

var (
	// "Failed password for user from 192.168.1.1 port 22 ssh2"
	// "Failed password for invalid user admin from 192.168.1.1 port 22 ssh2"
	reFailedAuth = regexp.MustCompile(
		`sshd\[\d+\]: Failed ([\w-]+) for (?:invalid user )?(\S+) from (\S+) port (\d+)`,
	)

	// "Accepted publickey for user from 192.168.1.1 port 22 ssh2"
	// "Accepted keyboard-interactive for user from 192.168.1.1 port 22 ssh2"
	reAcceptedAuth = regexp.MustCompile(
		`sshd\[\d+\]: Accepted ([\w-]+) for (\S+) from (\S+) port (\d+)`,
	)

	// "Disconnected from user root 192.168.1.1 port 22"
	// "Disconnected from 192.168.1.1 port 22"
	reDisconnectedFrom = regexp.MustCompile(
		`sshd\[\d+\]: Disconnected from (?:user (\S+) )?(\S+) port (\d+)`,
	)

	// "Connection closed by 192.168.1.1 port 22"
	// "Connection closed by authenticating user root 192.168.1.1 port 22"
	reConnectionClosed = regexp.MustCompile(
		`sshd\[\d+\]: Connection closed by (?:authenticating user (\S+) )?(\S+) port (\d+)`,
	)
)

// ParseLine parses a single auth log line and returns an AuthEvent if it
// matches an SSH-related pattern. Returns nil if the line is not relevant.
func ParseLine(line string) *AuthEvent {
	if !strings.Contains(line, "sshd[") {
		return nil
	}

	if m := reFailedAuth.FindStringSubmatch(line); m != nil {
		return &AuthEvent{
			Type:     EventAuthFailure,
			Method:   m[1],
			User:     m[2],
			RemoteIP: m[3],
			Port:     m[4],
		}
	}

	if m := reAcceptedAuth.FindStringSubmatch(line); m != nil {
		return &AuthEvent{
			Type:     EventAuthSuccess,
			Method:   m[1],
			User:     m[2],
			RemoteIP: m[3],
			Port:     m[4],
		}
	}

	if m := reDisconnectedFrom.FindStringSubmatch(line); m != nil {
		return &AuthEvent{
			Type:     EventDisconnect,
			User:     m[1], // may be empty
			RemoteIP: m[2],
			Port:     m[3],
		}
	}

	if m := reConnectionClosed.FindStringSubmatch(line); m != nil {
		return &AuthEvent{
			Type:     EventDisconnect,
			User:     m[1], // may be empty
			RemoteIP: m[2],
			Port:     m[3],
		}
	}

	return nil
}
