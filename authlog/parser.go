package authlog

import (
	"regexp"
	"strings"
)

// "Failed password for user from 192.168.1.1 port 22 ssh2"
// "Failed password for invalid user admin from 192.168.1.1 port 22 ssh2"
// "Failed keyboard-interactive for user from 192.168.1.1 port 22 ssh2"
var reFailedAuth = regexp.MustCompile(
	`sshd\[\d+\]: Failed ([\w-]+) for (?:invalid user )?(\S+) from (\S+) port (\d+)`,
)

// ParseLine parses a single auth log line and returns an AuthEvent if it
// matches an SSH authentication failure. Returns nil for non-matching lines.
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
		}
	}

	return nil
}
