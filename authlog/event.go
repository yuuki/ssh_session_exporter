package authlog

import "time"

// EventType represents the type of SSH auth event.
type EventType int

const (
	EventAuthFailure       EventType = iota
	EventAuthSuccess                 // Accepted password/publickey/...
	EventInvalidUser                 // Invalid user attempt
	EventPreauthDisconnect           // Disconnected before authentication completed
)

// AuthEvent represents a parsed SSH authentication event from the auth log.
type AuthEvent struct {
	Type      EventType
	User      string
	RemoteIP  string
	Method    string    // "password", "publickey", etc.
	PID       int32     // sshd process ID from sshd[PID]
	Timestamp time.Time // log line timestamp
}
