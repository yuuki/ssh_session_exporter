package authlog

// EventType represents the type of SSH auth event.
type EventType int

const (
	EventAuthFailure EventType = iota
)

// AuthEvent represents a parsed SSH authentication failure from the auth log.
type AuthEvent struct {
	Type     EventType
	User     string
	RemoteIP string
	Method   string // "password", "publickey", etc.
}
