package authlog

// EventType represents the type of SSH auth event.
type EventType int

const (
	// EventAuthFailure indicates a failed authentication attempt.
	EventAuthFailure EventType = iota
	// EventAuthSuccess indicates a successful authentication.
	EventAuthSuccess
	// EventDisconnect indicates a session disconnect.
	EventDisconnect
)

// AuthEvent represents a parsed SSH authentication event from the auth log.
type AuthEvent struct {
	Type     EventType
	User     string
	RemoteIP string
	Port     string
	Method   string // "password", "publickey", etc.
}
