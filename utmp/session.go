package utmp

import "time"

// Session represents a single active SSH session.
type Session struct {
	User      string
	TTY       string
	Host      string
	LoginTime time.Time
	PID       int32
}

// Reader reads active SSH sessions.
type Reader interface {
	ReadSessions() ([]Session, error)
}
