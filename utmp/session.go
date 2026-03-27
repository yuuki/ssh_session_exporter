package utmp

import "time"

type Session struct {
	User      string
	TTY       string
	Host      string
	LoginTime time.Time
	PID       int32
}

type Reader interface {
	ReadSessions() ([]Session, error)
}
