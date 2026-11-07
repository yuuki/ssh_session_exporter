package authlog

import (
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// asciiSpace is what RE2's \s matches; the \S+ captures never contain it.
const asciiSpace = " \t\n\f\r"

var reMethod = regexp.MustCompile(`^[\w-]+(?:/\w+)*$`)

// Remote clients choose the user names sshd logs, and local users can write
// arbitrary lines through syslog(3), so ParseLine sees untrusted input.
func FuzzParseLine(f *testing.F) {
	for _, line := range []string{
		"Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 192.168.1.10 port 22 ssh2",
		"Jan  1 12:00:00 server sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 49876 ssh2",
		"Jan  1 12:00:00 server sshd[1234]: Failed keyboard-interactive/pam for alice from 2001:db8::1 port 22 ssh2",
		"Jan  1 12:00:00 server sshd-auth[8123]: Failed password for alice from 192.168.1.10 port 22 ssh2",
		"Sep  2 05:06:41 localhost sshd-session[15424]: Accepted publickey for probe from 192.168.5.2 port 59614 ssh2",
		"Jan  1 12:00:00 server sshd[3001]: Invalid user admin from 10.0.0.5 port 22",
		"Jan  1 12:00:00 server sshd[4002]: Connection closed by authenticating user alice 192.168.1.10 port 54321 [preauth]",
		"Jan  1 12:00:00 server sshd[4001]: Disconnected from authenticating user root 10.0.0.1 port 22 [preauth]",
		"Jan  1 12:05:00 server sshd[1234]: Connection closed by 10.0.0.5 port 54321",
		"Jan  1 12:00:00 server systemd[1]: Started Session 1 of user alice.",
		"Jan  1 12:00:00 server sshd[1234]: Invalid user ad\xffmin from 10.0.0.5 port 22",
		"Feb 30 12:00:00 server sshd[99999999999]: Invalid user x from y",
		"",
	} {
		f.Add(line)
	}
	year := time.Now().Year()

	f.Fuzz(func(t *testing.T, line string) {
		event := ParseLine(line)
		if event == nil {
			return
		}
		if event.Type < EventAuthFailure || event.Type > EventPreauthDisconnect {
			t.Fatalf("unknown event type %d", event.Type)
		}
		// Every field becomes a Prometheus label value: client_golang
		// panics on invalid UTF-8.
		for name, v := range map[string]string{"user": event.User, "remote_ip": event.RemoteIP, "method": event.Method} {
			if !utf8.ValidString(v) {
				t.Fatalf("%s %q is not valid UTF-8", name, v)
			}
			if strings.ContainsAny(v, asciiSpace) {
				t.Fatalf("%s %q contains white space", name, v)
			}
		}
		if event.User == "" || event.RemoteIP == "" {
			t.Fatalf("empty identity in %+v", event)
		}
		switch event.Type {
		case EventAuthFailure, EventAuthSuccess:
			if !reMethod.MatchString(event.Method) {
				t.Fatalf("method %q is not an auth method", event.Method)
			}
		default:
			if event.Method != "" {
				t.Fatalf("method %q set on event type %d", event.Method, event.Type)
			}
		}
		if ts := event.Timestamp; !ts.IsZero() && ts.Year() != year && ts.Year() != year-1 {
			t.Fatalf("timestamp %v is neither this year nor the last", ts)
		}
	})
}

// splitLines carries partial lines between reads, so it must never lose or
// invent bytes.
func FuzzSplitLines(f *testing.F) {
	f.Add("")
	f.Add("no newline")
	f.Add("one\n")
	f.Add("a\nb\npartial")
	f.Add("\n\n\n")
	f.Fuzz(func(t *testing.T, text string) {
		lines, partial := splitLines(text)
		if got := strings.Join(append(lines, partial), "\n"); got != text {
			t.Fatalf("lines and partial rejoin to %q, want %q", got, text)
		}
		if got, want := len(lines), strings.Count(text, "\n"); got != want {
			t.Fatalf("%d complete lines, want %d", got, want)
		}
		if strings.Contains(partial, "\n") {
			t.Fatalf("partial %q contains a newline", partial)
		}
	})
}

func TestParseLine_ReplacesInvalidUTF8(t *testing.T) {
	event := ParseLine("Jan  1 12:00:00 server sshd[3001]: Invalid user ad\xffmin from 10.0.0.\xfe5 port 22")
	if event == nil {
		t.Fatal("expected an event")
	}
	if event.User != "ad\uFFFDmin" || event.RemoteIP != "10.0.0.\uFFFD5" {
		t.Errorf("got user %q remote_ip %q, want invalid bytes replaced by U+FFFD", event.User, event.RemoteIP)
	}
}
