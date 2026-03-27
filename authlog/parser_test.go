package authlog

import "testing"

func TestParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantUser string
		wantIP   string
		wantMeth string
		wantNil  bool
	}{
		{
			name:     "failed password",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 192.168.1.10 port 22 ssh2`,
			wantUser: "alice",
			wantIP:   "192.168.1.10",
			wantMeth: "password",
		},
		{
			name:     "failed password invalid user",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 49876 ssh2`,
			wantUser: "admin",
			wantIP:   "10.0.0.5",
			wantMeth: "password",
		},
		{
			name:     "failed publickey",
			line:     `Jan  1 12:00:00 server sshd[5678]: Failed publickey for bob from 172.16.0.1 port 54321 ssh2`,
			wantUser: "bob",
			wantIP:   "172.16.0.1",
			wantMeth: "publickey",
		},
		{
			name:     "failed keyboard-interactive",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed keyboard-interactive for alice from 10.0.0.1 port 22 ssh2`,
			wantUser: "alice",
			wantIP:   "10.0.0.1",
			wantMeth: "keyboard-interactive",
		},
		{
			name:     "ipv6 address",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 2001:db8::1 port 22 ssh2`,
			wantUser: "alice",
			wantIP:   "2001:db8::1",
			wantMeth: "password",
		},
		{
			name:    "accepted auth is ignored",
			line:    `Jan  1 12:00:00 server sshd[1234]: Accepted password for alice from 192.168.1.10 port 22 ssh2`,
			wantNil: true,
		},
		{
			name:    "disconnect is ignored",
			line:    `Jan  1 12:05:00 server sshd[1234]: Disconnected from user alice 192.168.1.10 port 22`,
			wantNil: true,
		},
		{
			name:    "connection closed is ignored",
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
			if event.Type != EventAuthFailure {
				t.Errorf("Type = %d, want EventAuthFailure", event.Type)
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
		})
	}
}
