package authlog

import "testing"

func TestParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantType EventType
		wantUser string
		wantIP   string
		wantMeth string
		wantPort string
		wantNil  bool
	}{
		{
			name:     "failed password",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 192.168.1.10 port 22 ssh2`,
			wantType: EventAuthFailure,
			wantUser: "alice",
			wantIP:   "192.168.1.10",
			wantMeth: "password",
			wantPort: "22",
		},
		{
			name:     "failed password invalid user",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 49876 ssh2`,
			wantType: EventAuthFailure,
			wantUser: "admin",
			wantIP:   "10.0.0.5",
			wantMeth: "password",
			wantPort: "49876",
		},
		{
			name:     "failed publickey",
			line:     `Jan  1 12:00:00 server sshd[5678]: Failed publickey for bob from 172.16.0.1 port 54321 ssh2`,
			wantType: EventAuthFailure,
			wantUser: "bob",
			wantIP:   "172.16.0.1",
			wantMeth: "publickey",
			wantPort: "54321",
		},
		{
			name:     "accepted password",
			line:     `Jan  1 12:00:00 server sshd[1234]: Accepted password for alice from 192.168.1.10 port 22 ssh2`,
			wantType: EventAuthSuccess,
			wantUser: "alice",
			wantIP:   "192.168.1.10",
			wantMeth: "password",
			wantPort: "22",
		},
		{
			name:     "accepted publickey",
			line:     `Jan  1 12:00:00 server sshd[5678]: Accepted publickey for bob from 10.0.0.5 port 12345 ssh2`,
			wantType: EventAuthSuccess,
			wantUser: "bob",
			wantIP:   "10.0.0.5",
			wantMeth: "publickey",
			wantPort: "12345",
		},
		{
			name:     "disconnected from with user",
			line:     `Jan  1 12:05:00 server sshd[1234]: Disconnected from user alice 192.168.1.10 port 22`,
			wantType: EventDisconnect,
			wantUser: "alice",
			wantIP:   "192.168.1.10",
			wantPort: "22",
		},
		{
			name:     "disconnected from without user",
			line:     `Jan  1 12:05:00 server sshd[1234]: Disconnected from 192.168.1.10 port 22`,
			wantType: EventDisconnect,
			wantUser: "",
			wantIP:   "192.168.1.10",
			wantPort: "22",
		},
		{
			name:     "connection closed",
			line:     `Jan  1 12:05:00 server sshd[1234]: Connection closed by 10.0.0.5 port 54321`,
			wantType: EventDisconnect,
			wantUser: "",
			wantIP:   "10.0.0.5",
			wantPort: "54321",
		},
		{
			name:     "connection closed authenticating user",
			line:     `Jan  1 12:05:00 server sshd[1234]: Connection closed by authenticating user root 10.0.0.5 port 22`,
			wantType: EventDisconnect,
			wantUser: "root",
			wantIP:   "10.0.0.5",
			wantPort: "22",
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
		{
			name:     "ipv6 address",
			line:     `Jan  1 12:00:00 server sshd[1234]: Failed password for alice from 2001:db8::1 port 22 ssh2`,
			wantType: EventAuthFailure,
			wantUser: "alice",
			wantIP:   "2001:db8::1",
			wantMeth: "password",
			wantPort: "22",
		},
		{
			name:     "accepted keyboard-interactive",
			line:     `Jan  1 12:00:00 server sshd[1234]: Accepted keyboard-interactive for alice from 10.0.0.1 port 22 ssh2`,
			wantType: EventAuthSuccess,
			wantUser: "alice",
			wantIP:   "10.0.0.1",
			wantMeth: "keyboard-interactive",
			wantPort: "22",
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
			if event.Type != tt.wantType {
				t.Errorf("Type = %d, want %d", event.Type, tt.wantType)
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
			if event.Port != tt.wantPort {
				t.Errorf("Port = %q, want %q", event.Port, tt.wantPort)
			}
		})
	}
}
