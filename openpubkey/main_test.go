package main

import "testing"

func TestParseUpstream(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort int
		wantUser string
	}{
		{
			name:     "user with port",
			input:    "alice@example.com:2222",
			wantHost: "example.com",
			wantPort: 2222,
			wantUser: "alice",
		},
		{
			name:     "host with port only",
			input:    "example.net:2200",
			wantHost: "example.net",
			wantPort: 2200,
			wantUser: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parseUpstream(tt.input)
			if err != nil {
				t.Fatalf("parseUpstream() error = %v", err)
			}

			if info.Host != tt.wantHost || info.Port != tt.wantPort || info.User != tt.wantUser {
				t.Fatalf("parseUpstream() = (%q, %d, %q), want (%q, %d, %q)",
					info.Host, info.Port, info.User, tt.wantHost, tt.wantPort, tt.wantUser)
			}
		})
	}
}
