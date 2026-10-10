package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The rendered config writes the banner as a TOML escape. Confirm the agent
// decodes it to a real CRLF -- if it arrived as a literal backslash-r the node
// would transmit four wrong bytes to every scanner that completes a handshake.
func TestBannerTOMLEscapeDecodes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.toml")
	os.WriteFile(p, []byte(`node_id = "t"
listen_ports = [8443]
log_path = "/tmp/x.jsonl"
capture_iface = "eth0"
banner = "\r\n"
`), 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Banner != "\r\n" {
		t.Fatalf("banner = %q, want %q", cfg.Banner, "\r\n")
	}
}

// never_bind replaced a hard-coded refusal to touch one specific port, which
// encoded a guess about what every host runs into software other people are
// expected to run. The guard still has to hold, so it is tested: a port in the
// list is refused, one merely near it is not, and an empty list blocks nothing.
func TestNeverBindRefusesListedPorts(t *testing.T) {
	base := "node_id = \"n\"\nlog_path = \"/tmp/m.jsonl\"\n"

	for _, tc := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"listed port refused", "listen_ports = [80, 9000]\nnever_bind = [9000]\n", true},
		{"unlisted port allowed", "listen_ports = [80, 9001]\nnever_bind = [9000]\n", false},
		{"empty list blocks nothing", "listen_ports = [22, 53, 9000]\n", false},
		{"ssh can be protected", "listen_ports = [22]\nnever_bind = [22, 9000]\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "agent.toml")
			if err := os.WriteFile(f, []byte(base+tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadConfig(f)
			if tc.wantErr && err == nil {
				t.Fatal("expected a refusal, got none")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
