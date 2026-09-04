// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		user        string
		key         string
		port        string
		runtime     string
		primaryNet  string
		wantErr     bool
		errContains string
		wantPort    string
		wantRuntime string
		wantPrimary string
	}{
		{
			name:        "minimal required with defaults",
			host:        "1.2.3.4",
			user:        "root",
			key:         "/path/key",
			wantPort:    "22",
			wantRuntime: "docker",
			wantPrimary: "kind",
		},
		{
			name:        "all fields explicit",
			host:        "host.example",
			user:        "core",
			key:         "/k",
			port:        "2222",
			runtime:     "podman",
			primaryNet:  "ostestbm_net",
			wantPort:    "2222",
			wantRuntime: "podman",
			wantPrimary: "ostestbm_net",
		},
		{
			name:        "missing host",
			user:        "root",
			key:         "/k",
			wantErr:     true,
			errContains: EnvHost,
		},
		{
			name:        "missing user",
			host:        "h",
			key:         "/k",
			wantErr:     true,
			errContains: EnvUser,
		},
		{
			name:        "missing key",
			host:        "h",
			user:        "root",
			wantErr:     true,
			errContains: EnvKey,
		},
		{
			name:        "invalid port",
			host:        "h",
			user:        "root",
			key:         "/k",
			port:        "70000",
			wantErr:     true,
			errContains: EnvPort,
		},
		{
			name:        "non-numeric port",
			host:        "h",
			user:        "root",
			key:         "/k",
			port:        "ssh",
			wantErr:     true,
			errContains: EnvPort,
		},
		{
			name:        "invalid runtime",
			host:        "h",
			user:        "root",
			key:         "/k",
			runtime:     "containerd",
			wantErr:     true,
			errContains: EnvContainerRuntime,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set every consumed env var so the dev machine's environment cannot
			// leak in; empty string means "unset" to ConfigFromEnv.
			t.Setenv(EnvHost, tt.host)
			t.Setenv(EnvUser, tt.user)
			t.Setenv(EnvKey, tt.key)
			t.Setenv(EnvPort, tt.port)
			t.Setenv(EnvContainerRuntime, tt.runtime)
			t.Setenv(EnvPrimaryNetwork, tt.primaryNet)

			cfg, err := ConfigFromEnv()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (cfg=%+v)", cfg)
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("error %q does not mention %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Host != tt.host || cfg.User != tt.user || cfg.PrivateKeyPath != tt.key {
				t.Fatalf("connection fields not preserved: %+v", cfg)
			}
			if cfg.Port != tt.wantPort {
				t.Errorf("port = %q, want %q", cfg.Port, tt.wantPort)
			}
			if cfg.Runtime != tt.wantRuntime {
				t.Errorf("runtime = %q, want %q", cfg.Runtime, tt.wantRuntime)
			}
			if cfg.PrimaryNetwork != tt.wantPrimary {
				t.Errorf("primaryNetwork = %q, want %q", cfg.PrimaryNetwork, tt.wantPrimary)
			}
		})
	}
}

func TestExpandHomeKeyPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "tilde slash expands", in: "~/.ssh/id_ed25519", want: filepath.Join(home, ".ssh/id_ed25519")},
		{name: "bare tilde expands to home", in: "~", want: home},
		{name: "absolute path untouched", in: "/etc/keys/id", want: "/etc/keys/id"},
		{name: "relative path untouched", in: "keys/id", want: "keys/id"},
		{name: "tilde user not expanded", in: "~other/id", want: "~other/id"},
		{name: "empty untouched", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expandHome(tt.in); got != tt.want {
				t.Fatalf("expandHome(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestConfigFromEnvExpandsKeyHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Set every consumed env var so the dev machine's environment cannot leak in.
	t.Setenv(EnvHost, "1.2.3.4")
	t.Setenv(EnvUser, "root")
	t.Setenv(EnvKey, "~/.ssh/id_ed25519")
	t.Setenv(EnvPort, "")
	t.Setenv(EnvContainerRuntime, "")
	t.Setenv(EnvPrimaryNetwork, "")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(home, ".ssh/id_ed25519")
	if cfg.PrivateKeyPath != want {
		t.Fatalf("PrivateKeyPath = %q, want %q", cfg.PrivateKeyPath, want)
	}
}

func TestConfigValidateAggregatesProblems(t *testing.T) {
	// Missing host, user and key at once should be reported together.
	cfg := Config{}
	cfg.applyDefaults()
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty config")
	}
	for _, want := range []string{EnvHost, EnvUser, EnvKey} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("aggregated error %q missing %q", err.Error(), want)
		}
	}
}
