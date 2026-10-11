// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"path/filepath"
	"strings"
	"testing"
)

func clearConfigEnv(t *testing.T) {
	t.Setenv(EnvHost, "")
	t.Setenv(EnvUser, "")
	t.Setenv(EnvKey, "")
	t.Setenv(EnvPort, "")
	t.Setenv(EnvContainerRuntime, "")
	t.Setenv(EnvPrimaryNetwork, "")
	t.Setenv(EnvNodeExecutor, "")
	t.Setenv(EnvKnownHosts, "")
	t.Setenv(EnvInsecureHostKey, "")
}

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
			clearConfigEnv(t)
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
	clearConfigEnv(t)
	t.Setenv(EnvHost, "1.2.3.4")
	t.Setenv(EnvUser, "root")
	t.Setenv(EnvKey, "~/.ssh/id_ed25519")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(home, ".ssh/id_ed25519")
	if cfg.PrivateKeyPath != want {
		t.Fatalf("PrivateKeyPath = %q, want %q", cfg.PrivateKeyPath, want)
	}
}

func TestValidateSSHHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{name: "ipv4", host: "1.2.3.4"},
		{name: "hostname", host: "host.example"},
		{name: "ipv6", host: "2001:db8::1"},
		{name: "ipv6 loopback", host: "::1"},
		{name: "embedded port", host: "host.example:2222", wantErr: true},
		{name: "ipv4 embedded port", host: "1.2.3.4:22", wantErr: true},
		{name: "bracketed ipv6 with port", host: "[::1]:2222", wantErr: true},
		{name: "bracketed ipv6 without port", host: "[::1]", wantErr: true},
		{name: "host with non-numeric port suffix", host: "host.example:ssh", wantErr: true},
		{name: "malformed ipv6 with colon", host: "not-an-ip::bad", wantErr: true},
		{name: "newline suffix", host: "host.example\nsuffix", wantErr: true},
		{name: "scheme", host: "ssh://host.example", wantErr: true},
		{name: "trailing colon", host: "host.example:", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Host: tt.host, User: "root", PrivateKeyPath: "/k"}
			cfg.applyDefaults()
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected validation error")
				}
				if !strings.Contains(err.Error(), EnvHost) {
					t.Fatalf("error %q should mention %s", err.Error(), EnvHost)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
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

func TestIsLocalHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "::1", " LOCALHOST "} {
		if !IsLocalHost(host) {
			t.Fatalf("IsLocalHost(%q) = false, want true", host)
		}
	}
	if IsLocalHost("10.0.0.1") {
		t.Fatal("remote host should not be local")
	}
}

func TestConfigNodeExecutorModeInvalid(t *testing.T) {
	clearConfigEnv(t)
	cfg := Config{
		Host:             "host",
		User:             "root",
		PrivateKeyPath:   "/k",
		NodeExecutorMode: "ssh",
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for unsupported node executor mode")
	}
}

func TestConfigFromEnvSecurityFields(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv(EnvHost, "host.example")
	t.Setenv(EnvUser, "root")
	t.Setenv(EnvKey, "/k")
	t.Setenv(EnvKnownHosts, "/tmp/known_hosts")
	t.Setenv(EnvInsecureHostKey, "1")
	t.Setenv(EnvNodeExecutor, "container")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.KnownHostsPath != "/tmp/known_hosts" {
		t.Fatalf("KnownHostsPath = %q", cfg.KnownHostsPath)
	}
	if !cfg.InsecureHostKey {
		t.Fatal("expected InsecureHostKey")
	}
	if cfg.NodeExecutorMode != "container" {
		t.Fatalf("NodeExecutorMode = %q", cfg.NodeExecutorMode)
	}
}
