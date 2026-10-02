package infraprovider

import (
	"errors"
	"testing"
)

type fakeRunner struct {
	calls [][]string
	// existsErr is returned by "podman network exists"; nil means it exists.
	existsErr error
}

func (f *fakeRunner) Run(command string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{command}, args...))
	if len(args) >= 2 && args[0] == "network" && args[1] == "exists" {
		return "", f.existsErr
	}
	return "", nil
}

func TestEnsurePrimaryNetworkExists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		existsErr  error
		wantCalls  int
		wantCreate bool
	}{
		{name: "network already exists: no create call", existsErr: nil, wantCalls: 1, wantCreate: false},
		{name: "network missing: creates it bound to the bridge", existsErr: errors.New("network not found"), wantCalls: 2, wantCreate: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &fakeRunner{existsErr: tc.existsErr}
			if err := ensurePrimaryNetworkExists(r); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(r.calls) != tc.wantCalls {
				t.Fatalf("calls: got %d, want %d (%v)", len(r.calls), tc.wantCalls, r.calls)
			}
			if tc.wantCreate && r.calls[1][2] != "create" {
				t.Fatalf("expected second call to be a create, got: %v", r.calls[1])
			}
		})
	}
}
