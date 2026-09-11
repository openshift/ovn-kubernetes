// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"strings"
	"sync"
)

// fakeRunner is a programmable api.Runner for tests. It records every call and
// returns canned output via a supplied responder. It also implements
// interface{ Close() error } so Close delegation can be verified.
type fakeRunner struct {
	mu     sync.Mutex
	calls  [][]string
	closed bool
	// respond returns (output, err) for a given (command, args). If nil, Run
	// returns ("", nil).
	respond func(command string, args []string) (string, error)
}

func (f *fakeRunner) Run(command string, args ...string) (string, error) {
	f.mu.Lock()
	call := append([]string{command}, args...)
	f.calls = append(f.calls, call)
	respond := f.respond
	f.mu.Unlock()
	if respond != nil {
		return respond(command, args)
	}
	return "", nil
}

func (f *fakeRunner) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// callStrings returns each recorded call joined by spaces, e.g. "docker exec x ip a".
func (f *fakeRunner) callStrings() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

// sawCall reports whether any recorded call joined by spaces equals want.
func (f *fakeRunner) sawCall(want string) bool {
	for _, c := range f.callStrings() {
		if c == want {
			return true
		}
	}
	return false
}

// firstIndexOf returns the index of the first recorded call (joined by spaces)
// equal to want, or -1. Useful for asserting relative ordering of calls.
func (f *fakeRunner) firstIndexOf(want string) int {
	for i, c := range f.callStrings() {
		if c == want {
			return i
		}
	}
	return -1
}

// containsArg reports whether args contains the exact token want.
func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
