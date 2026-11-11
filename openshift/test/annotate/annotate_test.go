// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package annotate

import (
	"testing"

	"github.com/onsi/ginkgo/v2/types"
)

// fakeSpec is a minimal types.TestSpec for exercising the generator without
// building the Ginkgo tree.
type fakeSpec struct {
	text   string
	labels []string
}

func (f *fakeSpec) CodeLocations() []types.CodeLocation { return nil }
func (f *fakeSpec) Text() string                        { return f.text }
func (f *fakeSpec) AppendText(text string)              { f.text += text }
func (f *fakeSpec) Labels() []string                    { return f.labels }

func TestGenerateSuiteAssignment(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		labels      []string
		nameMatches map[string][]string
		want        string
	}{
		{
			name: "no serial marker goes to the parallel suite",
			text: "Feature does something",
			want: "[Suite:ovn-kubernetes/conformance/parallel]",
		},
		{
			name:   "Ginkgo Serial decorator label goes to the serial suite without a duplicate name marker",
			text:   "Feature restarts a component",
			labels: []string{"Feature:Example", "Serial"},
			want:   "[Suite:ovn-kubernetes/conformance/serial]",
		},
		{
			name:        "Serial name rule appends the marker and the serial suite",
			text:        "Feature restarts a component",
			nameMatches: map[string][]string{"[Serial]": {"Feature restarts"}},
			want:        "[Serial][Suite:ovn-kubernetes/conformance/serial]",
		},
		{
			name:   "Serial label on a conformance test goes to the minimal serial suite",
			text:   "Feature works [Conformance]",
			labels: []string{"Serial"},
			want:   "[Suite:ovn-kubernetes/conformance/serial/minimal]",
		},
		{
			name:        "disabled tests get no suite even with the Serial label",
			text:        "Feature is not implemented",
			labels:      []string{"Serial"},
			nameMatches: map[string][]string{"[Disabled:Unimplemented]": {"not implemented"}},
			want:        "[Disabled:Unimplemented]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newGenerator(tt.nameMatches, map[string][]string{})
			r.generate(tt.text, &fakeSpec{text: tt.text, labels: tt.labels})
			if got := r.output[tt.text]; got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
