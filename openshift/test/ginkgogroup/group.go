// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Package ginkgogroup runs reviewed specs of one upstream Ginkgo Ordered
// container as a single OTE test.
//
// The pinned openshift-tests-extension runs every Ginkgo spec on its own: its
// Run hands one spec to the OpenShift Ginkgo fork's Suite.RunSpec, which calls
// runSpecs with that spec only. The BeforeAll, AfterAll and DeferCleanup nodes
// of an Ordered container then run around each spec, and specs that build on
// the state left by the ones declared before them do not test what they
// claim. Once OTE has built the Ginkgo tree, neither OTE nor the fork offers a
// way to run several specs in one Ginkgo run, so a Group re-executes the
// binary and runs its members there with a native ginkgo.RunSpecs call,
// focused on exactly those members. Ginkgo then owns the setup, the order of
// the specs and the cleanup.
package ginkgogroup

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	ext "github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	oteginkgo "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/openshift-eng/openshift-tests-extension/pkg/util/sets"
)

const (
	// disabledAnnotation prefixes the annotations that disable a test, see
	// openshift/test/annotate/rules.go.
	disabledAnnotation = "[Disabled:"
	// defaultTimeout is the timeout OTE's SpawnProcessToRunTest applies when
	// a spec sets none.
	defaultTimeout = 90 * time.Minute
)

// Group is a reviewed selection of the specs of one upstream Ordered
// container.
type Group struct {
	// Container is the text Ginkgo gives the Ordered container: the texts of
	// the container and its ancestors joined by spaces, leaving out empty ones.
	Container string
	// Members are the leaf texts of the specs that run in the group, in
	// declaration order.
	Members []string
	// Excluded are the leaf texts of the other specs of the container. They
	// must be disabled in the catalog and stay individual OTE tests.
	Excluded []string
}

// Collect replaces the members of the group in specs by a single spec that
// runs them in one Ginkgo run, at the position of the first member. specs
// must come straight from the Ginkgo tree, before OTE renames them.
// annotations maps a spec text to the annotations OTE appends to its name,
// see openshift/test/generated.
//
// Collect fails unless the container holds exactly the reviewed specs: the
// members in declaration order plus the excluded specs, all disabled. The
// members must not be disabled, and must carry the same labels and
// annotations, and no spec outside the container may have the name of one of
// its specs. Upstream changes to the container therefore stop the catalog from
// building until the group is reviewed again.
func (g Group) Collect(specs ext.ExtensionTestSpecs, annotations map[string]string) (ext.ExtensionTestSpecs, error) {
	if len(g.Members) == 0 {
		return nil, fmt.Errorf("group %q has no members", g.Container)
	}
	prefix := g.specText("")

	// The container is identified by the nodes of its first member, not by
	// its text: other containers can have texts starting with the same words.
	// Those are the nodes before the leaf: the containers and their setup
	// nodes. Ginkgo puts the setup nodes declared after a spec behind its leaf,
	// so a container declaring some after its specs fails to collect.
	anchor := slices.IndexFunc(specs, func(spec *ext.ExtensionTestSpec) bool {
		return spec.Name == g.specText(g.Members[0])
	})
	if anchor < 0 {
		return nil, fmt.Errorf("group %q: spec %q not found", g.Container, g.specText(g.Members[0]))
	}
	containerNodes := specs[anchor].CodeLocations[:len(specs[anchor].CodeLocations)-1]
	inContainer := func(spec *ext.ExtensionTestSpec) bool {
		return len(spec.CodeLocations) > len(containerNodes) && slices.Equal(spec.CodeLocations[:len(containerNodes)], containerNodes)
	}

	excluded := sets.New(g.Excluded...)
	foundExcluded := sets.New[string]()
	var members ext.ExtensionTestSpecs
	var leaves []string
	collected := make(ext.ExtensionTestSpecs, 0, len(specs))
	first := -1
	for _, spec := range specs {
		leaf, ok := strings.CutPrefix(spec.Name, prefix)
		if !inContainer(spec) {
			// The group runs its members by name.
			if ok && (slices.Contains(g.Members, leaf) || excluded.Has(leaf)) {
				return nil, fmt.Errorf("group %q: spec %q is outside the container but has the name of one of its specs", g.Container, spec.Name)
			}
			collected = append(collected, spec)
			continue
		}
		if !ok {
			return nil, fmt.Errorf("group %q: spec %q is in the container but does not start with its text", g.Container, spec.Name)
		}
		if excluded.Has(leaf) {
			if foundExcluded.Has(leaf) {
				return nil, fmt.Errorf("group %q: excluded spec %q appears more than once", g.Container, leaf)
			}
			foundExcluded.Insert(leaf)
			if !strings.Contains(annotations[spec.Name], disabledAnnotation) {
				return nil, fmt.Errorf("group %q: excluded spec %q is not disabled: review the group membership", g.Container, leaf)
			}
			collected = append(collected, spec)
			continue
		}
		if first < 0 {
			first = len(collected)
			collected = append(collected, nil)
		}
		members = append(members, spec)
		leaves = append(leaves, leaf)
	}
	if !slices.Equal(leaves, g.Members) {
		return nil, fmt.Errorf("group %q: the container holds, in declaration order, %q besides the excluded specs, want exactly %q: review the group membership",
			g.Container, leaves, g.Members)
	}
	if missing := excluded.Difference(foundExcluded); missing.Len() > 0 {
		return nil, fmt.Errorf("group %q: excluded specs %q not found in the container", g.Container, sets.List(missing))
	}

	annotation, ok := annotations[members[0].Name]
	if !ok {
		return nil, fmt.Errorf("group %q: no generated annotations for %q", g.Container, members[0].Name)
	}
	for _, member := range members {
		if got, ok := annotations[member.Name]; !ok || got != annotation {
			return nil, fmt.Errorf("group %q: member %q is annotated %q, want %q like the other members", g.Container, member.Name, got, annotation)
		}
		if !member.Labels.Equal(members[0].Labels) {
			return nil, fmt.Errorf("group %q: member %q has labels %q, want %q like the other members",
				g.Container, member.Name, sets.List(member.Labels), sets.List(members[0].Labels))
		}
	}
	if strings.Contains(annotation, disabledAnnotation) {
		return nil, fmt.Errorf("group %q: members are disabled (%s): review the group membership", g.Container, annotation)
	}

	collected[first] = g.newSpec(members, containerNodes, annotation)
	return collected, nil
}

// specText returns the text Ginkgo gives the spec of the container whose leaf
// text is leaf.
func (g Group) specText(leaf string) string {
	return g.Container + " " + leaf
}

// newSpec returns the OTE spec running the members as one group. Its name is
// the container text with the annotations of the members appended.
func (g Group) newSpec(members ext.ExtensionTestSpecs, containerNodes []string, annotation string) *ext.ExtensionTestSpec {
	codeLocations := slices.Clone(containerNodes)
	for _, member := range members {
		codeLocations = append(codeLocations, member.CodeLocations[len(member.CodeLocations)-1])
	}
	spec := &ext.ExtensionTestSpec{
		Name:          g.Container + " " + annotation,
		Labels:        members[0].Labels.Clone(),
		CodeLocations: codeLocations,
		Lifecycle:     members[0].Lifecycle,
	}
	// Both read the name when they run: OTE renames specs after Collect.
	spec.Run = func(ctx context.Context) *ext.ExtensionTestResult {
		return g.run(ctx, spec.Name)
	}
	spec.RunParallel = func(ctx context.Context) *ext.ExtensionTestResult {
		timeout := defaultTimeout
		if spec.Timeout > 0 {
			timeout = spec.Timeout
		}
		return oteginkgo.SpawnProcessToRunTest(ctx, spec.Name, timeout)
	}
	return spec
}
