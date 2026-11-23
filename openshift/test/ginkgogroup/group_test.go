// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ginkgogroup

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/types"
	. "github.com/onsi/gomega"

	ext "github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	oteginkgo "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
)

const (
	// eventsEnv is the file the fixture specs append their events to.
	eventsEnv = "GINKGOGROUP_TEST_EVENTS"
	// failSeedEnv makes the seeding spec fail.
	failSeedEnv = "GINKGOGROUP_TEST_FAIL_SEED"
	// blockSeedEnv makes the seeding spec block until it is interrupted.
	blockSeedEnv = "GINKGOGROUP_TEST_BLOCK_SEED"
	// skipSetupEnv makes BeforeAll skip, like a missing cluster feature.
	skipSetupEnv = "GINKGOGROUP_TEST_SKIP_SETUP"
	// failProcessSetupEnv makes the setup of the re-executed binary fail.
	failProcessSetupEnv = "GINKGOGROUP_TEST_FAIL_PROCESS_SETUP"

	fixtureContainer = "fixture: ordered group"
	seedSpec         = "seeds the state"
	brokenSpec       = "is broken upstream"
	verifySpec       = "checks the seeded state"
)

// record appends event to the events file of the test.
func record(event string) error {
	f, err := os.OpenFile(os.Getenv(eventsEnv), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f, event)
	return errors.Join(err, f.Close())
}

// The fixture mirrors the upstream no-flood container: a labelled Describe
// holding an unnamed Ordered, Serial Context whose specs build on each other,
// with a broken spec in the middle. Its members are not declared in
// alphabetical order.
var _ = Describe(fixtureContainer, Label("Feature:Fixture"), func() {
	Context("", Ordered, Serial, func() {
		var state string

		BeforeAll(func() {
			Expect(record("setup")).To(Succeed())
			if os.Getenv(skipSetupEnv) != "" {
				Skip("fixture feature disabled")
			}
			DeferCleanup(func() {
				Expect(record("cleanup")).To(Succeed())
			})
		})

		It(seedSpec, func(ctx SpecContext) {
			Expect(record("seed")).To(Succeed())
			if os.Getenv(blockSeedEnv) != "" {
				<-ctx.Done()
			}
			if os.Getenv(failSeedEnv) != "" {
				Fail("seed failed on purpose")
			}
			state = "seeded"
		})

		It(brokenSpec, func() {
			Expect(record("broken")).To(Succeed())
		})

		It(verifySpec, func() {
			Expect(record("verify")).To(Succeed())
			Expect(state).To(Equal("seeded"), "verify must run after seed, in the same Ginkgo run")
		})
	})
})

// A different container whose text starts with the text of the fixture
// container. The upstream uplink container is a sibling as well, but its text
// only shares the first words.
var _ = Describe(fixtureContainer+" on same uplink", Label("Feature:Fixture"), func() {
	Context("", Ordered, func() {
		It("joins the uplink", func() {
			Expect(record("uplink")).To(Succeed())
		})
	})
})

var _ = Describe("fixture: unordered group", func() {
	Context("", func() {
		It("runs alone", func() {
			Expect(record("unordered")).To(Succeed())
		})
	})
})

// Members carrying different labels.
var _ = Describe("fixture: labelled group", func() {
	Context("", Ordered, func() {
		It("is plain", func() {})
		It("is labelled", Label("Extra"), func() {})
	})
})

// Two containers with the same text, as when upstream splits a container.
var _ = Describe("fixture: split group", func() {
	Context("", Ordered, func() {
		It("runs", func() {})
	})
})

var _ = Describe("fixture: split group", func() {
	It("runs", func() {})
})

var _ = Describe("fixture: unrelated", func() {
	It("stays a leaf", func() {
		Expect(record("unrelated")).To(Succeed())
	})
})

var (
	fixtureGroup = Group{
		Container: fixtureContainer,
		Members:   []string{seedSpec, verifySpec},
		Excluded:  []string{brokenSpec},
	}
	unorderedGroup = Group{
		Container: "fixture: unordered group",
		Members:   []string{"runs alone"},
	}

	fixtureAnnotations = map[string]string{
		fixtureContainer + " " + seedSpec:                     "[Suite:fixture/serial]",
		fixtureContainer + " " + brokenSpec:                   "[Disabled:Broken]",
		fixtureContainer + " " + verifySpec:                   "[Suite:fixture/serial]",
		fixtureContainer + " on same uplink joins the uplink": "[Disabled:Unimplemented]",
		"fixture: unordered group runs alone":                 "[Suite:fixture/serial]",
		"fixture: labelled group is plain":                    "[Suite:fixture/serial]",
		"fixture: labelled group is labelled":                 "[Suite:fixture/serial]",
		"fixture: split group runs":                           "[Suite:fixture/serial]",
		"fixture: unrelated stays a leaf":                     "[Suite:fixture/parallel]",
	}

	// catalog builds the OTE specs of the fixture tree the way main does.
	catalog = sync.OnceValues(func() (ext.ExtensionTestSpecs, error) {
		return oteginkgo.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite(ext.AllTestsIncludingVendored())
	})
)

// Like openshift/test/generated in the OTE binary, append annotations to the
// spec texts whenever Ginkgo runs the suite.
func init() {
	GetSuite().SetAnnotateFn(func(_ string, spec types.TestSpec) {
		spec.AppendText("[Suite:fixture]")
	})
}

// TestMain is also the entry point of the binary a group re-executes.
func TestMain(m *testing.M) {
	for _, g := range []Group{fixtureGroup, unorderedGroup} {
		if g.Reentered() {
			os.Exit(g.RunNative(func() error {
				if os.Getenv(failProcessSetupEnv) != "" {
					return errors.New("no cluster")
				}
				return record("process-setup")
			}))
		}
	}
	os.Exit(m.Run())
}

func names(specs ext.ExtensionTestSpecs) []string {
	var names []string
	for _, spec := range specs {
		names = append(names, spec.Name)
	}
	return names
}

// collect returns the fixture catalog with g collected, and the group spec.
func collect(t *testing.T, g Group) (ext.ExtensionTestSpecs, *ext.ExtensionTestSpec) {
	t.Helper()
	specs, err := catalog()
	if err != nil {
		t.Fatalf("failed to build the fixture catalog: %v", err)
	}
	collected, err := g.Collect(specs, fixtureAnnotations)
	if err != nil {
		t.Fatalf("Collect() failed: %v", err)
	}
	i := slices.IndexFunc(collected, func(spec *ext.ExtensionTestSpec) bool { return strings.HasPrefix(spec.Name, g.Container+" [") })
	if i < 0 {
		t.Fatalf("no group spec in %q", names(collected))
	}
	return collected, collected[i]
}

// runGroup runs the group spec like OTE's run-test does and returns its
// result and the events the fixture recorded.
func runGroup(t *testing.T, spec *ext.ExtensionTestSpec) (*ext.ExtensionTestResult, []string) {
	t.Helper()
	return runGroupCancelledAt(t, spec, "")
}

// runGroupCancelledAt is runGroup, cancelling the context of the run once the
// fixture records event, like OTE's run-test does when it is interrupted.
func runGroupCancelledAt(t *testing.T, spec *ext.ExtensionTestSpec, event string) (*ext.ExtensionTestResult, []string) {
	t.Helper()
	events := filepath.Join(t.TempDir(), "events")
	t.Setenv(eventsEnv, events)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	done := make(chan *ext.ExtensionTestResult, 1)
	go func() { done <- spec.Run(ctx) }()
	if event != "" {
		for !slices.Contains(readEvents(t, events), event) {
			select {
			case result := <-done:
				t.Fatalf("the group run ended before %q: %s %s", event, result.Result, result.Error)
			case <-time.After(20 * time.Millisecond):
			}
		}
		cancel()
	}
	return <-done, readEvents(t, events)
}

func readEvents(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to read the events: %v", err)
	}
	return strings.Fields(string(data))
}

func details(result *ext.ExtensionTestResult) []string {
	var details []string
	for _, d := range result.Details {
		details = append(details, fmt.Sprintf("%s=%v", d.Name, d.Value))
	}
	return details
}

func TestCollectReplacesTheMembersByOneSpec(t *testing.T) {
	specs, err := catalog()
	if err != nil {
		t.Fatalf("failed to build the fixture catalog: %v", err)
	}
	collected, group := collect(t, fixtureGroup)

	if want := fixtureContainer + " [Suite:fixture/serial]"; group.Name != want {
		t.Errorf("group name = %q, want %q", group.Name, want)
	}
	// The group takes the place of its first member. Every other spec, the
	// excluded one and the one of the uplink container included, is left as
	// it was.
	var want []string
	for _, name := range names(specs) {
		switch name {
		case fixtureContainer + " " + seedSpec:
			want = append(want, group.Name)
		case fixtureContainer + " " + verifySpec:
		default:
			want = append(want, name)
		}
	}
	if got := names(collected); !slices.Equal(got, want) {
		t.Errorf("collected specs = %q, want %q", got, want)
	}
	for _, spec := range collected {
		if spec != group && !slices.Contains(specs, spec) {
			t.Errorf("spec %q was changed", spec.Name)
		}
	}
	for _, name := range []string{fixtureContainer + " " + brokenSpec, fixtureContainer + " on same uplink joins the uplink"} {
		if !slices.Contains(names(collected), name) {
			t.Errorf("spec %q is not an individual test anymore", name)
		}
	}

	member := specs[slices.IndexFunc(specs, func(spec *ext.ExtensionTestSpec) bool { return spec.Name == fixtureContainer+" "+seedSpec })]
	if !group.Labels.Equal(member.Labels) || !group.Labels.Has("Serial") || !group.Labels.Has("Feature:Fixture") {
		t.Errorf("group labels = %v, want the labels of the members %v", group.Labels, member.Labels)
	}
	if got, want := len(group.CodeLocations), len(member.CodeLocations)+1; got != want {
		t.Errorf("group has %d code locations, want the container ones and one per member: %d", got, want)
	}
	if group.Run == nil || group.RunParallel == nil {
		t.Error("group spec cannot run")
	}
}

func TestCollectRejectsDrift(t *testing.T) {
	specs, err := catalog()
	if err != nil {
		t.Fatalf("failed to build the fixture catalog: %v", err)
	}
	disabledMembers := maps.Clone(fixtureAnnotations)
	differentMembers := maps.Clone(fixtureAnnotations)
	enabledBroken := maps.Clone(fixtureAnnotations)
	unannotatedSeed := maps.Clone(fixtureAnnotations)
	delete(unannotatedSeed, fixtureContainer+" "+seedSpec)
	disabledMembers[fixtureContainer+" "+seedSpec] = "[Disabled:Broken]"
	disabledMembers[fixtureContainer+" "+verifySpec] = "[Disabled:Broken]"
	differentMembers[fixtureContainer+" "+verifySpec] = "[Suite:fixture/parallel]"
	enabledBroken[fixtureContainer+" "+brokenSpec] = "[Suite:fixture/serial]"
	sorted := slices.Clone(fixtureGroup.Members)
	sort.Strings(sorted)

	for _, tc := range []struct {
		name        string
		group       Group
		annotations map[string]string
		wantErr     string
	}{
		{
			name:    "members sorted alphabetically instead of declaration order",
			group:   Group{Container: fixtureContainer, Members: sorted, Excluded: []string{brokenSpec}},
			wantErr: "review the group membership",
		},
		{
			name:    "container holds a spec that was not reviewed",
			group:   Group{Container: fixtureContainer, Members: []string{seedSpec}, Excluded: []string{brokenSpec}},
			wantErr: "review the group membership",
		},
		{
			name:    "reviewed member is gone",
			group:   Group{Container: fixtureContainer, Members: []string{seedSpec, verifySpec, "was removed upstream"}, Excluded: []string{brokenSpec}},
			wantErr: "review the group membership",
		},
		{
			name:    "broken spec is not excluded",
			group:   Group{Container: fixtureContainer, Members: []string{seedSpec, brokenSpec, verifySpec}},
			wantErr: "is annotated",
		},
		{
			name:    "excluded spec is gone",
			group:   Group{Container: fixtureContainer, Members: fixtureGroup.Members, Excluded: []string{brokenSpec, "was removed upstream"}},
			wantErr: "not found in the container",
		},
		{
			name:        "excluded spec is enabled again",
			group:       fixtureGroup,
			annotations: enabledBroken,
			wantErr:     "is not disabled",
		},
		{
			name:        "members are disabled",
			group:       fixtureGroup,
			annotations: disabledMembers,
			wantErr:     "members are disabled",
		},
		{
			name:        "members end up in different suites",
			group:       fixtureGroup,
			annotations: differentMembers,
			wantErr:     "is annotated",
		},
		{
			name:    "first member is gone",
			group:   Group{Container: fixtureContainer, Members: []string{"was removed upstream", seedSpec, verifySpec}, Excluded: []string{brokenSpec}},
			wantErr: "not found",
		},
		{
			name:    "no members",
			group:   Group{Container: fixtureContainer},
			wantErr: "has no members",
		},
		{
			name:        "member has no generated annotations",
			group:       fixtureGroup,
			annotations: unannotatedSeed,
			wantErr:     "no generated annotations",
		},
		{
			name:    "members carry different labels",
			group:   Group{Container: "fixture: labelled group", Members: []string{"is plain", "is labelled"}},
			wantErr: "has labels",
		},
		{
			name:    "a spec outside the container has the name of a member",
			group:   Group{Container: "fixture: split group", Members: []string{"runs"}},
			wantErr: "is outside the container",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			annotations := tc.annotations
			if annotations == nil {
				annotations = fixtureAnnotations
			}
			_, err := tc.group.Collect(specs, annotations)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Collect() error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestRunOrdersSetupSeedVerifyCleanup(t *testing.T) {
	_, group := collect(t, fixtureGroup)

	result, events := runGroup(t, group)

	if result.Result != ext.ResultPassed {
		t.Fatalf("result = %s, want passed; error: %s\noutput:\n%s", result.Result, result.Error, result.Output)
	}
	// One Ginkgo run: BeforeAll and the cleanup run once around the members,
	// verify sees the state seed left, and neither the excluded spec nor the
	// specs of other containers run.
	if want := []string{"process-setup", "setup", "seed", "verify", "cleanup"}; !slices.Equal(events, want) {
		t.Errorf("events = %q, want %q", events, want)
	}
	if want := []string{seedSpec + "=passed", verifySpec + "=passed"}; !slices.Equal(details(result), want) {
		t.Errorf("details = %q, want %q", details(result), want)
	}
	for _, line := range []string{"[passed] " + seedSpec, "[passed] " + verifySpec} {
		if !strings.Contains(result.Output, line) {
			t.Errorf("output does not contain %q:\n%s", line, result.Output)
		}
	}
	if result.Name != group.Name {
		t.Errorf("result name = %q, want %q", result.Name, group.Name)
	}
}

func TestRunSkipsVerifyAndCleansUpWhenSeedFails(t *testing.T) {
	_, group := collect(t, fixtureGroup)
	t.Setenv(failSeedEnv, "1")

	result, events := runGroup(t, group)

	if result.Result != ext.ResultFailed {
		t.Fatalf("result = %s, want failed; output:\n%s", result.Result, result.Output)
	}
	if want := []string{"process-setup", "setup", "seed", "cleanup"}; !slices.Equal(events, want) {
		t.Errorf("events = %q, want %q", events, want)
	}
	if want := "group_test.go"; !strings.Contains(result.Error, "fail [") || !strings.Contains(result.Error, want) ||
		!strings.Contains(result.Error, seedSpec+": seed failed on purpose") {
		t.Errorf("error = %q, want an OTE failure naming %q at %s", result.Error, seedSpec, want)
	}
	if strings.Contains(result.Error, verifySpec) {
		t.Errorf("error = %q, want no failure for %q", result.Error, verifySpec)
	}
	got := details(result)
	if len(got) != 2 || !strings.HasPrefix(got[0], seedSpec+"=failed: seed failed on purpose") ||
		!strings.HasPrefix(got[1], verifySpec+"=skipped: ") {
		t.Errorf("details = %q, want %q failed and %q skipped", got, seedSpec, verifySpec)
	}
}

func TestRunResetsOnRerun(t *testing.T) {
	_, group := collect(t, fixtureGroup)

	t.Setenv(failSeedEnv, "1")
	failed, _ := runGroup(t, group)
	if failed.Result != ext.ResultFailed {
		t.Fatalf("first run result = %s, want failed", failed.Result)
	}

	// The next runs of the same spec start from scratch: nothing is left of
	// the failure, nor of the state or reports of the earlier runs.
	t.Setenv(failSeedEnv, "")
	var runs [][]string
	for i := range 2 {
		result, events := runGroup(t, group)
		if result.Result != ext.ResultPassed {
			t.Fatalf("run %d result = %s, want passed; error: %s", i+2, result.Result, result.Error)
		}
		if want := []string{"process-setup", "setup", "seed", "verify", "cleanup"}; !slices.Equal(events, want) {
			t.Errorf("run %d events = %q, want %q", i+2, events, want)
		}
		runs = append(runs, details(result))
	}
	if !slices.Equal(runs[0], runs[1]) {
		t.Errorf("reruns differ: %q and %q", runs[0], runs[1])
	}
}

func TestRunIsSkippedWhenEveryMemberIsSkipped(t *testing.T) {
	_, group := collect(t, fixtureGroup)
	t.Setenv(skipSetupEnv, "1")

	result, events := runGroup(t, group)

	if result.Result != ext.ResultSkipped {
		t.Fatalf("result = %s, want skipped; error: %s", result.Result, result.Error)
	}
	if want := []string{"process-setup", "setup"}; !slices.Equal(events, want) {
		t.Errorf("events = %q, want %q", events, want)
	}
	if !strings.Contains(result.Output, " skip [") || !strings.Contains(result.Output, "group_test.go:") ||
		!strings.Contains(result.Output, seedSpec+": fixture feature disabled") {
		t.Errorf("output does not report like OTE why %q was skipped:\n%s", seedSpec, result.Output)
	}
}

func TestRunRejectsSpecsOutsideAnOrderedContainer(t *testing.T) {
	_, group := collect(t, unorderedGroup)

	result, _ := runGroup(t, group)

	if result.Result != ext.ResultFailed || !strings.Contains(result.Error, "not in an Ordered container") {
		t.Errorf("result = %s with error %q, want a failure for the missing Ordered container", result.Result, result.Error)
	}
}

func TestRunFailsWhenTheProcessCannotBeSetUp(t *testing.T) {
	_, group := collect(t, fixtureGroup)
	t.Setenv(failProcessSetupEnv, "1")

	result, events := runGroup(t, group)

	if result.Result != ext.ResultFailed || !strings.Contains(result.Error, "left no Ginkgo report") ||
		!strings.Contains(result.Output, "no cluster") {
		t.Errorf("result = %s with error %q and output %q, want a failure reporting the setup error", result.Result, result.Error, result.Output)
	}
	if len(events) != 0 {
		t.Errorf("events = %q, want none", events)
	}
}

func TestRunCleansUpAndReportsTheInterruptionWhenCancelled(t *testing.T) {
	_, group := collect(t, fixtureGroup)
	t.Setenv(blockSeedEnv, "1")

	result, events := runGroupCancelledAt(t, group, "seed")

	if result.Result != ext.ResultFailed {
		t.Fatalf("result = %s, want failed; output:\n%s", result.Result, result.Output)
	}
	if want := []string{"process-setup", "setup", "seed", "cleanup"}; !slices.Equal(events, want) {
		t.Errorf("events = %q, want %q", events, want)
	}
	if !strings.Contains(result.Error, seedSpec+": ") || !strings.Contains(result.Error, "the group run failed: Interrupted") {
		t.Errorf("error = %q, want the interrupted %q and the reason of the interruption", result.Error, seedSpec)
	}
	got := details(result)
	if len(got) != 2 || !strings.HasPrefix(got[0], seedSpec+"=interrupted") ||
		!strings.HasPrefix(got[1], verifySpec+"=skipped: not run: Interrupted") {
		t.Errorf("details = %q, want %q interrupted and %q not run", got, seedSpec, verifySpec)
	}
}

// TestSetResult checks the result of the group for reports Ginkgo produces
// in situations the fixture runs do not cover.
func TestSetResult(t *testing.T) {
	t.Parallel()

	container := []types.CodeLocation{{FileName: "/src/noflood.go", LineNumber: 389}}
	member := func(leaf string, state types.SpecState, message string) specResult {
		return specResult{
			Text:                        fixtureContainer + " " + leaf,
			LeafNodeType:                types.NodeTypeIt,
			IsInOrderedContainer:        true,
			ContainerHierarchyLocations: container,
			State:                       state,
			NumAttempts:                 1,
			Failure: types.Failure{
				Message:  message,
				Location: types.CodeLocation{FileName: "/go/vendor/example.com/e2e/noflood.go", LineNumber: 700},
			},
		}
	}
	passedSeed := member(seedSpec, types.SpecStatePassed, "")
	passedVerify := member(verifySpec, types.SpecStatePassed, "")
	report := func(specs ...specResult) runReport {
		return runReport{SuiteSucceeded: true, SpecsThatWillRun: 2, Specs: specs}
	}

	panicked := member(seedSpec, types.SpecStatePanicked, "Test Panicked")
	panicked.Failure.ForwardedPanic = "oops"
	panicked.Failure.Location.FullStackTrace = "goroutine 1"
	panicked.AdditionalFailures = []types.AdditionalFailure{{
		State:   types.SpecStateFailed,
		Failure: types.Failure{Message: "cleanup failed", Location: types.CodeLocation{FileName: "/root/src/e2e/cleanup.go", LineNumber: 9}},
	}}
	interrupted := report(member(seedSpec, types.SpecStateInterrupted, "Interrupted by User"),
		specResult{Text: fixtureContainer + " " + verifySpec, LeafNodeType: types.NodeTypeIt, IsInOrderedContainer: true,
			ContainerHierarchyLocations: container, State: types.SpecStateSkipped})
	interrupted.SuiteSucceeded = false
	interrupted.SpecialSuiteFailureReasons = []string{"Interrupted by User"}
	suiteFailed := report(passedSeed, passedVerify)
	suiteFailed.SuiteSucceeded = false
	suiteFailed.SpecialSuiteFailureReasons = []string{"Detected Programmatic Focus"}
	unordered := member(verifySpec, types.SpecStatePassed, "")
	unordered.IsInOrderedContainer = false
	elsewhere := member(verifySpec, types.SpecStatePassed, "")
	elsewhere.ContainerHierarchyLocations = []types.CodeLocation{{FileName: "/src/other.go", LineNumber: 1}}
	overselected := report(passedSeed, passedVerify)
	overselected.SpecsThatWillRun = 3

	for _, tc := range []struct {
		name        string
		report      runReport
		runErr      error
		wantResult  ext.Result
		wantError   []string
		wantDetails []string
		wantOutput  []string
	}{
		{
			name:        "every member passed",
			report:      report(passedSeed, passedVerify),
			wantResult:  ext.ResultPassed,
			wantDetails: []string{seedSpec + "=passed", verifySpec + "=passed"},
			wantOutput:  []string{"[passed] " + seedSpec, "child output"},
		},
		{
			name:        "a member skipped and the others passed",
			report:      report(passedSeed, member(verifySpec, types.SpecStateSkipped, "needs IPv4")),
			wantResult:  ext.ResultPassed,
			wantDetails: []string{seedSpec + "=passed", verifySpec + "=skipped: needs IPv4"},
			wantOutput:  []string{"[skipped] " + verifySpec},
		},
		{
			name: "every member skipped",
			report: report(member(seedSpec, types.SpecStateSkipped, "feature disabled"),
				member(verifySpec, types.SpecStateSkipped, "Spec skipped because Skip() was called in BeforeAll")),
			wantResult: ext.ResultSkipped,
			wantOutput: []string{" skip [example.com/e2e/noflood.go:700]: " + seedSpec + ": feature disabled"},
		},
		{
			name:        "a member failed",
			report:      report(member(seedSpec, types.SpecStateFailed, "boom"), member(verifySpec, types.SpecStateSkipped, "earlier spec failed")),
			wantResult:  ext.ResultFailed,
			wantError:   []string{"fail [example.com/e2e/noflood.go:700]: " + seedSpec + ": boom"},
			wantDetails: []string{seedSpec + "=failed: boom", verifySpec + "=skipped: earlier spec failed"},
		},
		{
			name:       "a member panicked and its cleanup failed",
			report:     report(panicked, member(verifySpec, types.SpecStateSkipped, "earlier spec failed")),
			wantResult: ext.ResultFailed,
			wantError: []string{
				"goroutine 1",
				"fail [example.com/e2e/noflood.go:700]: " + seedSpec + ": Test Panicked: oops",
				"fail [e2e/cleanup.go:9]: " + seedSpec + ": cleanup failed",
			},
		},
		{
			name:        "the run was interrupted",
			report:      interrupted,
			runErr:      errors.New("exit status 1"),
			wantResult:  ext.ResultFailed,
			wantError:   []string{seedSpec + ": Interrupted by User", "the group run failed: Interrupted by User"},
			wantDetails: []string{seedSpec + "=interrupted: Interrupted by User", verifySpec + "=skipped: not run: Interrupted by User"},
		},
		{
			name: "a suite node failed",
			report: report(passedSeed, passedVerify, specResult{LeafNodeType: types.NodeTypeReportAfterSuite, State: types.SpecStateFailed,
				Failure: types.Failure{Message: "cannot write the report"}}),
			wantResult: ext.ResultFailed,
			wantError:  []string{"ReportAfterSuite: cannot write the report"},
		},
		{
			name:       "the suite failed outside of the members",
			report:     suiteFailed,
			wantResult: ext.ResultFailed,
			wantError:  []string{"the group run failed: Detected Programmatic Focus"},
		},
		{
			name:       "the process failed after writing the report",
			report:     report(passedSeed, passedVerify),
			runErr:     errors.New("signal: killed"),
			wantResult: ext.ResultFailed,
			wantError:  []string{"the group run failed: signal: killed"},
		},
		{
			name:       "a spec that is not a member ran",
			report:     report(passedSeed, passedVerify, specResult{Text: "fixture: unrelated stays a leaf", LeafNodeType: types.NodeTypeIt, State: types.SpecStatePassed, NumAttempts: 1}),
			wantResult: ext.ResultFailed,
			wantError:  []string{`spec "fixture: unrelated stays a leaf" ran in the group, but is not a member`},
		},
		{
			name:       "the focus selected more specs than the members",
			report:     overselected,
			wantResult: ext.ResultFailed,
			wantError:  []string{"the group run selected 3 specs, want its 2 members"},
		},
		{
			name:       "the members ran out of declaration order",
			report:     report(passedVerify, passedSeed),
			wantResult: ext.ResultFailed,
			wantError:  []string{"the group ran"},
		},
		{
			name:       "a member is not in an Ordered container",
			report:     report(passedSeed, unordered),
			wantResult: ext.ResultFailed,
			wantError:  []string{"is not in an Ordered container"},
		},
		{
			name:       "a member is in another container",
			report:     report(passedSeed, elsewhere),
			wantResult: ext.ResultFailed,
			wantError:  []string{"is not in the container of"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := &ext.ExtensionTestResult{Name: "group", Result: ext.ResultFailed, Output: "child output"}

			fixtureGroup.setResult(result, tc.report, tc.runErr)

			if result.Result != tc.wantResult {
				t.Errorf("result = %s, want %s; error: %s", result.Result, tc.wantResult, result.Error)
			}
			for _, want := range tc.wantError {
				if !strings.Contains(result.Error, want) {
					t.Errorf("error = %q, want it to contain %q", result.Error, want)
				}
			}
			if tc.wantError == nil && result.Error != "" {
				t.Errorf("error = %q, want none", result.Error)
			}
			if tc.wantDetails != nil && !slices.Equal(details(result), tc.wantDetails) {
				t.Errorf("details = %q, want %q", details(result), tc.wantDetails)
			}
			for _, want := range tc.wantOutput {
				if !strings.Contains(result.Output, want) {
					t.Errorf("output = %q, want it to contain %q", result.Output, want)
				}
			}
		})
	}
}
