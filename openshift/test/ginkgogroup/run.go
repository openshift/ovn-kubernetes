// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ginkgogroup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/types"
	"github.com/onsi/gomega"

	ext "github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
)

const (
	// groupEnv names the group a re-executed binary must run.
	groupEnv = "OVN_KUBERNETES_OTE_GINKGO_GROUP"
	// reportEnv is the path the re-executed binary writes its report to.
	reportEnv = "OVN_KUBERNETES_OTE_GINKGO_GROUP_REPORT"
	// suiteDescription is the description of the native Ginkgo run. Ginkgo
	// matches the focus expressions against it followed by the spec text.
	suiteDescription = "OVN-Kubernetes OTE group"
	// cleanupGrace bounds how long an interrupted group run gets to run its
	// cleanup nodes before it is killed. OTE's run-test gives a process 30
	// minutes after an interrupt.
	cleanupGrace = 25 * time.Minute
)

// Reentered reports whether this process is the re-executed binary that must
// run g.
func (g Group) Reentered() bool {
	return os.Getenv(groupEnv) == g.Container
}

// RunNative runs the members of g with a native Ginkgo RunSpecs call and
// returns the exit code for the process. It is the entry point of the
// re-executed binary, so it must run before anything builds the Ginkgo tree.
// setup prepares the process the way OTE's BeforeAll does for in-process
// specs; the providers the specs use must already be set.
func (g Group) RunNative(setup func() error) int {
	reportPath := os.Getenv(reportEnv)
	if reportPath == "" {
		fmt.Fprintf(os.Stderr, "%s must be set to run group %q\n", reportEnv, g.Container)
		return 1
	}
	gomega.RegisterFailHandler(ginkgo.Fail)
	if err := setup(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set up the run of group %q: %v\n", g.Container, err)
		return 1
	}

	// The focus and the report expect the texts of the Ginkgo tree, but Ginkgo
	// runs the suite after letting openshift/test/generated append the OTE
	// annotations to them.
	ginkgo.GetSuite().SetAnnotateFn(nil)
	// Ginkgo's own JSON report leaves out whether a spec is in an Ordered
	// container, so write the report the parent needs from the in-memory one.
	ginkgo.ReportAfterSuite("OTE group report", func(report ginkgo.Report) {
		gomega.Expect(writeReport(reportPath, newRunReport(report))).To(gomega.Succeed())
	})
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	suiteConfig.FocusStrings = g.focusStrings()
	// As for the specs OTE runs in-process: the deadline of the parent applies.
	suiteConfig.Timeout = 24 * time.Hour
	reporterConfig.NoColor = true
	reporterConfig.Verbose = true
	reporterConfig.SilenceSkips = true
	if !ginkgo.RunSpecs(testingT{}, suiteDescription, suiteConfig, reporterConfig) {
		return 1
	}
	return 0
}

// runReport is what the parent needs to know about the native run.
type runReport struct {
	SuiteSucceeded             bool
	SpecialSuiteFailureReasons []string
	// SpecsThatWillRun is the number of specs the focus selected.
	SpecsThatWillRun int
	Specs            []specResult
}

// specResult is what the parent needs to know about a spec of the native run.
type specResult struct {
	Text                        string
	LeafNodeType                types.NodeType
	IsInOrderedContainer        bool
	ContainerHierarchyLocations []types.CodeLocation
	State                       types.SpecState
	NumAttempts                 int
	RunTime                     time.Duration
	Failure                     types.Failure
	AdditionalFailures          []types.AdditionalFailure
}

func newRunReport(report types.Report) runReport {
	run := runReport{
		SuiteSucceeded:             report.SuiteSucceeded,
		SpecialSuiteFailureReasons: report.SpecialSuiteFailureReasons,
		SpecsThatWillRun:           report.PreRunStats.SpecsThatWillRun,
	}
	for _, spec := range report.SpecReports {
		run.Specs = append(run.Specs, specResult{
			Text:                        spec.FullText(),
			LeafNodeType:                spec.LeafNodeType,
			IsInOrderedContainer:        spec.IsInOrderedContainer,
			ContainerHierarchyLocations: spec.ContainerHierarchyLocations,
			State:                       spec.State,
			NumAttempts:                 spec.NumAttempts,
			RunTime:                     spec.RunTime,
			Failure:                     spec.Failure,
			AdditionalFailures:          spec.AdditionalFailures,
		})
	}
	return run
}

func writeReport(path string, report runReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// readReport reads the report the native run wrote.
func readReport(path string) (runReport, error) {
	var report runReport
	data, err := os.ReadFile(path)
	if err != nil {
		return report, err
	}
	return report, json.Unmarshal(data, &report)
}

// testingT is the GinkgoTestingT of the native run, whose outcome RunSpecs
// also returns.
type testingT struct{}

func (testingT) Fail() {}

// focusStrings returns one anchored expression per member, matching exactly
// the full text Ginkgo gives that member in the native run.
func (g Group) focusStrings() []string {
	focus := make([]string, 0, len(g.Members))
	for _, member := range g.Members {
		focus = append(focus, "^"+regexp.QuoteMeta(suiteDescription+" "+g.specText(member))+"$")
	}
	return focus
}

// run re-executes the binary to run the group and turns the Ginkgo report
// into the result of the OTE test called name.
func (g Group) run(ctx context.Context, name string) *ext.ExtensionTestResult {
	result := &ext.ExtensionTestResult{Name: name, Result: ext.ResultFailed}

	dir, err := os.MkdirTemp("", "ote-ginkgo-group-")
	if err != nil {
		result.Error = fmt.Sprintf("failed to create a directory for the Ginkgo report: %v", err)
		return result
	}
	defer func() { _ = os.RemoveAll(dir) }()
	reportPath := filepath.Join(dir, "report.json")

	executable, err := os.Executable()
	if err != nil {
		result.Error = fmt.Sprintf("failed to find the binary to re-execute: %v", err)
		return result
	}
	var output bytes.Buffer
	// Also stream the output, as OTE does for the specs it runs in-process.
	out := io.MultiWriter(&output, os.Stderr)
	cmd := exec.CommandContext(ctx, executable)
	cmd.Env = append(os.Environ(), groupEnv+"="+g.Container, reportEnv+"="+reportPath)
	cmd.Stdout = out
	cmd.Stderr = out
	// Interrupt rather than kill, so that Ginkgo runs the cleanup nodes. A
	// second interrupt makes Ginkgo skip them, so keep the child out of the
	// process group a terminal interrupts as well.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = cleanupGrace
	runErr := cmd.Run()
	result.Output = output.String()

	report, err := readReport(reportPath)
	if err != nil {
		result.Error = fmt.Sprintf("the group run left no Ginkgo report (%v): %v", runErr, err)
		return result
	}
	g.setResult(result, report, runErr)
	return result
}

// memberReports returns the reports of the members, in the order they ran.
// It fails unless Ginkgo ran the members, and only them, in declaration order
// within one Ordered container.
func (g Group) memberReports(report runReport) ([]specResult, error) {
	if report.SpecsThatWillRun != len(g.Members) {
		return nil, fmt.Errorf("the group run selected %d specs, want its %d members", report.SpecsThatWillRun, len(g.Members))
	}
	prefix := g.specText("")
	var members []specResult
	var leaves []string
	for _, spec := range report.Specs {
		if spec.LeafNodeType != types.NodeTypeIt {
			continue
		}
		leaf, ok := strings.CutPrefix(spec.Text, prefix)
		if !ok || !slices.Contains(g.Members, leaf) {
			if spec.NumAttempts > 0 || !spec.State.Is(types.SpecStateSkipped|types.SpecStatePending) {
				return nil, fmt.Errorf("spec %q ran in the group, but is not a member", spec.Text)
			}
			continue
		}
		if !spec.IsInOrderedContainer {
			return nil, fmt.Errorf("member %q is not in an Ordered container: review the group", leaf)
		}
		members = append(members, spec)
		leaves = append(leaves, leaf)
	}
	if !slices.Equal(leaves, g.Members) {
		return nil, fmt.Errorf("the group ran %q, want %q in that order", leaves, g.Members)
	}
	for i := range members {
		if !slices.Equal(members[i].ContainerHierarchyLocations, members[0].ContainerHierarchyLocations) {
			return nil, fmt.Errorf("member %q is not in the container of %q: review the group", g.Members[i], g.Members[0])
		}
	}
	return members, nil
}

// setResult fills result from the report of the group run. Like OTE does for
// a single spec, the group failed if a member or the run failed, was skipped
// if every member was skipped and passed otherwise. Output starts with the
// outcome of every member and Details holds one entry per member.
func (g Group) setResult(result *ext.ExtensionTestResult, report runReport, runErr error) {
	members, err := g.memberReports(report)
	if err != nil {
		result.Error = err.Error()
		return
	}

	var summary strings.Builder
	var failures, skips []string
	passed := 0
	for i, spec := range members {
		leaf := g.Members[i]
		fmt.Fprintf(&summary, "[%s] %s (%s)\n", spec.State, leaf, spec.RunTime.Round(time.Millisecond))
		switch {
		case spec.State.Is(types.SpecStatePassed):
			passed++
			result.AddDetails(leaf, spec.State.String())
		case spec.State.Is(types.SpecStateSkipped | types.SpecStatePending):
			reason := spec.Failure.Message
			if reason == "" {
				// Ginkgo gives no reason for the specs it did not get to
				// because the run was interrupted, aborted or timed out.
				reason = strings.Join(append([]string{"not run"}, report.SpecialSuiteFailureReasons...), ": ")
			}
			skips = append(skips, fmt.Sprintf("skip [%s]: %s: %s", location(spec.Failure.Location), leaf, reason))
			result.AddDetails(leaf, fmt.Sprintf("%s: %s", spec.State, reason))
		default:
			failures = append(failures, failureLines(leaf, spec)...)
			result.AddDetails(leaf, fmt.Sprintf("%s: %s", spec.State, spec.Failure.Message))
		}
	}
	// Failures outside of the specs, e.g. in a ReportAfterSuite node.
	for _, spec := range report.Specs {
		if spec.LeafNodeType != types.NodeTypeIt && spec.State.Is(types.SpecStateFailureStates) {
			failures = append(failures, failureLines(spec.LeafNodeType.String(), spec)...)
		}
	}
	if len(report.SpecialSuiteFailureReasons) > 0 {
		failures = append(failures, "the group run failed: "+strings.Join(report.SpecialSuiteFailureReasons, "; "))
	}
	if len(failures) == 0 && (!report.SuiteSucceeded || runErr != nil) {
		failures = append(failures, fmt.Sprintf("the group run failed: %v", runErr))
	}
	result.Output = summary.String() + "\n" + result.Output

	switch {
	case len(failures) > 0:
		result.Result = ext.ResultFailed
		result.Error = strings.Join(failures, "\n")
	case passed == 0:
		result.Result = ext.ResultSkipped
		result.Output += "\n " + strings.Join(skips, "\n ") + "\n"
	default:
		result.Result = ext.ResultPassed
	}
}

// failureLines formats the failures of a spec the way OTE does, naming the
// spec.
func failureLines(name string, spec specResult) []string {
	var lines []string
	failure := spec.Failure
	if failure.ForwardedPanic != "" {
		if failure.Location.FullStackTrace != "" {
			lines = append(lines, fmt.Sprintf("\n%s\n", failure.Location.FullStackTrace))
		}
		lines = append(lines, fmt.Sprintf("fail [%s]: %s: Test Panicked: %s", location(failure.Location), name, failure.ForwardedPanic))
	}
	lines = append(lines, fmt.Sprintf("fail [%s]: %s: %s", location(failure.Location), name, failure.Message))
	for _, additional := range spec.AdditionalFailures {
		lines = append(lines, fmt.Sprintf("fail [%s]: %s: %s", location(additional.Failure.Location), name, additional.Failure.Message))
	}
	return lines
}

// location formats a code location the way OTE does, without the path up to
// the vendor or source directory.
func location(cl types.CodeLocation) string {
	file := cl.FileName
	if parts := strings.Split(file, "/vendor/"); len(parts) > 1 {
		file = parts[len(parts)-1]
	} else if parts := strings.Split(file, "/src/"); len(parts) > 1 {
		file = parts[len(parts)-1]
	}
	return fmt.Sprintf("%s:%d", file, cl.LineNumber)
}
