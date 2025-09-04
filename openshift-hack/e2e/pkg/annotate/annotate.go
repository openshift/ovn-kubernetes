package annotate

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/types"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/util/sets"
)

// Run generates tests annotations for the targeted package.
// It accepts two maps which defines labeling rules and filter
// function to remove elements based on test name and their labels.
// labelToTestName contains key as a label and values a list of strings which can be a partial, full or regex
// match of a test name. labelToLabel is used to map labels to labels - i.e. you can select tests by labels (ginkgo labels) and add labels.
func Run(labelToTestName, labelToLabel map[string][]string, filter func(name string) bool) {
	var errors []string
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "error: requires exactly one argument which is a path to the output file")
		os.Exit(1)
	}
	// append labels from test map to test name
	if err := ginkgo.GetSuite().BuildTree(); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to build ginkgo suite test tree: %v", err)
		os.Exit(1)
	}
	generator := newGenerator(labelToTestName, labelToLabel)
	ginkgo.GetSuite().WalkTests(generator.generate)
	if len(generator.errors) > 0 {
		sort.Strings(errors)
		for _, s := range errors {
			fmt.Fprintf(os.Stderr, "appending label failed: %s\n", s)
		}
		os.Exit(1)
	}
	ginkgo.GetSuite().WalkTests(generator.appendLabelsToTestName)
	if len(generator.missing) > 0 {
		var names []string
		for name := range generator.missing {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprintf(os.Stderr, "appending label failed:\n%s\n", strings.Join(names, "\n"))
		os.Exit(1)
	}

	var pairs []string
	for testName, labels := range generator.output {
		if filter(fmt.Sprintf("%s%s", testName, labels)) {
			continue
		}
		pairs = append(pairs, fmt.Sprintf("%q:\n%q,", testName, labels))
	}
	sort.Strings(pairs)
	contents := fmt.Sprintf(`
package generated

import (
	"fmt"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/types"
)

var AppendedAnnotations = map[string]string{
%s
}

func init() {
	ginkgo.GetSuite().SetAnnotateFn(func(name string, node types.TestSpec) {
		if newLabels, ok := AppendedAnnotations[name]; ok {
			node.AppendText(newLabels)
		} else {
			panic(fmt.Sprintf("unable to find test %%s", name))
		}
	})
}
`, strings.Join(pairs, "\n\n")) // double space between to ease readability
	generatedAnnotationsFileName := os.Args[len(os.Args)-1]
	if err := ioutil.WriteFile(generatedAnnotationsFileName, []byte(contents), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to write generated annotations file at path %q: %v", generatedAnnotationsFileName, err)
		os.Exit(1)
	}
	if _, err := exec.Command("gofmt", "-s", "-w", generatedAnnotationsFileName).Output(); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to format golang file at path %q: %v", generatedAnnotationsFileName, err)
		os.Exit(1)
	}
}

// ginkgoTestLabel is used to append labels to a test
type ginkgoTestLabel struct {
	// all labels we care about applying rules to and defined in openshift-hack/e2e/annotate/rules.go derived from LabelToTestNameMatchMaps & LabelToTestNameMatchMaps
	labels []string
	// exact substrings to match to apply a particular label derived from LabelToTestNameMatchMaps map
	stringMatches map[string][]string
	// regular expressions to match to apply a particular label derived from LabelToTestNameMatchMaps map
	matches map[string]*regexp.Regexp
	// regular expression excluding permanently a set of tests
	// see ExcludedTests in openshift-hack/e2e/annotate/rules.go
	excludedTestsFilter *regexp.Regexp
	// label and a list of labels defined in openshift-hack/e2e/annotate/rules.go LabelToLabelMaps map
	labelToLabel map[string][]string

	// output from the generate and also input for appendLabelsToTestName
	output map[string]string
	// map of unmatched test names
	missing map[string]struct{}
	// a list of errors to display
	errors []string
}

func newGenerator(labelToTestNames, labelToLabels map[string][]string) *ginkgoTestLabel {
	allLabelsSet := sets.New[string]()
	matches := make(map[string]*regexp.Regexp)
	stringMatches := make(map[string][]string)
	for _, labels := range labelToLabels {
		allLabelsSet.Insert(labels...)
	}

	for label, matchTestNames := range labelToTestNames {
		sort.Strings(matchTestNames)
		allLabelsSet.Insert(label)
		var remain []string
		for _, matchTestName := range matchTestNames {
			// matchTestName maybe regex expression or partial test name or full test name
			re := regexp.MustCompile(matchTestName)
			if p, ok := re.LiteralPrefix(); ok {
				stringMatches[label] = append(stringMatches[label], p)
			} else {
				remain = append(remain, matchTestName)
			}
		}
		if len(remain) > 0 {
			matches[label] = regexp.MustCompile(strings.Join(remain, `|`))
		}
	}
	allLabels := allLabelsSet.UnsortedList()
	sort.Strings(allLabels)

	excludedTestsFilter := regexp.MustCompile(strings.Join(ExcludedTests, `|`))

	return &ginkgoTestLabel{
		labels:              allLabels,
		stringMatches:       stringMatches,
		matches:             matches,
		labelToLabel:        labelToLabels,
		excludedTestsFilter: excludedTestsFilter,
		output:              make(map[string]string),
	}
}

func (r *ginkgoTestLabel) appendLabelsToTestName(name string, node types.TestSpec) {
	if newLables, ok := r.output[name]; ok {
		node.AppendText(newLables)
	} else {
		r.missing[name] = struct{}{}
	}
}

func (r *ginkgoTestLabel) generate(name string, node types.TestSpec) {
	newLabels := ""
	newName := name

	for {
		count := 0
		for _, label := range r.labels {
			// skip processing this label if it already exists in the test name
			if strings.Contains(newName, label) {
				continue
			}
			var isLabelRequired bool
			// check if there is a substring match from the test name
			for _, segment := range r.stringMatches[label] {
				isLabelRequired = strings.Contains(newName, segment)
				if isLabelRequired {
					break
				}
			}
			// check if there is a match from the test name using a regex
			if !isLabelRequired {
				if re := r.matches[label]; re != nil {
					isLabelRequired = r.matches[label].MatchString(newName)
				}
			}
			// check to see if the label is present - label is extracted from ginkgo labels
			if !isLabelRequired {
				if potentialLabels, ok := r.labelToLabel[label]; ok {
					for _, potentialLabel := range potentialLabels {
						isLabelRequired = containsLabel(node.Labels(), potentialLabel)
						if isLabelRequired {
							break
						}
					}
				}
			}

			if isLabelRequired {
				count++
				newLabels += label
				newName += label
			}
		}
		if count == 0 {
			break
		}
	}

	// Append suite name to test, if it doesn't already have one
	if !r.excludedTestsFilter.MatchString(newName) && !strings.Contains(newName, "[Suite:") {
		isSerial := strings.Contains(newName, "[Serial]")
		isConformance := strings.Contains(newName, "[Conformance]")
		switch {
		case isSerial && isConformance:
			newLabels += "[Suite:openshift/conformance/serial/minimal]"
		case isSerial:
			newLabels += "[Suite:openshift/conformance/serial]"
		case isConformance:
			newLabels += "[Suite:openshift/conformance/parallel/minimal]"
		default:
			newLabels += "[Suite:openshift/conformance/parallel]"
		}
	}

	if err := checkBalancedBrackets(newName); err != nil {
		r.errors = append(r.errors, err.Error())
	}

	r.output[name] = newLabels
}

// checkBalancedBrackets ensures that square brackets are balanced in generated test
// names. If they are not, it returns an error with the name of the test and a guess
// where the unmatched bracket(s) are.
func checkBalancedBrackets(testName string) error {
	stack := make([]int, 0, len(testName))
	for idx, c := range testName {
		if c == '[' {
			stack = append(stack, idx)
		} else if c == ']' {
			// case when we start off with a ]
			if len(stack) == 0 {
				stack = append(stack, idx)
			} else {
				stack = stack[:len(stack)-1]
			}
		}
	}

	if len(stack) > 0 {
		msg := testName + "\n"
	outerLoop:
		for i := 0; i < len(testName); i++ {
			for _, loc := range stack {
				if i == loc {
					msg += "^"
					continue outerLoop
				}
			}
			msg += " "
		}
		return fmt.Errorf("unbalanced brackets in test name:\n%s\n", msg)
	}

	return nil
}

// containLabel labels return true if labels are equal. Input args labels slice and/or candidate label may or may not contain brackets.
func containsLabel(labels []string, candidateLabel string) bool {
	if len(labels) == 0 {
		return false
	}
	for _, label := range labels {
		if stripBrackets(label) == stripBrackets(candidateLabel) {
			return true
		}
	}
	return false
}

func stripBrackets(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		if r == '[' || r == ']' {
			return true
		}
		return false
	})
}
