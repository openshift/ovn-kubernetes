package main

import (
	"sort"
	"strings"

	"github.com/openshift-eng/openshift-tests-extension/pkg/util/sets"
)

// map contains prepend labels to be added on the spec for an existing spec label
var labelToPrependLabelsMap = map[string][]string{
	// Make EVPN tests to be added with gated label.
	"Feature:EVPN": {
		"FeatureGate:EVPN",
	},
}

// getTestExtensionLabels returns labels that should be applied to all tests in this extension
func getTestExtensionLabels() []string {
	return []string{"sig-network", "ovn-kubernetes-ote"}
}

// generatePrependedLabelsStr generates labels that are prepended to a test name
// Excludes labels that should not be prepended (e.g., those already in annotations)
func generatePrependedLabelsStr(labels sets.Set[string], excludeLabels sets.Set[string]) string {
	labelList := labels.UnsortedList()
	sort.Strings(labelList)

	var labelsStr = ""
	for _, label := range labelList {
		// Skip labels that are in the exclude list
		if excludeLabels.Has(label) {
			continue
		}
		labelsStr += "[" + label + "]"
	}
	return labelsStr
}

// getPrependLabels returns additional prepend labels for given labels.
func getPrependLabels(labels sets.Set[string]) []string {
	var prependLabels []string
	for _, label := range labels.UnsortedList() {
		for _, prependLabel := range labelToPrependLabelsMap[label] {
			prependLabels = append(prependLabels, prependLabel)
		}
	}
	return prependLabels
}

// parseLabelsFromAnnotation extracts individual labels from annotation strings like "[Serial][Suite:openshift/conformance/serial]"
func parseLabelsFromAnnotation(annotation string) []string {
	var labels []string
	remainder := annotation
	for {
		start := strings.Index(remainder, "[")
		if start == -1 {
			break
		}
		end := strings.Index(remainder[start:], "]")
		if end == -1 {
			break
		}
		label := remainder[start+1 : start+end]
		if label != "" {
			labels = append(labels, label)
		}
		remainder = remainder[start+end+1:]
	}
	return labels
}
