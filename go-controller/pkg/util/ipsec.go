package util

import (
	"fmt"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
)

func GetAllEstablishedIPsecTunnels() (sets.Set[string], error) {
	ipsecTunnels := sets.Set[string]{}
	stdout, stderr, err := RunIPsec("showstates")
	if err != nil {
		return ipsecTunnels, fmt.Errorf("failed to retrieve ipsec states %v: %v", stderr, err)
	}
	if stdout == "" {
		return ipsecTunnels, nil
	}

	lines := strings.Split(string(stdout), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ESTABLISHED_CHILD_SA") {
			matches := regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				ipsecTunnels.Insert(strings.Fields(m[1])...)
			}
		}
	}
	return ipsecTunnels, nil
}
