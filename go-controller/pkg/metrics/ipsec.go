// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"regexp"
	"strings"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	ovsops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops/ovs"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/vswitchd"
	"k8s.io/apimachinery/pkg/util/sets"
)

type ipsecClient func(args ...string) (string, string, error)

func getGeneveInterfaces(ovsDBClient libovsdbclient.Client) ([]string, error) {
	interfaces, err := ovsops.FindInterfacesWithPredicate(ovsDBClient, func(intf *vswitchd.Interface) bool {
		return intf.Type == "geneve"
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Geneve interfaces: %v", err)
	}

	var infNames []string
	for _, intf := range interfaces {
		infNames = append(infNames, intf.Name)
	}
	return infNames, nil
}

// areAllIPsecTunnelsEstablished checks if all expected IPsec tunnels (based on geneve interfaces)
// have established Child SAs.
// 1. filter "ipsec showstates" output to only ESTABLISHED_CHILD_SA lines.
// 2. check for expected tunnels.
// 3. return true when all expected tunnels are found.
func areAllIPsecTunnelsEstablished(ipsec ipsecClient, geneveInterfaces []string) (bool, error) {
	if len(geneveInterfaces) == 0 {
		return false, fmt.Errorf("no geneve interfaces provided")
	}

	// Each geneve interface has -in-1 and -out-1 tunnels.
	expectedTunnels := sets.New[string]()
	for _, geneveTunnel := range geneveInterfaces {
		expectedTunnels.Insert(fmt.Sprintf("%s-in-1", geneveTunnel))
		expectedTunnels.Insert(fmt.Sprintf("%s-out-1", geneveTunnel))
	}

	stdout, stderr, err := ipsec("showstates")
	if err != nil {
		return false, fmt.Errorf("failed to retrieve ipsec states, stderr: %v, err: %v", stderr, err)
	}
	if stdout == "" {
		return false, fmt.Errorf("no IPsec tunnels found")
	}

	// Filter lines to only those with ESTABLISHED_CHILD_SA (similar to: ipsec showstates | grep ESTABLISHED_CHILD_SA)
	var filteredLines []string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "ESTABLISHED_CHILD_SA") {
			filteredLines = append(filteredLines, line)
		}
	}

	// sample output:
	// 000 #7: "ovn-60abc6-0-in-1":500 STATE_V2_ESTABLISHED_CHILD_SA (established Child SA); REKEY in 25883s; REPLACE in 26153s; IKE SA #5; idle;
	// 000 #10: "ovn-60abc6-0-in-1":500 STATE_V2_ESTABLISHED_CHILD_SA (established Child SA); REKEY in 25527s; REPLACE in 26153s; newest; eroute owner; IKE SA #5; idle;
	// 000 #6: "ovn-60abc6-0-out-1":500 STATE_V2_ESTABLISHED_CHILD_SA (established Child SA); REKEY in 25883s; REPLACE in 26153s; newest; eroute owner; IKE SA #5; idle;

	foundTunnels := sets.New[string]()
	re := regexp.MustCompile(`"([^"]*)"`)
	for _, line := range filteredLines {
		// Extract IPsec tunnel name which is enclosed with double quotes
		if matches := re.FindStringSubmatch(line); len(matches) == 2 {
			tunnelName := matches[1]
			// track expected tunnels
			if expectedTunnels.Has(tunnelName) {
				foundTunnels.Insert(tunnelName)
				// if all expected tunnels are found, return immediately
				if foundTunnels.Len() == expectedTunnels.Len() {
					return true, nil
				}
			}
		}
	}

	// Not all expected tunnels were found
	return false, nil
}
