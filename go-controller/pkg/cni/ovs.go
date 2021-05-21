package cni

import (
	"bytes"
	"context"
	"fmt"
	utilnet "k8s.io/utils/net"
	"net"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog/v2"
	kexec "k8s.io/utils/exec"
)

var runner kexec.Interface
var vsctlPath string
var ofctlPath string

func SetExec(r kexec.Interface) error {
	runner = r
	var err error
	vsctlPath, err = r.LookPath("ovs-vsctl")
	if err != nil {
		return err
	}
	ofctlPath, err = r.LookPath("ovs-ofctl")
	return err
}

// ResetRunner used by unit-tests to reset runner to its initial (un-initialized) value
func ResetRunner() {
	runner = nil
}

func ovsExec(args ...string) (string, error) {
	if runner == nil {
		if err := SetExec(kexec.New()); err != nil {
			return "", err
		}
	}

	args = append([]string{"--timeout=30"}, args...)
	output, err := runner.Command(vsctlPath, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to run 'ovs-vsctl %s': %v\n  %q", strings.Join(args, " "), err, string(output))
	}

	return strings.TrimSuffix(string(output), "\n"), nil
}

func ovsCreate(table string, values ...string) (string, error) {
	args := append([]string{"create", table}, values...)
	return ovsExec(args...)
}

func ovsDestroy(table, record string) error {
	_, err := ovsExec("--if-exists", "destroy", table, record)
	return err
}

func ovsSet(table, record string, values ...string) error {
	args := append([]string{"set", table, record}, values...)
	_, err := ovsExec(args...)
	return err
}

func ovsGet(table, record, column, key string) (string, error) {
	args := []string{"--if-exists", "get", table, record}
	if key != "" {
		args = append(args, fmt.Sprintf("%s:%s", column, key))
	} else {
		args = append(args, column)
	}
	output, err := ovsExec(args...)
	return strings.Trim(strings.TrimSpace(string(output)), "\""), err
}

// Returns the given column of records that match the condition
func ovsFind(table, column, condition string) ([]string, error) {
	output, err := ovsExec("--no-heading", "--format=csv", "--data=bare", "--columns="+column, "find", table, condition)
	if err != nil {
		return nil, err
	}
	if output == "" {
		return nil, nil
	}
	return strings.Split(output, "\n"), nil
}

func ovsClear(table, record string, columns ...string) error {
	args := append([]string{"--if-exists", "clear", table, record}, columns...)
	_, err := ovsExec(args...)
	return err
}

func ofctlExec(args ...string) (string, error) {
	if runner == nil {
		if err := SetExec(kexec.New()); err != nil {
			return "", err
		}
	}

	args = append([]string{"--timeout=10", "--no-stats", "--strict"}, args...)
	var stdout, stderr bytes.Buffer
	cmd := runner.Command(ofctlPath, args...)
	cmd.SetStdout(&stdout)
	cmd.SetStderr(&stderr)

	cmdStr := strings.Join(args, " ")
	klog.V(5).Infof("exec: %s %s", ofctlPath, cmdStr)

	err := cmd.Run()
	if err != nil {
		stderrStr := stderr.String()
		klog.Errorf("exec: %s %s : stderr: %q", ofctlPath, cmdStr, stderrStr)
		return "", fmt.Errorf("failed to run '%s %s': %v\n  %q", ofctlPath, cmdStr, err, stderrStr)
	}
	stdoutStr := stdout.String()
	klog.V(5).Infof("exec: %s %s: stdout: %q", ofctlPath, cmdStr, stdoutStr)

	trimmed := strings.TrimSpace(stdoutStr)
	// If output is a single line, strip the trailing newline
	if strings.Count(trimmed, "\n") == 0 {
		stdoutStr = trimmed
	}
	return stdoutStr, nil
}

// isIfaceIDSet checks to see if the interface has its external id set, which indicates if it is active
func isIfaceIDSet(ifaceName, ifaceID string) error {
	// ensure the OVS interface is still active. It may have been cleared by a subsequent CNI ADD
	// and if so, there's no need to keep checking for flows
	out, err := ovsGet("Interface", ifaceName, "external-ids", "iface-id")
	if err == nil && out != ifaceID {
		return fmt.Errorf("OVS sandbox port %s is no longer active (probably due to a subsequent "+
			"CNI ADD)", ifaceName)
	}

	// Try again
	return nil
}

func isIfaceOvnInstalledSet(ifaceName string) bool {
	out, err := ovsGet("Interface", ifaceName, "external-ids", "ovn-installed")
	if err == nil && out == "true" {
		klog.V(5).Infof("Interface %s has ovn-installed=true", ifaceName)
		return true
	}

	klog.V(5).Info("Still waiting for OVS port %s to have ovn-installed=true", ifaceName)
	return false
}

// getIfaceOFPort returns the of port number for an interface
func getIfaceOFPort(ifaceName string) (int, error) {
	port, err := ovsGet("Interface", ifaceName, "ofport", "")
	if err == nil && port == "" {
		return -1, fmt.Errorf("cannot find OpenFlow port for OVS interface: %s, error: %v ", ifaceName, err)
	}

	iPort, err := strconv.Atoi(port)
	if err != nil {
		return -1, fmt.Errorf("unable to parse OpenFlow port %s, error: %v", port, err)
	}
	return iPort, nil
}

type openflowQuery struct {
	match  string
	tables []int
}

func getLegacyFlowQueries(mac string, ifAddrs []*net.IPNet, ofPort int) []openflowQuery {
	// Query the flows by mac address for in_port_security and OF port
	queries := getMinimalFlowQueries(mac, ofPort)
	for _, ifAddr := range ifAddrs {
		var ipMatch string
		if !utilnet.IsIPv6(ifAddr.IP) {
			ipMatch = "ip,ip_dst"
		} else {
			ipMatch = "ipv6,ipv6_dst"
		}
		// add queries for out_port_security
		// note we need to support table 48 for 20.06 OVN backwards compatibility. Table 49 is now
		// where out_port_security lives
		queries = append(queries,
			openflowQuery{fmt.Sprintf("%s=%s", ipMatch, ifAddr.IP), []int{48, 49}},
		)
	}
	return queries
}

func getMinimalFlowQueries(mac string, ofPort int) []openflowQuery {
	// Query the flows by mac address for in_port_security and OF port
	queries := []openflowQuery{
		{
			match:  "dl_src=" + mac,
			tables: []int{9},
		},
		{
			match:  fmt.Sprintf("in_port=%d", ofPort),
			tables: []int{0},
		},
	}
	return queries
}

func doPodFlowsExist(queries []openflowQuery) bool {
	// Function checks for OpenFlow flows to know the pod is ready
	// TODO(trozet): in the future use a more stable mechanism provided by OVN:
	// https://bugzilla.redhat.com/show_bug.cgi?id=1839102

	// Must find the right flows in all queries to succeed
	for _, query := range queries {
		found := false
		// Look for a match in any table of this query to be considered success
		for _, table := range query.tables {
			queryStr := fmt.Sprintf("table=%d,%s", table, query.match)
			// ovs-ofctl dumps error on stderr, so stdout will only dump flow data if matches the query.
			stdout, err := ofctlExec("dump-flows", "br-int", queryStr)
			if err == nil && len(stdout) > 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func waitForPodInterface(ctx context.Context, mac string, ifAddrs []*net.IPNet, ifaceName, ifaceID string, ofPort int, checkExternalIDs bool) error {
	var queries []openflowQuery
	if checkExternalIDs {
		queries = getMinimalFlowQueries(mac, ofPort)
	} else {
		queries = getLegacyFlowQueries(mac, ifAddrs, ofPort)
	}
	timeout := time.After(20 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("canceled while waiting for OVS port binding")
		case <-timeout:
			return fmt.Errorf("timed out while waiting for OVS port binding")
		default:
			if err := isIfaceIDSet(ifaceName, ifaceID); err != nil {
				return err
			}
			if doPodFlowsExist(queries) {
				if checkExternalIDs {
					if isIfaceOvnInstalledSet(ifaceName) {
						return nil
					}
				} else {
					return nil
				}
			}

			// try again later
			time.Sleep(200 * time.Millisecond)
		}
	}
}
