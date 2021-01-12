package cni

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"
	kexec "k8s.io/utils/exec"
)

var runner kexec.Interface
var vsctlPath string

func setExec(r kexec.Interface) error {
	runner = r
	var err error
	vsctlPath, err = r.LookPath("ovs-vsctl")
	return err
}

func ovsExec(args ...string) (string, error) {
	if runner == nil {
		if err := setExec(kexec.New()); err != nil {
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
	args = append([]string{"--timeout=10", "--no-stats", "--strict"}, args...)
	var stdout, stderr bytes.Buffer
	cmd := runner.Command("ovs-ofctl", args...)
	cmd.SetStdout(&stdout)
	cmd.SetStderr(&stderr)

	cmdStr := strings.Join(args, " ")
	klog.V(5).Infof("exec: ovs-ofctl %s", cmdStr)

	err := cmd.Run()
	if err != nil {
		stderrStr := stderr.String()
		klog.Errorf("exec: ovs-ofctl %s : stderr: %q", cmdStr, stderrStr)
		return "", fmt.Errorf("failed to run 'ovs-ofctl %s': %v\n  %q", cmdStr, err, stderrStr)
	}
	stdoutStr := stdout.String()
	klog.V(5).Infof("exec: ovs-ofctl %s: stdout: %q", cmdStr, stdoutStr)

	trimmed := strings.TrimSpace(stdoutStr)
	// If output is a single line, strip the trailing newline
	if strings.Count(trimmed, "\n") == 0 {
		stdoutStr = trimmed
	}
	return stdoutStr, nil
}

func isIfaceOvnInstalledSet(ifaceName string) error {
	out, err := ovsGet("Interface", ifaceName, "external-ids", "ovn-installed")
	if err == nil && out == "true" {
		klog.V(5).Infof("Interface %s has ovn-installed=true", ifaceName)
		return nil
	}

	// Try again
	return fmt.Errorf("still waiting for OVS port %s to have ovn-installed", ifaceName)
}

func waitForPodFlows(ifaceName string) error {
	return wait.PollImmediate(200*time.Millisecond, 20*time.Second, func() (bool, error) {
		if err := isIfaceOvnInstalledSet(ifaceName); err == nil {
			//success
			return true, nil
		}
		return false, nil
	})
}
