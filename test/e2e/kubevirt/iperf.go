// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kubevirt

import (
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	kubevirtv1 "kubevirt.io/api/core/v1"
)

// IPerfLogCommand returns a bounded log summary without hiding terminal errors
// earlier in the log. Streaming the entire growing log over a VM's serial
// console makes observation increasingly expensive while traffic is running.
func IPerfLogCommand(logFile string) string {
	quotedPath := "'" + strings.ReplaceAll(logFile, "'", "'\"'\"'") + "'"
	return `awk '/iperf3: error/ { print; failed = 1; exit } { last = $0 } END { if (!failed) print last }' ` + quotedPath
}

// ReadIPerfLog retries failed read-only console observations independently of
// the caller's traffic-recovery polling. A successful observation, including
// empty output, zero throughput or an iperf error, is returned immediately for
// the caller to evaluate. No traffic is restarted and no log is cleared.
func (virtctl *Client) ReadIPerfLog(vmi *kubevirtv1.VirtualMachineInstance, logFile string) (string, error) {
	return readIPerfLog(func(command string) (string, error) {
		return virtctl.RunCommand(vmi, command, 5*time.Second)
	}, logFile, time.Second, 30*time.Second)
}

func readIPerfLog(runCommand func(string) (string, error), logFile string, interval, timeout time.Duration) (string, error) {
	var output string
	var readErr error
	err := wait.PollImmediate(interval, timeout, func() (bool, error) {
		output, readErr = runCommand(IPerfLogCommand(logFile))
		return readErr == nil, nil
	})
	if err != nil {
		return "", fmt.Errorf("reading iperf log %s via console: %w (last command error: %v)", logFile, err, readErr)
	}
	return output, nil
}
