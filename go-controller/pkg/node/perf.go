package node

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

func getPidOf(item string) (string, error) {
	if item[0] == '/' {
		pid, err := ioutil.ReadFile(item)
		if err != nil {
			return "", err
		}
		return strings.Trim(string(pid), " \n"), nil
	}

	files, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	for _, file := range files {
		filepath := fmt.Sprintf("/proc/%s/comm", file.Name())
		comm, err := ioutil.ReadFile(filepath)
		if err != nil {
			continue
		}

		if string(comm) == item {
			return file.Name(), nil
		}
	}

	return "", fmt.Errorf("not found")
}

func startOnePerf(stopChan chan struct{}, pidfile string) error {
	pid, err := getPidOf(pidfile)
	if err != nil {
		return fmt.Errorf("Failed to get pid for %s: %v", pidfile, err)
	}

	fname := fmt.Sprintf("perf.data.%s", pid)
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second * 30)
			cmd := exec.CommandContext(ctx, "/usr/bin/perf", "record", "-o", fname, "-p", pid, "sleep", "25")
			out, err := cmd.CombinedOutput()
			if err != nil {
				klog.Warningf("##### error running perf: %v\n  %s", err, string(out))
				time.Sleep(5)
				cancel()
				continue
			}
			cancel()

			select {
			case <-stopChan:
				return
			case <-time.After(time.Millisecond):
				cmd := exec.Command("/usr/bin/perf", "report", "-i", fname, "--stdio")
				out, _ := cmd.CombinedOutput()
				if len(out) > 0 {
					lines := strings.Split(string(out), "\n")
					var realout string
					var c int
					for _, l := range lines {
						if c > 15 {
							break
						}
						if len(l) > 0 && l[0] != '#' && len(strings.TrimSpace(l)) != 0 {
							realout = realout + l + "\n"
							c++
						}
					}
					klog.Infof("##### perf %s %s\n%s\n", pidfile, time.Now().Format(time.RFC3339), realout)
				}
				os.Remove(fname)
			}
		}
	}()

	return nil
}

func startPerf(stopChan chan struct{}) error {
	if err := startOnePerf(stopChan, "/var/run/openvswitch/ovs-vswitchd.pid"); err != nil {
		return err
	}

	if err := startOnePerf(stopChan, "NetworkManager"); err != nil {
		return err
	}

	return nil
}
