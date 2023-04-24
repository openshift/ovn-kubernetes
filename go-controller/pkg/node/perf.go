package node

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
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

	files, err := os.ReadDir("/host/proc")
	if err != nil {
		return "", err
	}

	for _, file := range files {
		filepath := fmt.Sprintf("/host/proc/%s/comm", file.Name())
		comm, err := ioutil.ReadFile(filepath)
		if err != nil {
			continue
		}

		if strings.TrimSpace(string(comm)) == item {
			return file.Name(), nil
		}
	}

	return "", fmt.Errorf("not found")
}

func reallyGetPidOf(item string, stopChan chan struct{}) string {
	pid, err := getPidOf(item)
	if pid != "" {
		return pid
	}

	for {
		select {
		case <-stopChan:
			return ""
		case <-time.After(time.Second * 5):
			pid, err = getPidOf(item)
			if err != nil {
				klog.Warningf("Failed to get pid for %s: %v", item, err)
			}
		}
		if pid != "" {
			return pid
		}
	}
	return ""
}

func startOnePerf(stopChan chan struct{}, pidfile string) error {
	go func() {
		var pid string

		fname := "perf.data"
		numLines := 300
		if pidfile != "" {
			pid = reallyGetPidOf(pidfile, stopChan)
			if pid == "" {
				// stopchan closed
				return
			}
			fname = fmt.Sprintf("perf.data.%s", pid)
			numLines = 300
		}

		for {
			wg := sync.WaitGroup{}
			var perfpid int
			wg.Add(1)
			go func() {
				defer wg.Done()
				args := []string{"record", "-o", fname, "-g"}
				if pid != "" {
					args = append(args, "-g", "-p", pid)
				}
				cmd := exec.Command("/usr/bin/perf", args...)
				if err := cmd.Start(); err != nil {
					klog.Warningf("##### error starting perf: %v", err)
					return
				}
				perfpid = cmd.Process.Pid
				if err := cmd.Wait(); err != nil {
					klog.Warningf("##### error running perf: %v", err)
				}
			}()
			<-time.After(time.Second * 25)
			if perfpid <= 0 {
				continue
			}
			syscall.Kill(perfpid, syscall.SIGINT)
			wg.Wait()

			select {
			case <-stopChan:
				return
			case <-time.After(time.Millisecond):
				args := []string{"report", "-i", fname, "--stdio"}
				if pid != "dddddddddd" {
					args = append(args, "-g", "graph,1,5")
				}
				cmd := exec.Command("/usr/bin/perf", args...)
				out, _ := cmd.CombinedOutput()
				if len(out) > 0 {
					lines := strings.Split(string(out), "\n")
					var realout string
					var c int
					for _, l := range lines {
						if c > numLines {
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
	if false {
		if err := startOnePerf(stopChan, "/var/run/openvswitch/ovs-vswitchd.pid"); err != nil {
			return err
		}

		if err := startOnePerf(stopChan, "/var/run/ovn/ovn-controller.pid"); err != nil {
			return err
		}

		if err := startOnePerf(stopChan, "NetworkManager"); err != nil {
			return err
		}
	}

	if err := startOnePerf(stopChan, ""); err != nil {
		return err
	}

	return nil
}
