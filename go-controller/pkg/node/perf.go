package node

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"k8s.io/klog/v2"
)

func startOnePerf(stopChan chan struct{}, pidfile string) error {
	fname := "perf.data"
	go func() {
		for {
			wg := sync.WaitGroup{}
			var perfpid int
			wg.Add(1)
			go func() {
				defer wg.Done()
				cmd := exec.Command("/usr/bin/perf", "record", "-g", "-o", fname)
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
				cmd := exec.Command("/usr/bin/perf", "report", "-g", "graph,1,5", "-i", fname, "--stdio")
				out, _ := cmd.CombinedOutput()
				if len(out) > 0 {
					lines := strings.Split(string(out), "\n")
					var realout string
					var c int
					for _, l := range lines {
						if c > 300 {
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

	if err := startOnePerf(stopChan, "/var/run/ovn/ovn-controller.pid"); err != nil {
		return err
	}

	if err := startOnePerf(stopChan, "NetworkManager"); err != nil {
		return err
	}

	return nil
}
