package infraprovider

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestConfigureIPerf3Pod(t *testing.T) {
	o := &OpenshiftInfraProvider{}
	const image = "registry.example.com/network-tools@sha256:abc"
	original := []string{"bash", "-c", "iperf3 -s; sleep infinity"}
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
		Name: "traffic", Image: image, Command: original[:2], Args: original[2:],
	}}}}
	if err := o.ConfigureIPerf3Pod(pod); err != nil {
		t.Fatal(err)
	}
	c := pod.Spec.Containers[0]
	if c.Image != image || c.Name != "traffic" || !reflect.DeepEqual(c.Args[2:], original) {
		t.Fatalf("preparation did not preserve the endpoint image/command: %+v", c)
	}
	if c.ReadinessProbe == nil || c.ReadinessProbe.Exec == nil {
		t.Fatal("traffic endpoint must wait for the server")
	}
	if err := o.ConfigureIPerf3Pod(&corev1.Pod{}); err == nil {
		t.Fatal("expected invalid endpoint error")
	}
}

func TestRequireIPerf3(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "present"}[installed], func(t *testing.T) {
			dir := t.TempDir()
			// Older payloads must fail clearly before starting any traffic.
			if installed {
				if err := os.WriteFile(filepath.Join(dir, "iperf3"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("/bin/bash", "-ceu", requireIPerf3)
			cmd.Env = append(os.Environ(), "PATH="+dir)
			output, err := cmd.CombinedOutput()
			if installed && err != nil {
				t.Fatalf("preinstalled iperf3 should succeed: %v: %s", err, output)
			}
			if !installed && (err == nil || !strings.Contains(string(output), "network-tools#189")) {
				t.Fatalf("missing payload prerequisite was not reported: %v: %s", err, output)
			}
		})
	}
}
