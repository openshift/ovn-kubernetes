package infraprovider

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Require a payload containing https://github.com/openshift/network-tools/pull/189.
const requireIPerf3 = `if ! command -v iperf3 >/dev/null 2>&1; then
    echo "network-tools image lacks iperf3; use a payload containing openshift/network-tools#189" >&2
    exit 1
fi
iperf3 --version
`

// RHEL 9's iperf3 3.9 supports --pidfile only for servers. Preserve the
// upstream client's PID-file contract in a shell wrapper and flush interval
// output so the live-traffic checks can observe it while the client runs.
const prepareIPerf3Client = requireIPerf3 + `
mkdir -p /usr/local/bin
cat > /usr/local/bin/iperf3 <<'IPERF_WRAPPER'
#!/bin/bash
set -eu
client=false
pidfile=
args=()
while (( $# )); do
    case "$1" in
        -c|--client) client=true; args+=("$1" "$2"); shift 2 ;;
        -I|--pidfile) pidfile=$2; shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done
if [[ -n "$pidfile" ]]; then
    if "$client"; then
        printf '%s\n' "$$" > "$pidfile"
    else
        args+=(--pidfile "$pidfile")
    fi
fi
exec /usr/bin/iperf3 --forceflush "${args[@]}"
IPERF_WRAPPER
chmod 0755 /usr/local/bin/iperf3
`

func (o *OpenshiftInfraProvider) ConfigureIPerf3Pod(pod *corev1.Pod) error {
	if len(pod.Spec.Containers) != 1 {
		return fmt.Errorf("expected one iperf3 container")
	}
	c := &pod.Spec.Containers[0]
	command := append(append([]string{}, c.Command...), c.Args...)
	if len(command) == 0 {
		return fmt.Errorf("iperf3 container has no command")
	}
	c.Command = []string{"/bin/bash", "-ceu"}
	c.Args = append([]string{requireIPerf3 + "exec \"$@\"", "iperf3-start"}, command...)
	// Pod phase Running precedes server startup. Wait for the server process
	// before the test performs its connectivity checks.
	c.ReadinessProbe = &corev1.Probe{
		ProbeHandler:  corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/bash", "-c", "command -v iperf3 >/dev/null && pgrep -x iperf3 >/dev/null"}}},
		PeriodSeconds: 2, TimeoutSeconds: 2,
	}
	return nil
}

func (o *OpenshiftInfraProvider) PrepareIPerf3Container(ctx api.Context, ec api.ExternalContainer) (api.ExternalContainer, error) {
	if o.clusterInfra == nil {
		return ec, fmt.Errorf("iperf3 external container requires hypervisor access")
	}
	client, err := kubernetes.NewForConfig(o.restConfig)
	if err != nil {
		return ec, err
	}
	pullCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	secret, err := client.CoreV1().Secrets("openshift-config").Get(pullCtx, "pull-secret", metav1.GetOptions{})
	if err != nil {
		return ec, fmt.Errorf("read payload pull credentials: %w", err)
	}
	if err := pullNetworkTools(pullCtx, ec.Image, secret.Data[corev1.DockerConfigJsonKey]); err != nil {
		return ec, err
	}
	ec.Entrypoint = "/bin/bash"
	ec.CmdArgs = []string{"-c", "sleep infinity"}
	ec.RuntimeArgs = append(ec.RuntimeArgs, "--user", "0")
	ec, err = ctx.CreateExternalContainer(ec)
	if err != nil {
		return ec, err
	}
	if _, err := o.ExecExternalContainerCommand(ec, []string{"/bin/bash", "-ceu", prepareIPerf3Client}); err != nil {
		return ec, fmt.Errorf("prepare external iperf3 container: %w", err)
	}
	return ec, nil
}

// Send credentials on stdin, never through command arguments, logs, or a
// persistent auth file on the hypervisor.
func pullNetworkTools(ctx context.Context, image string, auth []byte) error {
	if len(auth) == 0 {
		return fmt.Errorf("payload pull secret contains no Docker credentials")
	}
	host, err := readHypervisorIP()
	if err != nil {
		return err
	}
	key, err := findSSHKeyPath()
	if err != nil {
		return err
	}
	if host == "" || key == "" {
		return fmt.Errorf("payload image pull requires hypervisor SSH configuration")
	}
	remote := "podman pull --authfile /dev/stdin " + "'" + strings.ReplaceAll(image, "'", "'\\''") + "'"
	cmd := exec.CommandContext(ctx, "ssh", "-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=30", "root@"+host, remote)
	cmd.Stdin = bytes.NewReader(auth)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pull network-tools on hypervisor: %w: %s", err, output)
	}
	return nil
}
