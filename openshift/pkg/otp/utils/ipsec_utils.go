package otputils

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/pkg/otp/testdata"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

const ipsecCertsMCName = "99-worker-import-certs"

func IpsecHostCIDR(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return ip + "/128"
	}
	return ip + "/32"
}

type IPsecCertData struct {
	CaPEM    []byte
	NodeP12s map[string][]byte
}

func GenerateIPsecCerts(nodeIPs []string) (*IPsecCertData, error) {
	tmpDir, err := os.MkdirTemp("", "ipsec-certs-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	caKeyPath := filepath.Join(tmpDir, "ca.key")
	caCertPath := filepath.Join(tmpDir, "ca.pem")

	cmd := exec.Command("openssl", "req", "-x509", "-new", "-nodes",
		"-keyout", caKeyPath, "-sha256", "-days", "365",
		"-out", caCertPath, "-subj", "/CN=IPsec Test CA")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to generate CA: %s: %w", string(out), err)
	}

	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	nodeP12s := make(map[string][]byte)
	for _, ip := range nodeIPs {
		certName := strings.ReplaceAll(ip, ".", "_")
		keyPath := filepath.Join(tmpDir, certName+".key")
		csrPath := filepath.Join(tmpDir, certName+".csr")
		certPath := filepath.Join(tmpDir, certName+".crt")
		p12Path := filepath.Join(tmpDir, certName+".p12")
		extPath := filepath.Join(tmpDir, certName+".ext")

		if err := os.WriteFile(extPath, []byte(fmt.Sprintf("subjectAltName=IP:%s", ip)), 0644); err != nil {
			return nil, fmt.Errorf("failed to write ext file for %s: %w", ip, err)
		}

		cmd = exec.Command("openssl", "req", "-new", "-nodes",
			"-keyout", keyPath, "-out", csrPath,
			"-subj", fmt.Sprintf("/CN=%s", ip))
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to generate CSR for %s: %s: %w", ip, string(out), err)
		}

		cmd = exec.Command("openssl", "x509", "-req",
			"-in", csrPath, "-CA", caCertPath, "-CAkey", caKeyPath,
			"-CAcreateserial", "-out", certPath, "-days", "365",
			"-sha256", "-extfile", extPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to sign cert for %s: %s: %w", ip, string(out), err)
		}

		cmd = exec.Command("openssl", "pkcs12", "-export",
			"-out", p12Path, "-inkey", keyPath, "-in", certPath,
			"-certfile", caCertPath, "-passout", "pass:",
			"-name", certName)
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to create PKCS12 for %s: %s: %w", ip, string(out), err)
		}

		p12Data, err := os.ReadFile(p12Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read PKCS12 for %s: %w", ip, err)
		}
		nodeP12s[certName] = p12Data
	}

	return &IPsecCertData{CaPEM: caPEM, NodeP12s: nodeP12s}, nil
}

func DeployIPsecCertsMachineConfig(oc *exutil.CLI, certs *IPsecCertData, leftIP string, rightIPs []string) error {
	certNames := make([]string, 0, len(certs.NodeP12s))
	for name := range certs.NodeP12s {
		certNames = append(certNames, name)
	}
	sort.Strings(certNames)

	script := "#!/bin/bash -e\necho \"importing cert to NSS\"\n"
	script += "certutil -A -n \"CA\" -t \"CT,C,C\" -d /var/lib/ipsec/nss/ -i /etc/pki/certs/ca.pem\n"
	for _, certName := range certNames {
		script += fmt.Sprintf("pk12util -W \"\" -i /etc/pki/certs/%s.p12 -d /var/lib/ipsec/nss/\n", certName)
		script += fmt.Sprintf("certutil -M -n \"%s\" -t \"u,u,u\" -d /var/lib/ipsec/nss/\n", certName)
	}

	leftCert := strings.ReplaceAll(leftIP, ".", "_")
	var nstestConf string
	for i, rightIP := range rightIPs {
		mode := "transport"
		if i > 0 {
			mode = "tunnel"
		}
		nstestConf += fmt.Sprintf("conn ep-worker%d\n", i+1)
		nstestConf += fmt.Sprintf("\ttype=%s\n", mode)
		nstestConf += fmt.Sprintf("\tleft=%s\n", leftIP)
		nstestConf += "\tleftid=%fromcert\n"
		nstestConf += "\tleftrsasigkey=%cert\n"
		nstestConf += fmt.Sprintf("\tleftcert=%s\n", leftCert)
		rightCert := strings.ReplaceAll(rightIP, ".", "_")
		nstestConf += fmt.Sprintf("\tright=%s\n", rightIP)
		nstestConf += "\trightid=%fromcert\n"
		nstestConf += "\trightrsasigkey=%cert\n"
		nstestConf += fmt.Sprintf("\trightcert=%s\n", rightCert)
		if mode == "tunnel" {
			nstestConf += fmt.Sprintf("\trightsubnet=%s\n", IpsecHostCIDR(rightIP))
		}
		nstestConf += "\tike=aes_gcm256-sha2_256\n"
		nstestConf += "\tesp=aes_gcm256\n"
		nstestConf += "\tikev2=insist\n"
		nstestConf += "\tauto=add\n"
	}

	mcYAML := buildIPsecMachineConfigYAML(certs, certNames, script, nstestConf)

	tmpFile, err := os.CreateTemp("", "ipsec-mc-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(mcYAML); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write MC YAML: %w", err)
	}
	tmpFile.Close()

	err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", tmpFile.Name()).Execute()
	if err != nil {
		return fmt.Errorf("failed to apply MachineConfig: %w", err)
	}

	g.By("Waiting for worker MCP to be updated after cert deployment")
	if err := GetmcpStatus(oc, "worker"); err != nil {
		return fmt.Errorf("MCP rollout failed: %w", err)
	}

	CheckOVNKState(oc)
	ipsecMode := CheckIPsec(oc)
	if ipsecMode == "Full" {
		if err := WaitForPodWithLabelReady(oc, "openshift-ovn-kubernetes", "app=ovn-ipsec"); err != nil {
			return fmt.Errorf("ovn-ipsec pods not ready after cert deployment: %w", err)
		}
	}
	WaitForNetworkOperatorState(oc, 60, 30, "True.*False.*False")
	return nil
}

func buildIPsecMachineConfigYAML(certs *IPsecCertData, certNames []string, script, nstestConf string) string {
	caB64 := base64.StdEncoding.EncodeToString(certs.CaPEM)
	scriptB64 := base64.StdEncoding.EncodeToString([]byte(script))
	nstestB64 := base64.StdEncoding.EncodeToString([]byte(nstestConf))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  labels:
    machineconfiguration.openshift.io/role: worker
  name: %s
spec:
  config:
    ignition:
      version: 3.4.0
    storage:
      files:
        - contents:
            source: data:;base64,%s
          mode: 480
          overwrite: true
          path: /etc/ipsec.d/nstest.conf
        - contents:
            source: data:;base64,%s
          mode: 256
          overwrite: true
          path: /etc/pki/certs/ca.pem
`, ipsecCertsMCName, nstestB64, caB64))

	for _, certName := range certNames {
		p12B64 := base64.StdEncoding.EncodeToString(certs.NodeP12s[certName])
		sb.WriteString(fmt.Sprintf(`        - contents:
            source: data:;base64,%s
          mode: 256
          overwrite: true
          path: /etc/pki/certs/%s.p12
`, p12B64, certName))
	}

	sb.WriteString(fmt.Sprintf(`        - contents:
            source: data:;base64,%s
          mode: 480
          overwrite: true
          path: /usr/local/bin/ipsec-addcert.sh
    systemd:
      units:
        - contents: |
            [Unit]
            Description=Import external certs into ipsec NSS
            Before=ipsec.service

            [Service]
            Type=oneshot
            ExecStart=/usr/local/bin/ipsec-addcert.sh
            RemainAfterExit=false
            StandardOutput=journal

            [Install]
            WantedBy=multi-user.target
          enabled: true
          name: ipsec-import.service
        - contents: |
            [Service]
            Type=oneshot
            ExecStart=systemctl enable --now ipsec.service

            [Install]
            WantedBy=multi-user.target
          enabled: true
          name: ipsecenabler.service
`, scriptB64))

	return sb.String()
}

func IPsecCertsMCExists(oc *exutil.CLI) bool {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("mc", ipsecCertsMCName).Output()
	return err == nil && !strings.Contains(output, "not found")
}

func nmstateTemplateDir() string {
	return testdata.FixturePath("networking", "nmstate")
}

func CreateIPsecNMStateCR(oc *exutil.CLI) {
	e2e.Logf("Create NMState CR")
	template := filepath.Join(nmstateTemplateDir(), "nmstate-cr-template.yaml")
	err := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", template, "-p", "NAME=nmstate")
	o.Expect(err).NotTo(o.HaveOccurred())

	err = WaitForPodWithLabelReady(oc, "openshift-nmstate", "component=kubernetes-nmstate-handler")
	o.Expect(err).NotTo(o.HaveOccurred(), "nmstate-handler pods not ready")
	err = WaitForPodWithLabelReady(oc, "openshift-nmstate", "component=kubernetes-nmstate-webhook")
	o.Expect(err).NotTo(o.HaveOccurred(), "nmstate-webhook pods not ready")
	err = WaitForPodWithLabelReady(oc, "openshift-nmstate", "component=kubernetes-nmstate-metrics")
	o.Expect(err).NotTo(o.HaveOccurred(), "nmstate-metrics pods not ready")
	e2e.Logf("SUCCESS - NMState CR Created")
}

func DeleteIPsecNMStateCR(oc *exutil.CLI) {
	e2e.Logf("Delete NMState CR")
	err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("nmstate", "nmstate", "--ignore-not-found=true").Execute()
	if err != nil {
		e2e.Logf("Failed to delete NMState CR: %v", err)
	}
}

func ConfigIPSecNNCP(oc *exutil.CLI, policyName, leftIP, nodeName, tunnelName, rightIP, leftCert, mode string) {
	e2e.Logf("Configure NNCP for IPsec: %s", policyName)
	template := filepath.Join(nmstateTemplateDir(), "ipsec-host2host-policy-template.yaml")
	rightSubnet := IpsecHostCIDR(rightIP)
	rightCert := IPsecCertName(rightIP)
	err := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", template, "-p",
		"NAME="+policyName,
		"NODELABEL=kubernetes.io/hostname",
		"LABELVALUE="+nodeName,
		"TUNELNAME="+tunnelName,
		"LEFT="+leftIP,
		"LEFTCERT="+leftCert,
		"RIGHT="+rightIP,
		"RIGHTCERT="+rightCert,
		"RIGHTSUBNET="+rightSubnet,
		"MODE="+mode,
	)
	o.Expect(err).NotTo(o.HaveOccurred())

	e2e.Logf("Wait ipsec NNCP applied: %s", policyName)
	err = CheckNNCPStatus(oc, policyName, "Available")
	o.Expect(err).NotTo(o.HaveOccurred(), "NNCP %s did not become Available", policyName)
	e2e.Logf("SUCCESS - IPsec NNCP %s applied", policyName)
}

func RemoveIPSecNNCP(oc *exutil.CLI, policyName, ifName, nodeName string) {
	template := filepath.Join(nmstateTemplateDir(), "iface-policy-template.yaml")
	err := ApplyResourceFromTemplateByAdmin(oc, "--ignore-unknown-parameters=true", "-f", template, "-p",
		"NAME="+policyName,
		"NODELABEL=kubernetes.io/hostname",
		"LABELVALUE="+nodeName,
		"IFACENAME="+ifName,
		"DESCR=disable ipsec tunnel",
		"IFACETYPE=ipsec",
		"STATE=absent",
		"IPV6FLAG=false",
	)
	if err != nil {
		e2e.Logf("Failed to apply iface removal NNCP %s: %v", policyName, err)
		return
	}

	err = CheckNNCPStatus(oc, policyName, "Available")
	if err != nil {
		e2e.Logf("NNCP %s removal did not reach Available: %v", policyName, err)
	}

	DeleteNNCP(oc, policyName)
}

func CheckNNCPStatus(oc *exutil.CLI, policyName, expectedStatus string) error {
	return wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nncp", policyName).Output()
		if err != nil {
			e2e.Logf("Failed to get nncp %s: %v", policyName, err)
			return false, nil
		}
		if !strings.Contains(output, expectedStatus) {
			e2e.Logf("NNCP %s status not yet %s: %s", policyName, expectedStatus, output)
			return false, nil
		}
		return true, nil
	})
}

func DeleteNNCP(oc *exutil.CLI, name string) {
	e2e.Logf("Delete NNCP %s", name)
	err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("nncp", name, "--ignore-not-found=true").Execute()
	if err != nil {
		e2e.Logf("Failed to delete nncp %s: %v", name, err)
	}
}

func VerifyIPSecTunnelUp(oc *exutil.CLI, nodeName, src, dst, mode string) {
	srcCIDR, dstCIDR := IpsecHostCIDR(src), IpsecHostCIDR(dst)
	cmd := fmt.Sprintf("ip xfrm policy get src %s dst %s dir out ; ip xfrm policy get src %s dst %s dir in", srcCIDR, dstCIDR, dstCIDR, srcCIDR)
	ipXfrmPolicy, err := DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmd)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(ipXfrmPolicy).Should(o.ContainSubstring(mode))
}

func VerifyIPSecTunnelDown(oc *exutil.CLI, nodeName, src, dst, mode string) {
	srcCIDR, dstCIDR := IpsecHostCIDR(src), IpsecHostCIDR(dst)
	cmd := fmt.Sprintf("ip xfrm policy get src %s dst %s dir out ; ip xfrm policy get src %s dst %s dir in", srcCIDR, dstCIDR, dstCIDR, srcCIDR)
	_, err := DebugNodeWithChroot(oc, nodeName, "/bin/bash", "-c", cmd)
	o.Expect(err).To(o.HaveOccurred())
}

func GetSnifPhyInf(oc *exutil.CLI, nodeName string) (string, error) {
	var phyInf string
	err := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, 15*time.Second, false, func(ctx context.Context) (bool, error) {
		ifaceList, ifaceErr := DebugNodeWithChroot(oc, nodeName, "nmcli", "con", "show")
		if ifaceErr != nil {
			e2e.Logf("Debug node error: %v", ifaceErr)
			return false, nil
		}
		for _, line := range strings.Split(ifaceList, "\n") {
			if strings.Contains(line, "ovs-if-phys0") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					phyInf = fields[3]
					return true, nil
				}
			}
		}
		e2e.Logf("Physical interface for ovs-if-phys0 not found yet on node %s", nodeName)
		return false, nil
	})
	return phyInf, err
}

func IPsecCertName(ip string) string {
	return strings.ReplaceAll(ip, ".", "_")
}
