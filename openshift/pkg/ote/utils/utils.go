package oteutils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

// ApplyResourceFromTemplate processes an OpenShift template and applies it.
// --local avoids depending on the current kubeconfig namespace existing (CI
// contexts often point at a short-lived ci-op-* project that is not on the DUT).
func ApplyResourceFromTemplate(namespace string, templatePath string, parameters ...string) error {
	args := append([]string{"process", "--local", "-f", templatePath, "--ignore-unknown-parameters=true"}, parameters...)
	if namespace != "" {
		args = append(args, "-p", "NAMESPACE="+namespace)
	}
	processCmd := exec.Command("oc", args...)
	var processed bytes.Buffer
	var errOut bytes.Buffer
	processCmd.Stdout = &processed
	processCmd.Stderr = &errOut
	if err := processCmd.Run(); err != nil {
		return fmt.Errorf("failed to process template %s: %v, stderr: %s", templatePath, err, errOut.String())
	}

	applyArgs := []string{"apply", "-f", "-"}
	if namespace != "" {
		applyArgs = append(applyArgs, "-n", namespace)
	}
	applyCmd := exec.Command("oc", applyArgs...)
	applyCmd.Stdin = &processed
	applyCmd.Stdout = os.Stdout
	applyCmd.Stderr = os.Stderr
	if err := applyCmd.Run(); err != nil {
		return fmt.Errorf("failed to apply processed template: %v", err)
	}

	return nil
}
