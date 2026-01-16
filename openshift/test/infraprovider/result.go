package infraprovider

import "fmt"

// result holds the execution result of SSH command
type result struct {
	user   string
	ip     string
	cmd    string
	stdout string
	stderr string
}

func (r result) String() string {
	return fmt.Sprintf("User: %q, IP: %q, Command: %q, Stdout: %q, Stderr: %q",
		r.user, r.ip, r.cmd, r.stdout, r.stderr)
}

func (r result) getStdOut() string {
	return r.stdout
}
