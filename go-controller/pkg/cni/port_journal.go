// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package cni

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/klog/v2"
)

// portJournalDir holds one journal file per pod OVS port that this node has
// successfully plugged into br-int. The journal exists because the OVS
// database is not the only owner of that state and can lose it underneath a
// live sandbox: ovsdb-server is started with --delete-transient-ports on every
// restart of the OVS container, and an unclean power off can roll conf.db back
// to a snapshot that predates the port. When that happens the sandbox, its
// netns and its veth pair all survive, so the runtime never re-runs CNI ADD
// and the pod keeps a permanently black-holed datapath.
//
// The journal lives on tmpfs under the CNI server run dir, which is shared
// between the cnishim and ovnkube-node. That placement is deliberate: the
// records are only meaningful for the current boot, and a real node reboot
// destroys every sandbox anyway.
var portJournalDir = filepath.Join(ServerRunDir, "ports")

// SetPortJournalDir overrides where the pod port journal is kept. It exists
// for unit tests in other packages, so that they never write to the node's
// /var/run.
func SetPortJournalDir(dir string) {
	portJournalDir = dir
}

// PortJournalEntry records everything ovnkube-node needs to re-plug one pod
// OVS port without the pod's netns, i.e. without recreating the sandbox.
type PortJournalEntry struct {
	PodNamespace string `json:"podNamespace"`
	PodName      string `json:"podName"`
	// PodUID is the UID the sandbox was created for. A repair is only valid
	// while the pod on the apiserver still has this UID.
	PodUID string `json:"podUID"`
	// SandboxID is the runtime's sandbox (infra container) ID.
	SandboxID string `json:"sandboxID"`
	// PodIfName is the interface name inside the pod (CNI_IFNAME), used to
	// distinguish the several ports a single sandbox can have.
	PodIfName string `json:"podIfName"`
	// HostIfaceName is the br-int port name: the host side of the veth pair,
	// or the VF/SF representor for hardware offload.
	HostIfaceName string `json:"hostIfaceName"`
	// IfaceID is external_ids:iface-id, the logical switch port ovn-controller
	// binds this interface to.
	IfaceID string `json:"ifaceID"`
	// ExternalIDs is the full set of Interface external_ids written by
	// ConfigureOVS.
	ExternalIDs map[string]string `json:"externalIDs"`
	// StripDefaultNetIDs mirrors the default-network handling in ConfigureOVS.
	StripDefaultNetIDs bool `json:"stripDefaultNetIDs,omitempty"`
	UseDPDK            bool `json:"useDPDK,omitempty"`
	MTU                int  `json:"mtu,omitempty"`
	// Ingress and Egress are the pod bandwidth limits in bits per second. The
	// OVS QoS and Queue records that implement them live in the same database
	// as the port, so they are lost and restored together with it.
	Ingress int64 `json:"ingress,omitempty"`
	Egress  int64 `json:"egress,omitempty"`
}

// sanitizeJournalComponent keeps generated file names to a predictable shape.
// Sandbox IDs are hex and pod interface names are netdev names, so in practice
// nothing is replaced; the sanitising only guards against a malformed
// CNI_IFNAME creating a path outside portJournalDir.
func sanitizeJournalComponent(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '.', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}

func portJournalPrefix(sandboxID string) string {
	return sanitizeJournalComponent(sandboxID) + "_"
}

func portJournalPath(sandboxID, podIfName string) string {
	return filepath.Join(portJournalDir,
		portJournalPrefix(sandboxID)+sanitizeJournalComponent(podIfName)+".json")
}

// WritePortJournal records a successfully plugged pod OVS port. Callers treat
// failures as non fatal: a missing record only means this port cannot be
// repaired later, which is the behaviour that predates the journal.
func WritePortJournal(entry *PortJournalEntry) error {
	if entry.SandboxID == "" || entry.HostIfaceName == "" {
		return fmt.Errorf("refusing to journal a pod port without a sandbox ID and a host interface name")
	}
	if err := os.MkdirAll(portJournalDir, 0o700); err != nil {
		return fmt.Errorf("failed to create the pod port journal dir %q: %w", portJournalDir, err)
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal the pod port journal of %s: %w", entry.HostIfaceName, err)
	}
	path := portJournalPath(entry.SandboxID, entry.PodIfName)
	// Write through a temporary file so a crash mid-write cannot leave a
	// truncated record that the repair loop would have to guess about.
	tmp, err := os.CreateTemp(portJournalDir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create a temporary pod port journal file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write the pod port journal of %s: %w", entry.HostIfaceName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close the pod port journal of %s: %w", entry.HostIfaceName, err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("failed to set the mode of the pod port journal of %s: %w", entry.HostIfaceName, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("failed to install the pod port journal of %s: %w", entry.HostIfaceName, err)
	}
	return nil
}

// RemovePortJournalsForSandbox forgets every port of a sandbox. It must run
// before CNI DEL tears the ports down, so that the repair loop cannot re-plug
// a port that is on its way out.
func RemovePortJournalsForSandbox(sandboxID string) {
	if sandboxID == "" {
		return
	}
	entries, err := os.ReadDir(portJournalDir)
	if err != nil {
		if !os.IsNotExist(err) {
			klog.Warningf("Failed to read the pod port journal dir %q: %v", portJournalDir, err)
		}
		return
	}
	prefix := portJournalPrefix(sandboxID)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if err := os.Remove(filepath.Join(portJournalDir, e.Name())); err != nil && !os.IsNotExist(err) {
			klog.Warningf("Failed to remove the pod port journal %q: %v", e.Name(), err)
		}
	}
}

// RemovePortJournal forgets a single port.
func RemovePortJournal(sandboxID, podIfName string) {
	if err := os.Remove(portJournalPath(sandboxID, podIfName)); err != nil && !os.IsNotExist(err) {
		klog.Warningf("Failed to remove the pod port journal of sandbox %s interface %s: %v",
			sandboxID, podIfName, err)
	}
}

// ListPortJournal returns every recorded pod port. Unreadable or corrupt
// records are dropped rather than failing the whole listing, so one bad file
// cannot stop the repair of every other pod on the node.
func ListPortJournal() ([]*PortJournalEntry, error) {
	dirEntries, err := os.ReadDir(portJournalDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read the pod port journal dir %q: %w", portJournalDir, err)
	}
	entries := make([]*PortJournalEntry, 0, len(dirEntries))
	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		path := filepath.Join(portJournalDir, de.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			klog.Warningf("Failed to read the pod port journal %q: %v", path, err)
			continue
		}
		entry := &PortJournalEntry{}
		if err := json.Unmarshal(data, entry); err != nil {
			klog.Warningf("Discarding the unparseable pod port journal %q: %v", path, err)
			if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
				klog.Warningf("Failed to remove the unparseable pod port journal %q: %v", path, rmErr)
			}
			continue
		}
		if entry.SandboxID == "" || entry.HostIfaceName == "" {
			klog.Warningf("Discarding the incomplete pod port journal %q", path)
			if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
				klog.Warningf("Failed to remove the incomplete pod port journal %q: %v", path, rmErr)
			}
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
