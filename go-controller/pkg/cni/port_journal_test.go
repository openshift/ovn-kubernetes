// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package cni

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// useTempPortJournal points the journal at a directory of this test's own and
// restores the previous one when the test ends.
func useTempPortJournal(t *testing.T) string {
	t.Helper()
	previous := portJournalDir
	portJournalDir = filepath.Join(t.TempDir(), "ports")
	t.Cleanup(func() { portJournalDir = previous })
	return portJournalDir
}

func testJournalEntry(sandboxID, podIfName, hostIfaceName string) *PortJournalEntry {
	return &PortJournalEntry{
		PodNamespace:  "a-ns",
		PodName:       "a-pod",
		PodUID:        "a-uid",
		SandboxID:     sandboxID,
		PodIfName:     podIfName,
		HostIfaceName: hostIfaceName,
		IfaceID:       "a-ns_a-pod",
		ExternalIDs: map[string]string{
			"iface-id":     "a-ns_a-pod",
			"iface-id-ver": "a-uid",
			"sandbox":      sandboxID,
		},
		MTU: 1400,
	}
}

func TestPortJournalRoundTrip(t *testing.T) {
	dir := useTempPortJournal(t)

	entry := testJournalEntry("sandbox-a", "eth0", "hostif-a")
	entry.Ingress = 1000
	entry.Egress = 2000
	entry.StripDefaultNetIDs = true
	require.NoError(t, WritePortJournal(entry))

	entries, err := ListPortJournal()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, entry, entries[0])

	// The journal must not be world readable: it names every pod on the node.
	info, err := os.Stat(portJournalPath("sandbox-a", "eth0"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	// Re-plugging the same interface overwrites rather than duplicates.
	entry.HostIfaceName = "hostif-a2"
	require.NoError(t, WritePortJournal(entry))
	entries, err = ListPortJournal()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "hostif-a2", entries[0].HostIfaceName)

	RemovePortJournal("sandbox-a", "eth0")
	entries, err = ListPortJournal()
	require.NoError(t, err)
	assert.Empty(t, entries)

	// Removing an entry that is already gone is not an error.
	RemovePortJournal("sandbox-a", "eth0")
}

func TestListPortJournalMissingDir(t *testing.T) {
	useTempPortJournal(t)

	// Nothing has ever been plugged on this node yet.
	entries, err := ListPortJournal()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestWritePortJournalRejectsIncompleteEntries(t *testing.T) {
	useTempPortJournal(t)

	require.Error(t, WritePortJournal(testJournalEntry("", "eth0", "hostif-a")))
	require.Error(t, WritePortJournal(testJournalEntry("sandbox-a", "eth0", "")))

	entries, err := ListPortJournal()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestRemovePortJournalsForSandbox(t *testing.T) {
	useTempPortJournal(t)

	// A multi-homed pod: two ports on one sandbox.
	require.NoError(t, WritePortJournal(testJournalEntry("sandbox-a", "eth0", "hostif-a")))
	require.NoError(t, WritePortJournal(testJournalEntry("sandbox-a", "net1", "hostif-a-net1")))
	// A second pod that must survive.
	require.NoError(t, WritePortJournal(testJournalEntry("sandbox-b", "eth0", "hostif-b")))
	// A sandbox ID that has the first one as a prefix must not be caught by
	// the prefix match, and must not catch it either.
	require.NoError(t, WritePortJournal(testJournalEntry("sandbox-a-longer", "eth0", "hostif-c")))

	RemovePortJournalsForSandbox("sandbox-a")

	entries, err := ListPortJournal()
	require.NoError(t, err)
	remaining := make([]string, 0, len(entries))
	for _, e := range entries {
		remaining = append(remaining, e.HostIfaceName)
	}
	assert.ElementsMatch(t, []string{"hostif-b", "hostif-c"}, remaining)

	// An empty sandbox ID must not wipe the journal.
	RemovePortJournalsForSandbox("")
	entries, err = ListPortJournal()
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestListPortJournalDiscardsBadRecords(t *testing.T) {
	dir := useTempPortJournal(t)

	good := testJournalEntry("sandbox-a", "eth0", "hostif-a")
	require.NoError(t, WritePortJournal(good))

	corrupt := filepath.Join(dir, "sandbox-b_eth0.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("{not json"), 0o600))
	incomplete := filepath.Join(dir, "sandbox-c_eth0.json")
	require.NoError(t, os.WriteFile(incomplete, []byte(`{"podName":"c-pod"}`), 0o600))
	// Leftovers from an interrupted write, and anything else that is not a
	// record, are ignored rather than reported.
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".tmp-1234"), []byte("{}"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "adir.json"), 0o700))

	entries, err := ListPortJournal()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, good, entries[0])

	// Unusable records are dropped from disk so they are not re-read forever.
	assert.NoFileExists(t, corrupt)
	assert.NoFileExists(t, incomplete)
}

func TestPortJournalPathStaysInsideDir(t *testing.T) {
	dir := useTempPortJournal(t)

	// A hostile or malformed CNI_IFNAME/sandbox ID must not escape the journal
	// dir, so that removing a record can never remove anything else.
	for _, tc := range []struct {
		sandboxID string
		podIfName string
	}{
		{"../../etc", "passwd"},
		{"sandbox-a", "../../../etc/passwd"},
		{"sandbox/../..", "eth0"},
		{"..", ".."},
	} {
		path := portJournalPath(tc.sandboxID, tc.podIfName)
		assert.Equal(t, dir, filepath.Dir(path),
			"sandboxID %q podIfName %q escaped the journal dir", tc.sandboxID, tc.podIfName)
	}
}
