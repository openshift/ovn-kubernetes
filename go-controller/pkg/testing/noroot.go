// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import "os"

func NoRoot() bool {
	return os.Getenv("NOROOT") == "TRUE"
}
