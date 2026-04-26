// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import "os"

type AferoFileMockHelper struct {
	FileName    string
	Permissions os.FileMode
	Content     []byte
}

type AferoDirMockHelper struct {
	DirName     string
	Permissions os.FileMode
	Files       []AferoFileMockHelper
}
