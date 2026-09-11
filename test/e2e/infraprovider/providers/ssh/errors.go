// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ssh

import "errors"

// ErrUnsupported is returned by provider capabilities that are not implemented
// for the generic SSH provider. Callers (or the test lane wiring) should skip or
// exclude specs that depend on an unsupported capability rather than treat this
// as a spurious failure.
//
// It is a typed sentinel so callers can detect it with errors.Is.
var ErrUnsupported = errors.New("capability not supported by the generic ssh infra provider")
