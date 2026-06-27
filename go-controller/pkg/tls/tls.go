// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"crypto/tls"

	cliflag "k8s.io/component-base/cli/flag"
)

type ApplyConfigOptions func(*tls.Config)

func NewApplyConfigOptions(minVersion string, cipherSuites []string) (ApplyConfigOptions, error) {
	minVersionID, err := cliflag.TLSVersion(minVersion)
	if err != nil {
		return nil, err
	}

	cipherSuiteIDs, err := cliflag.TLSCipherSuites(cipherSuites)
	if err != nil {
		return nil, err
	}

	return func(cfg *tls.Config) {
		cfg.CipherSuites = cipherSuiteIDs
		cfg.MinVersion = minVersionID
	}, nil
}
