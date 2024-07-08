// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

const (
	// DefaultBGPStatusUpdateInterval is the default interval to update BGP status in the CiliumBGPNodeConfig CRD.
	DefaultBGPStatusUpdateInterval = 5 * time.Second
)

type BGPConfig struct {
	StatusUpdateInterval time.Duration `mapstructure:"bgp-status-update-interval"`
}

func (bc BGPConfig) Flags(flags *pflag.FlagSet) {
	flags.DurationVar(&bc.StatusUpdateInterval, "bgp-status-update-interval", DefaultBGPStatusUpdateInterval, "Interval to update BGP status in the CiliumBGPNodeConfig CRD")
}
