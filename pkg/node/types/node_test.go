// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/source"
)

func TestGetNodeIP(t *testing.T) {
	n := Node{
		Name: "node-1",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.0.2.3"), Type: addressing.NodeExternalIP},
		},
	}
	ip := n.GetNodeIP(false)
	// Return the only IP present
	require.Equal(t, ip, net.ParseIP("192.0.2.3"))

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("192.0.2.3"), Type: addressing.NodeExternalIP})
	ip = n.GetNodeIP(false)
	// The next priority should be NodeExternalIP
	require.Equal(t, ip, net.ParseIP("192.0.2.3"))

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("198.51.100.2"), Type: addressing.NodeInternalIP})
	ip = n.GetNodeIP(false)
	// The next priority should be NodeInternalIP
	require.Equal(t, ip, net.ParseIP("198.51.100.2"))

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("2001:DB8::1"), Type: addressing.NodeExternalIP})
	ip = n.GetNodeIP(true)
	// The next priority should be NodeExternalIP and IPv6
	require.Equal(t, ip, net.ParseIP("2001:DB8::1"))

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("2001:DB8::2"), Type: addressing.NodeInternalIP})
	ip = n.GetNodeIP(true)
	// The next priority should be NodeInternalIP and IPv6
	require.Equal(t, ip, net.ParseIP("2001:DB8::2"))

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("198.51.100.2"), Type: addressing.NodeInternalIP})
	ip = n.GetNodeIP(false)
	// Should still return NodeInternalIP and IPv4
	require.Equal(t, ip, net.ParseIP("198.51.100.2"))
}

func TestGetIPByType(t *testing.T) {
	n := Node{
		Name: "node-1",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.0.2.3"), Type: addressing.NodeExternalIP},
		},
	}

	ip := n.GetIPByType(addressing.NodeInternalIP, false)
	require.Nil(t, ip)
	ip = n.GetIPByType(addressing.NodeInternalIP, true)
	require.Nil(t, ip)

	ip = n.GetIPByType(addressing.NodeExternalIP, false)
	require.Equal(t, ip, net.ParseIP("192.0.2.3"))
	ip = n.GetIPByType(addressing.NodeExternalIP, true)
	require.Nil(t, ip)

	n = Node{
		Name: "node-2",
		IPAddresses: []Address{
			{IP: net.ParseIP("f00b::1"), Type: addressing.NodeCiliumInternalIP},
		},
	}

	ip = n.GetIPByType(addressing.NodeExternalIP, false)
	require.Nil(t, ip)
	ip = n.GetIPByType(addressing.NodeExternalIP, true)
	require.Nil(t, ip)

	ip = n.GetIPByType(addressing.NodeCiliumInternalIP, false)
	require.Nil(t, ip)
	ip = n.GetIPByType(addressing.NodeCiliumInternalIP, true)
	require.Equal(t, ip, net.ParseIP("f00b::1"))

	n = Node{
		Name: "node-3",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.42.0.3"), Type: addressing.NodeExternalIP},
			{IP: net.ParseIP("f00d::1"), Type: addressing.NodeExternalIP},
		},
	}

	ip = n.GetIPByType(addressing.NodeInternalIP, false)
	require.Nil(t, ip)
	ip = n.GetIPByType(addressing.NodeInternalIP, true)
	require.Nil(t, ip)

	ip = n.GetIPByType(addressing.NodeExternalIP, false)
	require.Equal(t, ip, net.ParseIP("192.42.0.3"))
	ip = n.GetIPByType(addressing.NodeExternalIP, true)
	require.Equal(t, ip, net.ParseIP("f00d::1"))
}

func TestParseCiliumNode(t *testing.T) {
	nodeResource := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "default"},
		Spec: ciliumv2.NodeSpec{
			Addresses: []ciliumv2.NodeAddress{
				{Type: addressing.NodeInternalIP, IP: "2.2.2.2"},
				{Type: addressing.NodeExternalIP, IP: "3.3.3.3"},
				{Type: addressing.NodeInternalIP, IP: "c0de::1"},
				{Type: addressing.NodeExternalIP, IP: "c0de::2"},
			},
			Encryption: ciliumv2.EncryptionSpec{
				Key: 10,
			},
			IPAM: ipamTypes.IPAMSpec{
				PodCIDRs: []string{
					"10.10.0.0/16",
					"c0de::/96",
					"10.20.0.0/16",
					"c0fe::/96",
				},
			},
			HealthAddressing: ciliumv2.HealthAddressingSpec{
				IPv4: "1.1.1.1",
				IPv6: "c0de::1",
			},
			IngressAddressing: ciliumv2.AddressPair{
				IPV4: "1.1.1.2",
				IPV6: "c0de::2",
			},
			NodeIdentity: uint64(12345),
		},
	}

	n := ParseCiliumNode(nodeResource)
	require.Equal(t, Node{
		Name:   "foo",
		Source: source.CustomResource,
		IPAddresses: []Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2.2.2.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("3.3.3.3")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("c0de::1")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("c0de::2")},
		},
		EncryptionKey:           uint8(10),
		IPv4AllocCIDR:           cidr.MustParseCIDR("10.10.0.0/16"),
		IPv6AllocCIDR:           cidr.MustParseCIDR("c0de::/96"),
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("10.20.0.0/16")},
		IPv6SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("c0fe::/96")},
		IPv4HealthIP:            net.ParseIP("1.1.1.1"),
		IPv6HealthIP:            net.ParseIP("c0de::1"),
		IPv4IngressIP:           net.ParseIP("1.1.1.2"),
		IPv6IngressIP:           net.ParseIP("c0de::2"),
		NodeIdentity:            uint32(12345),
	}, n)
}

func TestNode_ToCiliumNode(t *testing.T) {
	nodeResource := Node{
		Name:   "foo",
		Source: source.CustomResource,
		IPAddresses: []Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2.2.2.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("3.3.3.3")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("c0de::1")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("c0de::2")},
		},
		EncryptionKey:           uint8(10),
		IPv4AllocCIDR:           cidr.MustParseCIDR("10.10.0.0/16"),
		IPv6AllocCIDR:           cidr.MustParseCIDR("c0de::/96"),
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("10.20.0.0/16")},
		IPv6SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("c0fe::/96")},
		IPv4HealthIP:            net.ParseIP("1.1.1.1"),
		IPv6HealthIP:            net.ParseIP("c0de::1"),
		IPv4IngressIP:           net.ParseIP("1.1.1.2"),
		IPv6IngressIP:           net.ParseIP("c0de::2"),
		NodeIdentity:            uint32(12345),
		WireguardPubKey:         "6kiIGGPvMiadJ1brWTVfSGXheE3e3k5GjDTxfjMLYx8=",
		Annotations: map[string]string{
			annotation.BGPVRouterAnnoPrefix + "64512": "router-id=172.0.0.3",
		},
	}

	n := nodeResource.ToCiliumNode()
	require.Equal(t, &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "",
			Annotations: map[string]string{
				annotation.BGPVRouterAnnoPrefix + "64512": "router-id=172.0.0.3",
			},
		},
		Spec: ciliumv2.NodeSpec{
			Addresses: []ciliumv2.NodeAddress{
				{Type: addressing.NodeInternalIP, IP: "2.2.2.2"},
				{Type: addressing.NodeExternalIP, IP: "3.3.3.3"},
				{Type: addressing.NodeInternalIP, IP: "c0de::1"},
				{Type: addressing.NodeExternalIP, IP: "c0de::2"},
			},
			Encryption: ciliumv2.EncryptionSpec{
				Key: 10,
			},
			IPAM: ipamTypes.IPAMSpec{
				PodCIDRs: []string{
					"10.10.0.0/16",
					"c0de::/96",
					"10.20.0.0/16",
					"c0fe::/96",
				},
			},
			HealthAddressing: ciliumv2.HealthAddressingSpec{
				IPv4: "1.1.1.1",
				IPv6: "c0de::1",
			},
			IngressAddressing: ciliumv2.AddressPair{
				IPV4: "1.1.1.2",
				IPV6: "c0de::2",
			},
			NodeIdentity: uint64(12345),
		},
	}, n)
}

func TestNodeValidate(t *testing.T) {
	tests := []struct {
		name   string
		node   Node
		assert assert.ErrorAssertionFunc
	}{
		{
			name:   "empty cluster",
			node:   Node{Name: "bar"},
			assert: assert.Error,
		},
		{
			name:   "empty name",
			node:   Node{Cluster: "foo"},
			assert: assert.Error,
		},
		{
			name:   "empty cluster ID",
			node:   Node{Cluster: "foo", Name: "bar"},
			assert: assert.NoError,
		},
		{
			name:   "valid cluster ID",
			node:   Node{Cluster: "foo", Name: "bar", ClusterID: 99},
			assert: assert.NoError,
		},
		{
			name:   "invalid cluster ID",
			node:   Node{Cluster: "foo", Name: "bar", ClusterID: 260},
			assert: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, tt.node.validate())
		})
	}
}

func TestGetIPv4AllocCIDRs(t *testing.T) {
	var (
		cidr1 = cidr.MustParseCIDR("1.0.0.0/24")
		cidr2 = cidr.MustParseCIDR("2.0.0.0/24")
		cidr3 = cidr.MustParseCIDR("3.0.0.0/24")
	)

	var tests = []struct {
		// name of test
		name string
		// primary ipv4 allocation cidr
		allocCIDR *cidr.CIDR
		// secondary ipv4 allocation cidrs
		secAllocCIDRs []*cidr.CIDR
		// expected ipv4 cidrs
		expectedCIDRs []*cidr.CIDR
	}{
		{
			name:          "nil cidrs",
			allocCIDR:     nil,
			secAllocCIDRs: nil,
			expectedCIDRs: make([]*cidr.CIDR, 0),
		},
		{
			name:          "one primary and no secondary cidrs",
			allocCIDR:     cidr1,
			secAllocCIDRs: nil,
			expectedCIDRs: []*cidr.CIDR{cidr1},
		},
		{
			name:          "one primary and one secondary cidr",
			allocCIDR:     cidr1,
			secAllocCIDRs: []*cidr.CIDR{cidr2},
			expectedCIDRs: []*cidr.CIDR{cidr1, cidr2},
		},
		{
			name:          "one primary and multiple secondary cidrs",
			allocCIDR:     cidr1,
			secAllocCIDRs: []*cidr.CIDR{cidr2, cidr3},
			expectedCIDRs: []*cidr.CIDR{cidr1, cidr2, cidr3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := Node{
				Name:                    fmt.Sprintf("node-%s", tt.name),
				IPv4AllocCIDR:           tt.allocCIDR,
				IPv4SecondaryAllocCIDRs: tt.secAllocCIDRs,
			}

			actual := n.GetIPv4AllocCIDRs()
			assert.Equal(t, tt.expectedCIDRs, actual)
		})
	}
}

func TestGetIPv6AllocCIDRs(t *testing.T) {
	var (
		cidr2001 = cidr.MustParseCIDR("2001:db8::/32")
		cidr2002 = cidr.MustParseCIDR("2002:db8::/32")
		cidr2003 = cidr.MustParseCIDR("2003:db8::/32")
	)

	var tests = []struct {
		// name of test
		name string
		// primary ipv6 allocation cidr
		allocCIDR *cidr.CIDR
		// secondary ipv6 allocation cidrs
		secAllocCIDRs []*cidr.CIDR
		// expected ipv6 cidrs
		expectedCIDRs []*cidr.CIDR
	}{
		{
			name:          "nil cidrs",
			allocCIDR:     nil,
			secAllocCIDRs: nil,
			expectedCIDRs: make([]*cidr.CIDR, 0),
		},
		{
			name:          "one primary and no secondary cidrs",
			allocCIDR:     cidr2001,
			secAllocCIDRs: nil,
			expectedCIDRs: []*cidr.CIDR{cidr2001},
		},
		{
			name:          "one primary and one secondary cidr",
			allocCIDR:     cidr2001,
			secAllocCIDRs: []*cidr.CIDR{cidr2002},
			expectedCIDRs: []*cidr.CIDR{cidr2001, cidr2002},
		},
		{
			name:          "one primary and multiple secondary cidrs",
			allocCIDR:     cidr2001,
			secAllocCIDRs: []*cidr.CIDR{cidr2002, cidr2003},
			expectedCIDRs: []*cidr.CIDR{cidr2001, cidr2002, cidr2003},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := Node{
				Name:                    fmt.Sprintf("node-%s", tt.name),
				IPv6AllocCIDR:           tt.allocCIDR,
				IPv6SecondaryAllocCIDRs: tt.secAllocCIDRs,
			}

			actual := n.GetIPv6AllocCIDRs()
			assert.Equal(t, tt.expectedCIDRs, actual)
		})
	}
}
