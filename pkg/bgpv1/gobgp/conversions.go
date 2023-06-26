// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	gobgpb "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"google.golang.org/protobuf/types/known/anypb"

	gobgp "github.com/osrg/gobgp/v3/api"
)

func toGoBGPTableType(table types.TableType) gobgp.TableType {
	switch table {
	case types.TableTypeGlobal:
		return gobgp.TableType_GLOBAL
	case types.TableTypeAdjRIBIn:
		return gobgp.TableType_ADJ_IN
	case types.TableTypeAdjRIBOut:
		return gobgp.TableType_ADJ_OUT
	default:
		return gobgp.TableType_GLOBAL
	}
}

func toGoBGPFamily(fam types.Family) *gobgp.Family {
	return &gobgp.Family{
		Afi:  toGoBGPAfi(fam.Afi),
		Safi: toGoBGPSafi(fam.Safi),
	}
}

func toAgentFamily(fam *gobgp.Family) types.Family {
	return types.Family{
		Afi:  toAgentAfi(fam.Afi),
		Safi: toAgentSafi(fam.Safi),
	}
}

// toAgentAfiSafiState translates gobgp structures to cilium bgp models.
func toAgentAfiSafiState(state *gobgp.AfiSafiState) *models.BgpPeerFamilies {
	res := &models.BgpPeerFamilies{}

	if state.Family != nil {
		res.Afi = toAgentAfi(state.Family.Afi).String()
		res.Safi = toAgentSafi(state.Family.Safi).String()
	}

	res.Received = int64(state.Received)
	res.Accepted = int64(state.Accepted)
	res.Advertised = int64(state.Advertised)

	return res
}

// toAgentSessionState translates gobgp session state to cilium bgp session state.
func toAgentSessionState(s gobgp.PeerState_SessionState) types.SessionState {
	switch s {
	case gobgp.PeerState_UNKNOWN:
		return types.SessionUnknown
	case gobgp.PeerState_IDLE:
		return types.SessionIdle
	case gobgp.PeerState_CONNECT:
		return types.SessionConnect
	case gobgp.PeerState_ACTIVE:
		return types.SessionActive
	case gobgp.PeerState_OPENSENT:
		return types.SessionOpenSent
	case gobgp.PeerState_OPENCONFIRM:
		return types.SessionOpenConfirm
	case gobgp.PeerState_ESTABLISHED:
		return types.SessionEstablished
	default:
		return types.SessionUnknown
	}
}

// toAgentAfi translates gobgp AFI to cilium bgp AFI.
func toAgentAfi(a gobgp.Family_Afi) types.Afi {
	switch a {
	case gobgp.Family_AFI_UNKNOWN:
		return types.AfiUnknown
	case gobgp.Family_AFI_IP:
		return types.AfiIPv4
	case gobgp.Family_AFI_IP6:
		return types.AfiIPv6
	case gobgp.Family_AFI_L2VPN:
		return types.AfiL2VPN
	case gobgp.Family_AFI_LS:
		return types.AfiLS
	case gobgp.Family_AFI_OPAQUE:
		return types.AfiOpaque
	default:
		return types.AfiUnknown
	}
}

func toGoBGPAfi(afi types.Afi) gobgp.Family_Afi {
	switch afi {
	case types.AfiUnknown:
		return gobgp.Family_AFI_UNKNOWN
	case types.AfiIPv4:
		return gobgp.Family_AFI_IP
	case types.AfiIPv6:
		return gobgp.Family_AFI_IP6
	case types.AfiL2VPN:
		return gobgp.Family_AFI_L2VPN
	case types.AfiLS:
		return gobgp.Family_AFI_LS
	case types.AfiOpaque:
		return gobgp.Family_AFI_OPAQUE
	default:
		return gobgp.Family_AFI_UNKNOWN
	}
}

func toAgentSafi(s gobgp.Family_Safi) types.Safi {
	switch s {
	case gobgp.Family_SAFI_UNKNOWN:
		return types.SafiUnknown
	case gobgp.Family_SAFI_UNICAST:
		return types.SafiUnicast
	case gobgp.Family_SAFI_MULTICAST:
		return types.SafiMulticast
	case gobgp.Family_SAFI_MPLS_LABEL:
		return types.SafiMplsLabel
	case gobgp.Family_SAFI_ENCAPSULATION:
		return types.SafiEncapsulation
	case gobgp.Family_SAFI_VPLS:
		return types.SafiVpls
	case gobgp.Family_SAFI_EVPN:
		return types.SafiEvpn
	case gobgp.Family_SAFI_LS:
		return types.SafiLs
	case gobgp.Family_SAFI_SR_POLICY:
		return types.SafiSrPolicy
	case gobgp.Family_SAFI_MUP:
		return types.SafiMup
	case gobgp.Family_SAFI_MPLS_VPN:
		return types.SafiMplsVpn
	case gobgp.Family_SAFI_MPLS_VPN_MULTICAST:
		return types.SafiMplsVpnMulticast
	case gobgp.Family_SAFI_ROUTE_TARGET_CONSTRAINTS:
		return types.SafiRouteTargetConstraints
	case gobgp.Family_SAFI_FLOW_SPEC_UNICAST:
		return types.SafiFlowSpecUnicast
	case gobgp.Family_SAFI_FLOW_SPEC_VPN:
		return types.SafiFlowSpecVpn
	case gobgp.Family_SAFI_KEY_VALUE:
		return types.SafiKeyValue
	default:
		return types.SafiUnknown
	}
}

func toGoBGPSafi(safi types.Safi) gobgp.Family_Safi {
	switch safi {
	case types.SafiUnknown:
		return gobgp.Family_SAFI_UNKNOWN
	case types.SafiUnicast:
		return gobgp.Family_SAFI_UNICAST
	case types.SafiMulticast:
		return gobgp.Family_SAFI_MULTICAST
	case types.SafiMplsLabel:
		return gobgp.Family_SAFI_MPLS_LABEL
	case types.SafiEncapsulation:
		return gobgp.Family_SAFI_ENCAPSULATION
	case types.SafiVpls:
		return gobgp.Family_SAFI_VPLS
	case types.SafiEvpn:
		return gobgp.Family_SAFI_EVPN
	case types.SafiLs:
		return gobgp.Family_SAFI_LS
	case types.SafiSrPolicy:
		return gobgp.Family_SAFI_SR_POLICY
	case types.SafiMup:
		return gobgp.Family_SAFI_MUP
	case types.SafiMplsVpn:
		return gobgp.Family_SAFI_MPLS_VPN
	case types.SafiMplsVpnMulticast:
		return gobgp.Family_SAFI_MPLS_VPN_MULTICAST
	case types.SafiRouteTargetConstraints:
		return gobgp.Family_SAFI_ROUTE_TARGET_CONSTRAINTS
	case types.SafiFlowSpecUnicast:
		return gobgp.Family_SAFI_FLOW_SPEC_UNICAST
	case types.SafiFlowSpecVpn:
		return gobgp.Family_SAFI_FLOW_SPEC_VPN
	case types.SafiKeyValue:
		return gobgp.Family_SAFI_KEY_VALUE
	default:
		return gobgp.Family_SAFI_UNKNOWN
	}
}

func toAgentPaths(gobgpPaths []*gobgp.Path) []types.Path {
	paths := make([]types.Path, 0, len(gobgpPaths))
	for _, p := range gobgpPaths {
		paths = append(paths, toAgentPath(p))
	}
	return paths
}

func toAgentPath(gobgpPath *gobgp.Path) types.Path {
	var result types.Path
	result.Nlri = toAgentNLRI(gobgpPath.GetFamily(), gobgpPath.GetNlri())
	result.Pattrs = toAgentPAttrs(gobgpPath.GetPattrs())

	result.Family = toAgentFamily(gobgpPath.GetFamily())
	result.Age = gobgpPath.GetAge().AsTime()
	result.Best = gobgpPath.GetBest()
	result.Stale = gobgpPath.GetStale()

	return result
}

func toAgentNLRI(fam *gobgp.Family, nlri *anypb.Any) any {
	unmarshaledNLRI, err := apiutil.UnmarshalNLRI(gobgpb.AfiSafiToRouteFamily(uint16(fam.Afi), uint8(fam.Safi)), nlri)
	if err != nil {
		return nil
	}

	switch nlri := unmarshaledNLRI.(type) {
	case *gobgpb.IPAddrPrefix:
		var result types.IPAddrPrefixNLRI
		result.Prefix = nlri.Prefix.String()
		result.Length = nlri.Length
		return result
	case *gobgpb.IPv6AddrPrefix:
		var result types.IPAddrPrefixNLRI
		result.Prefix = nlri.Prefix.String()
		result.Length = nlri.Length
		return result
	}
	return nil
}

func toGoBGPNLRI(nlri any) *anypb.Any {
	switch nlri := nlri.(type) {
	case types.IPAddrPrefixNLRI:
		prefix, _ := anypb.New(&gobgp.IPAddressPrefix{
			Prefix:    nlri.Prefix,
			PrefixLen: uint32(nlri.Length),
		})
		return prefix
	}
	return nil
}

func toAgentPAttrs(pattrs []*anypb.Any) []any {
	result := make([]any, 0, len(pattrs))
	attrs, err := apiutil.UnmarshalPathAttributes(pattrs)
	if err != nil {
		return result
	}

	for _, attr := range attrs {
		switch attr := attr.(type) {
		case *gobgpb.PathAttributeOrigin:
			result = append(result, toAgentOrigin(attr))
		case *gobgpb.PathAttributeAsPath:
			result = append(result, toAgentAsPath(attr))
		case *gobgpb.PathAttributeNextHop:
			result = append(result, toAgentNextHop(attr))
		case *gobgpb.PathAttributeMultiExitDisc:
			result = append(result, toAgentMultiExitDisc(attr))
		case *gobgpb.PathAttributeLocalPref:
			result = append(result, toAgentLocalPref(attr))
		case *gobgpb.PathAttributeAtomicAggregate:
			result = append(result, toAgentAtomicAggregate(attr))
		case *gobgpb.PathAttributeAggregator:
			result = append(result, toAgentAggregator(attr))
		case *gobgpb.PathAttributeCommunities:
			result = append(result, toAgentCommunities(attr))
		case *gobgpb.PathAttributeOriginatorId:
			result = append(result, toAgentOriginatorId(attr))
		case *gobgpb.PathAttributeClusterList:
			result = append(result, toAgentClusterList(attr))
		case *gobgpb.PathAttributeMpReachNLRI:
			result = append(result, toAgentMpReachNLRI(attr))
		case *gobgpb.PathAttributeMpUnreachNLRI:
			result = append(result, toAgentMpUnreachNLRI(attr))
		case *gobgpb.PathAttributeExtendedCommunities:
			result = append(result, toAgentExtendedCommunities(attr))
		case *gobgpb.PathAttributeIP6ExtendedCommunities:
			result = append(result, toAgentIP6ExtendedCommunities(attr))
		case *gobgpb.PathAttributeLargeCommunities:
			result = append(result, toAgentLargeCommunities(attr))
		case *gobgpb.PathAttributePrefixSID:
			result = append(result, toAgentPrefixSID(attr))
		default:
			continue
		}
	}
	return result
}

func toGoBGPPAttrs(pattrs []any) []*anypb.Any {
	result := make([]*anypb.Any, 0, len(pattrs))
	for _, attr := range pattrs {
		switch attr := attr.(type) {
		case types.PathAttributeOrigin:
			result = append(result, toGoBGPOrigin(attr))
		case types.PathAttributeASPath:
			result = append(result, toGoBGPAsPath(attr))
		case types.PathAttributeNextHop:
			result = append(result, toGoBGPNextHop(attr))
		case types.PathAttributeMultiExitDisc:
			result = append(result, toGoBGPMultiExitDisc(attr))
		case types.PathAttributeLocalPref:
			result = append(result, toGoBGPLocalPref(attr))
		case types.PathAttributeAtomicAggregate:
			result = append(result, toGoBGPAtomicAggregate(attr))
		case types.PathAttributeAggregator:
			result = append(result, toGoBGPAggregator(attr))
		case types.PathAttributeCommunities:
			result = append(result, toGoBGPCommunities(attr))
		case types.PathAttributeOriginatorId:
			result = append(result, toGoBGPOriginatorId(attr))
		case types.PathAttributeClusterList:
			result = append(result, toGoBGPClusterList(attr))
		case types.PathAttributeMpReachNLRI:
			result = append(result, toGoBGPMpReachNLRI(attr))
		case types.PathAttributeMpUnreachNLRI:
			result = append(result, toGoBGPMpUnreachNLRI(attr))
		case types.PathAttributeExtendedCommunities:
			result = append(result, toGoBGPExtendedCommunities(attr))
		case types.PathAttributeIP6ExtendedCommunities:
			result = append(result, toGoBGP6ExtendedCommunities(attr))
		case types.PathAttributeLargeCommunities:
			result = append(result, toGoBGPLargeCommunities(attr))
		case types.PathAttributePrefixSID:
			result = append(result, toGoBGPPrefixSID(attr))
		default:
			continue
		}
	}
	return result
}
