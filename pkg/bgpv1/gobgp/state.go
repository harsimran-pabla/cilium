// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"

	gobgp "github.com/osrg/gobgp/v3/api"
)

// GetBgp returns bgp global configuration from gobgp server
func (g *GoBGPServer) GetBGP(ctx context.Context) (types.GetBGPResponse, error) {
	bgpConfig, err := g.server.GetBgp(ctx, &gobgp.GetBgpRequest{})
	if err != nil {
		return types.GetBGPResponse{}, err
	}

	if bgpConfig.Global == nil {
		return types.GetBGPResponse{}, fmt.Errorf("gobgp returned nil config")
	}

	res := types.BGPGlobal{
		ASN:        bgpConfig.Global.Asn,
		RouterID:   bgpConfig.Global.RouterId,
		ListenPort: bgpConfig.Global.ListenPort,
	}
	if bgpConfig.Global.RouteSelectionOptions != nil {
		res.RouteSelectionOptions = &types.RouteSelectionOptions{
			AdvertiseInactiveRoutes: bgpConfig.Global.RouteSelectionOptions.AdvertiseInactiveRoutes,
		}
	}

	return types.GetBGPResponse{
		Global: res,
	}, nil
}

// GetPeerState invokes goBGP ListPeer API to get current peering state.
func (g *GoBGPServer) GetPeerState(ctx context.Context) (types.GetPeerStateResponse, error) {
	var data []*models.BgpPeer
	fn := func(peer *gobgp.Peer) {
		if peer == nil {
			return
		}

		peerState := &models.BgpPeer{}

		if peer.Transport != nil {
			peerState.PeerPort = int64(peer.Transport.RemotePort)
		}

		if peer.Conf != nil {
			peerState.LocalAsn = int64(peer.Conf.LocalAsn)
			peerState.PeerAddress = peer.Conf.NeighborAddress
			peerState.PeerAsn = int64(peer.Conf.PeerAsn)
		}

		if peer.State != nil {
			peerState.SessionState = toAgentSessionState(peer.State.SessionState).String()

			// Uptime is time since session got established.
			// It is calculated by difference in time from uptime timestamp till now.
			if peer.State.SessionState == gobgp.PeerState_ESTABLISHED && peer.Timers != nil && peer.Timers.State != nil {
				peerState.UptimeNanoseconds = int64(time.Now().Sub(peer.Timers.State.Uptime.AsTime()))
			}
		}

		for _, afiSafi := range peer.AfiSafis {
			if afiSafi.State == nil {
				continue
			}
			peerState.Families = append(peerState.Families, toAgentAfiSafiState(afiSafi.State))
		}

		if peer.EbgpMultihop != nil && peer.EbgpMultihop.Enabled {
			peerState.EbgpMultihopTTL = int64(peer.EbgpMultihop.MultihopTtl)
		} else {
			peerState.EbgpMultihopTTL = int64(v2alpha1api.DefaultBGPEBGPMultihopTTL) // defaults to 1 if not enabled
		}

		if peer.Timers != nil {
			tConfig := peer.Timers.Config
			tState := peer.Timers.State
			if tConfig != nil {
				peerState.ConnectRetryTimeSeconds = int64(tConfig.ConnectRetry)
				peerState.ConfiguredHoldTimeSeconds = int64(tConfig.HoldTime)
				peerState.ConfiguredKeepAliveTimeSeconds = int64(tConfig.KeepaliveInterval)
			}
			if tState != nil {
				if tState.NegotiatedHoldTime != 0 {
					peerState.AppliedHoldTimeSeconds = int64(tState.NegotiatedHoldTime)
				}
				if tState.KeepaliveInterval != 0 {
					peerState.AppliedKeepAliveTimeSeconds = int64(tState.KeepaliveInterval)
				}
			}
		}

		peerState.GracefulRestart = &models.BgpGracefulRestart{}
		if peer.GracefulRestart != nil {
			peerState.GracefulRestart.Enabled = peer.GracefulRestart.Enabled
			peerState.GracefulRestart.RestartTimeSeconds = int64(peer.GracefulRestart.RestartTime)
		}

		data = append(data, peerState)
	}

	// API to get peering list from gobgp, enableAdvertised is set to true to get count of
	// advertised routes.
	err := g.server.ListPeer(ctx, &gobgp.ListPeerRequest{EnableAdvertised: true}, fn)
	if err != nil {
		return types.GetPeerStateResponse{}, err
	}

	return types.GetPeerStateResponse{
		Peers: data,
	}, nil
}

// GetPrefixes invokes GoBGP ListPath to get current paths from BGP routing tables. It can be filtered
// by table type, family and neighbor address.
func (g *GoBGPServer) GetPrefixes(ctx context.Context, r types.GetPrefixesRequest) (types.GetPrefixesResponse, error) {
	var destinations []types.Prefix

	fn := func(destination *gobgp.Destination) {
		destinations = append(destinations, types.Prefix{
			Prefix: destination.Prefix,
			Paths:  toAgentPaths(destination.Paths),
		})
	}

	if err := g.server.ListPath(ctx, &gobgp.ListPathRequest{
		TableType: toGoBGPTableType(r.TableType),
		Family:    toGoBGPFamily(r.Family),
		Name:      r.Name,
	}, fn); err != nil {
		return types.GetPrefixesResponse{}, err
	}

	return types.GetPrefixesResponse{
		Prefixes: destinations,
	}, nil
}
