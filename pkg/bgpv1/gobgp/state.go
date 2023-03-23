// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"time"

	gobgp "github.com/osrg/gobgp/v3/api"

	"github.com/cilium/cilium/api/v1/models"
)

// GetPeerState invokes goBGP ListPeer API to get current peering state.
func (sc *ServerWithConfig) GetPeerState(ctx context.Context) ([]*models.BgpPeer, error) {
	var data []*models.BgpPeer
	fn := func(peer *gobgp.Peer) {
		if peer == nil {
			return
		}

		peerState := &models.BgpPeer{}

		if peer.Conf != nil {
			peerState.LocalAsn = int64(peer.Conf.LocalAsn)
			peerState.PeerAddress = peer.Conf.NeighborAddress
			peerState.PeerAsn = int64(peer.Conf.PeerAsn)
		}

		if peer.State != nil {
			peerState.SessionState = peer.State.SessionState.String()
			peerState.AdminState = peer.State.AdminState.String()

			// Uptime is time since session got established.
			// It is calculated by difference in time from uptime timestamp till now.
			// Time is rounded to second precision.
			if peer.State.SessionState == gobgp.PeerState_ESTABLISHED && peer.Timers != nil && peer.Timers.State != nil {
				peerState.Uptime = time.Now().Sub(peer.Timers.State.Uptime.AsTime()).Round(time.Second).String()
			}
		}

		for _, afiSafi := range peer.AfiSafis {
			afiSafiState := afiSafi.State
			if afiSafiState == nil {
				continue
			}
			peerState.AfiSafi = append(peerState.AfiSafi, toAgentAfiSafiState(afiSafiState))
		}

		data = append(data, peerState)
	}

	// API to get peering list from gobgp, enableAdvertised is set to true to get count of
	// advertised routes.
	err := sc.Server.ListPeer(ctx, &gobgp.ListPeerRequest{EnableAdvertised: true}, fn)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// toAgentAfiSafiState translates gobgp structures to cilium bgp models.
func toAgentAfiSafiState(state *gobgp.AfiSafiState) *models.BgpPeerAfiSafi {
	res := &models.BgpPeerAfiSafi{}

	if state.Family != nil {
		res.Afi = state.Family.Afi.String()
		res.Safi = state.Family.Safi.String()
	}

	res.Enabled = state.Enabled
	res.Received = int64(state.Received)
	res.Accepted = int64(state.Accepted)
	res.Advertised = int64(state.Advertised)

	return res
}
