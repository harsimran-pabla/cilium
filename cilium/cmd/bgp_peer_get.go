// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
)

var BgpPeersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List current state of all peers",
	Long:  "List state of all peers defined in CiliumBGPPeeringPolicy",
	Run: func(cmd *cobra.Command, args []string) {
		res, err := client.Bgp.GetBgpPeers(nil)
		if err != nil {
			Fatalf("cannot get peers list: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(res.GetPayload()); err != nil {
				Fatalf("error getting output in JSON: %s\n", err)
			}
		} else {
			printSummary(res.GetPayload())
		}
	},
}

func printSummary(peers []*models.BgpPeer) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	// sort by local AS, if peers from same AS then sort by peer address.
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].LocalAsn < peers[j].LocalAsn || peers[i].PeerAddress < peers[j].PeerAddress
	})

	fmt.Fprintln(w, "Local AS\tPeer AS\tPeer Address\tSession\tUptime\tFamily\tReceived\tAdvertised\tEnabled")
	for _, peer := range peers {
		for _, afisafi := range peer.AfiSafi {
			fmt.Fprintf(w, "%d\t", peer.LocalAsn)
			fmt.Fprintf(w, "%d\t", peer.PeerAsn)
			fmt.Fprintf(w, "%s\t", peer.PeerAddress)
			fmt.Fprintf(w, "%s\t", peer.SessionState)
			fmt.Fprintf(w, "%s\t", peer.Uptime)

			// AFI and SAFI are concatenated for brevity
			fmt.Fprintf(w, "%s_%s\t", afisafi.Afi, afisafi.Safi)
			fmt.Fprintf(w, "%d\t", afisafi.Received)
			fmt.Fprintf(w, "%d\t", afisafi.Advertised)
			fmt.Fprintf(w, "%s\t", strconv.FormatBool(afisafi.Enabled))
			fmt.Fprintf(w, "\n")
		}
	}
	w.Flush()
}

func init() {
	bgpCmd.AddCommand(BgpPeersCmd)
	command.AddOutputOption(BgpPeersCmd)
}
