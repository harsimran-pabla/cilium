package types

import (
	"time"
)

// Prefix is the BGP prefix and associated PathAttributes
type Prefix struct {
	Prefix string
	Paths  []Path
}

type Path struct {
	Nlri   any
	Pattrs []any
	Age    time.Time
	Best   bool
	Stale  bool
	Family Family
}

type IPAddrPrefixNLRI struct {
	Prefix string
	Length uint8
}

type PathAttributeOrigin struct {
	Origin uint8
}

type PathAttributeASPath struct {
	Type   uint8
	Length uint8
	ASNs   []uint32
}

type PathAttributeNextHop struct {
	NextHop string
}

type PathAttributeMultiExitDisc struct {
	MED uint32
}

type PathAttributeLocalPref struct {
	LocalPref uint32
}

type PathAttributeAtomicAggregate struct {
}

type PathAttributeAggregator struct {
	ASN     uint32
	Address string
}

type PathAttributeCommunities struct {
	Communities []uint32
}

type PathAttributeOriginatorId struct {
	OriginatorId string
}

type PathAttributeClusterList struct {
	ClusterList []string
}

type PathAttributeMpReachNLRI struct {
	Family  Family
	NextHop string
	NLRI    []any
}

type PathAttributeMpUnreachNLRI struct {
	Family Family
	NLRI   []any
}

type PathAttributeExtendedCommunities struct {
	ExtendedCommunities []uint64
}

type PathAttributeAs4Path struct {
	Type   uint8
	Length uint8
	ASNs   []uint32
}

type PathAttributeAs4Aggregator struct {
	ASN     uint32
	Address string
}

type PathAttributeAsPathLimit struct {
	ASN uint32
}

type PathAttributeLargeCommunities struct {
	LargeCommunities []uint64
}

type PathAttributeIP6ExtendedCommunities struct {
	ExtendedCommunities []uint64
}

type PathAttributeAttrSet struct {
	AttrSet []uint64
}

type PathAttributePrefixSID struct {
	Flags     uint8
	MPLSLabel uint32
	MTID      uint8
	Algorithm uint8
	SID       uint32
}
