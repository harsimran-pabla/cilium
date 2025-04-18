// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumiov2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	gentype "k8s.io/client-go/gentype"
)

// fakeCiliumBGPAdvertisements implements CiliumBGPAdvertisementInterface
type fakeCiliumBGPAdvertisements struct {
	*gentype.FakeClientWithList[*v2.CiliumBGPAdvertisement, *v2.CiliumBGPAdvertisementList]
	Fake *FakeCiliumV2
}

func newFakeCiliumBGPAdvertisements(fake *FakeCiliumV2) ciliumiov2.CiliumBGPAdvertisementInterface {
	return &fakeCiliumBGPAdvertisements{
		gentype.NewFakeClientWithList[*v2.CiliumBGPAdvertisement, *v2.CiliumBGPAdvertisementList](
			fake.Fake,
			"",
			v2.SchemeGroupVersion.WithResource("ciliumbgpadvertisements"),
			v2.SchemeGroupVersion.WithKind("CiliumBGPAdvertisement"),
			func() *v2.CiliumBGPAdvertisement { return &v2.CiliumBGPAdvertisement{} },
			func() *v2.CiliumBGPAdvertisementList { return &v2.CiliumBGPAdvertisementList{} },
			func(dst, src *v2.CiliumBGPAdvertisementList) { dst.ListMeta = src.ListMeta },
			func(list *v2.CiliumBGPAdvertisementList) []*v2.CiliumBGPAdvertisement {
				return gentype.ToPointerSlice(list.Items)
			},
			func(list *v2.CiliumBGPAdvertisementList, items []*v2.CiliumBGPAdvertisement) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
