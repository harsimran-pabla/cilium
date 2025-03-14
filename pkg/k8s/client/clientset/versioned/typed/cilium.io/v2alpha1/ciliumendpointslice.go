// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v2alpha1

import (
	context "context"

	ciliumiov2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// CiliumEndpointSlicesGetter has a method to return a CiliumEndpointSliceInterface.
// A group's client should implement this interface.
type CiliumEndpointSlicesGetter interface {
	CiliumEndpointSlices() CiliumEndpointSliceInterface
}

// CiliumEndpointSliceInterface has methods to work with CiliumEndpointSlice resources.
type CiliumEndpointSliceInterface interface {
	Create(ctx context.Context, ciliumEndpointSlice *ciliumiov2alpha1.CiliumEndpointSlice, opts v1.CreateOptions) (*ciliumiov2alpha1.CiliumEndpointSlice, error)
	Update(ctx context.Context, ciliumEndpointSlice *ciliumiov2alpha1.CiliumEndpointSlice, opts v1.UpdateOptions) (*ciliumiov2alpha1.CiliumEndpointSlice, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*ciliumiov2alpha1.CiliumEndpointSlice, error)
	List(ctx context.Context, opts v1.ListOptions) (*ciliumiov2alpha1.CiliumEndpointSliceList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *ciliumiov2alpha1.CiliumEndpointSlice, err error)
	CiliumEndpointSliceExpansion
}

// ciliumEndpointSlices implements CiliumEndpointSliceInterface
type ciliumEndpointSlices struct {
	*gentype.ClientWithList[*ciliumiov2alpha1.CiliumEndpointSlice, *ciliumiov2alpha1.CiliumEndpointSliceList]
}

// newCiliumEndpointSlices returns a CiliumEndpointSlices
func newCiliumEndpointSlices(c *CiliumV2alpha1Client) *ciliumEndpointSlices {
	return &ciliumEndpointSlices{
		gentype.NewClientWithList[*ciliumiov2alpha1.CiliumEndpointSlice, *ciliumiov2alpha1.CiliumEndpointSliceList](
			"ciliumendpointslices",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *ciliumiov2alpha1.CiliumEndpointSlice { return &ciliumiov2alpha1.CiliumEndpointSlice{} },
			func() *ciliumiov2alpha1.CiliumEndpointSliceList { return &ciliumiov2alpha1.CiliumEndpointSliceList{} },
		),
	}
}
