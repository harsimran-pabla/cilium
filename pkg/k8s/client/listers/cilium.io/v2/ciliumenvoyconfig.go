// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by lister-gen. DO NOT EDIT.

package v2

import (
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// CiliumEnvoyConfigLister helps list CiliumEnvoyConfigs.
// All objects returned here must be treated as read-only.
type CiliumEnvoyConfigLister interface {
	// List lists all CiliumEnvoyConfigs in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2.CiliumEnvoyConfig, err error)
	// CiliumEnvoyConfigs returns an object that can list and get CiliumEnvoyConfigs.
	CiliumEnvoyConfigs(namespace string) CiliumEnvoyConfigNamespaceLister
	CiliumEnvoyConfigListerExpansion
}

// ciliumEnvoyConfigLister implements the CiliumEnvoyConfigLister interface.
type ciliumEnvoyConfigLister struct {
	listers.ResourceIndexer[*v2.CiliumEnvoyConfig]
}

// NewCiliumEnvoyConfigLister returns a new CiliumEnvoyConfigLister.
func NewCiliumEnvoyConfigLister(indexer cache.Indexer) CiliumEnvoyConfigLister {
	return &ciliumEnvoyConfigLister{listers.New[*v2.CiliumEnvoyConfig](indexer, v2.Resource("ciliumenvoyconfig"))}
}

// CiliumEnvoyConfigs returns an object that can list and get CiliumEnvoyConfigs.
func (s *ciliumEnvoyConfigLister) CiliumEnvoyConfigs(namespace string) CiliumEnvoyConfigNamespaceLister {
	return ciliumEnvoyConfigNamespaceLister{listers.NewNamespaced[*v2.CiliumEnvoyConfig](s.ResourceIndexer, namespace)}
}

// CiliumEnvoyConfigNamespaceLister helps list and get CiliumEnvoyConfigs.
// All objects returned here must be treated as read-only.
type CiliumEnvoyConfigNamespaceLister interface {
	// List lists all CiliumEnvoyConfigs in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2.CiliumEnvoyConfig, err error)
	// Get retrieves the CiliumEnvoyConfig from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v2.CiliumEnvoyConfig, error)
	CiliumEnvoyConfigNamespaceListerExpansion
}

// ciliumEnvoyConfigNamespaceLister implements the CiliumEnvoyConfigNamespaceLister
// interface.
type ciliumEnvoyConfigNamespaceLister struct {
	listers.ResourceIndexer[*v2.CiliumEnvoyConfig]
}
