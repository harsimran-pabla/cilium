// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/lock"
)

// Limits specifies the IPAM relevant instance limits
type Limits struct {
	// Adapters specifies the maximum number of interfaces that can be
	// attached to the instance
	Adapters int

	// IPv4 is the maximum number of IPv4 addresses per adapter/interface
	IPv4 int

	// IPv6 is the maximum number of IPv6 addresses per adapter/interface
	IPv6 int

	// HypervisorType tracks the instance's hypervisor type if available. Used to determine if features like prefix
	// delegation are supported on an instance. Bare metal instances would have empty string.
	HypervisorType string

	// IsBareMetal tracks whether an instance is a bare metal instance or not
	IsBareMetal bool
}

// AllocationIP is an IP which is available for allocation, or already
// has been allocated
type AllocationIP struct {
	// Owner is the owner of the IP. This field is set if the IP has been
	// allocated. It will be set to the pod name or another identifier
	// representing the usage of the IP
	//
	// The owner field is left blank for an entry in Spec.IPAM.Pool and
	// filled out as the IP is used and also added to Status.IPAM.Used.
	//
	// +optional
	Owner string `json:"owner,omitempty"`

	// Resource is set for both available and allocated IPs, it represents
	// what resource the IP is associated with, e.g. in combination with
	// AWS ENI, this will refer to the ID of the ENI
	//
	// +optional
	Resource string `json:"resource,omitempty"`
}

// AllocationMap is a map of allocated IPs indexed by IP
type AllocationMap map[string]AllocationIP

// IPAMPodCIDR is a pod CIDR
//
// +kubebuilder:validation:Format=cidr
type IPAMPodCIDR string

func (c *IPAMPodCIDR) ToPrefix() (*netip.Prefix, error) {
	if c == nil {
		return nil, fmt.Errorf("nil ipam cidr")
	}

	prefix, err := netip.ParsePrefix(string(*c))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ipam cidr %v: %w", c, err)
	}

	return &prefix, nil
}

// IPAMPoolAllocation describes an allocation of an IPAM pool from the operator to the
// node. It contains the assigned PodCIDRs allocated from this pool
type IPAMPoolAllocation struct {
	// Pool is the name of the IPAM pool backing this allocation
	//
	// +kubebuilder:validation:MinLength=1
	Pool string `json:"pool"`

	// CIDRs contains a list of pod CIDRs currently allocated from this pool
	//
	// +optional
	CIDRs []IPAMPodCIDR `json:"cidrs,omitempty"`
}

type IPAMPoolRequest struct {
	// Pool is the name of the IPAM pool backing this request
	//
	// +kubebuilder:validation:MinLength=1
	Pool string `json:"pool"`

	// Needed indicates how many IPs out of the above Pool this node requests
	// from the operator. The operator runs a reconciliation loop to ensure each
	// node always has enough PodCIDRs allocated in each pool to fulfill the
	// requested number of IPs here.
	//
	// +optional
	Needed IPAMPoolDemand `json:"needed,omitempty"`
}

type IPAMPoolSpec struct {
	// Requested contains a list of IPAM pool requests, i.e. indicates how many
	// addresses this node requests out of each pool listed here. This field
	// is owned and written to by cilium-agent and read by the operator.
	//
	// +optional
	Requested []IPAMPoolRequest `json:"requested,omitempty"`

	// Allocated contains the list of pooled CIDR assigned to this node. The
	// operator will add new pod CIDRs to this field, whereas the agent will
	// remove CIDRs it has released.
	//
	// +optional
	Allocated []IPAMPoolAllocation `json:"allocated,omitempty"`
}

// IPAMSpec is the IPAM specification of the node
//
// This structure is embedded into v2.CiliumNode
type IPAMSpec struct {
	// Pool is the list of IPv4 addresses available to the node for allocation.
	// When an IPv4 address is used, it will remain on this list but will be added to
	// Status.IPAM.Used
	//
	// +optional
	Pool AllocationMap `json:"pool,omitempty"`

	// IPv6Pool is the list of IPv6 addresses available to the node for allocation.
	// When an IPv6 address is used, it will remain on this list but will be added to
	// Status.IPAM.IPv6Used
	//
	// +optional
	IPv6Pool AllocationMap `json:"ipv6-pool,omitempty"`

	// Pools contains the list of assigned IPAM pools for this node.
	//
	// +optional
	Pools IPAMPoolSpec `json:"pools,omitempty"`

	// PodCIDRs is the list of CIDRs available to the node for allocation.
	// When an IP is used, the IP will be added to Status.IPAM.Used
	//
	// +optional
	PodCIDRs []string `json:"podCIDRs,omitempty"`

	// MinAllocate is the minimum number of IPs that must be allocated when
	// the node is first bootstrapped. It defines the minimum base socket
	// of addresses that must be available. After reaching this watermark,
	// the PreAllocate and MaxAboveWatermark logic takes over to continue
	// allocating IPs.
	//
	// +kubebuilder:validation:Minimum=0
	MinAllocate int `json:"min-allocate,omitempty"`

	// MaxAllocate is the maximum number of IPs that can be allocated to the
	// node. When the current amount of allocated IPs will approach this value,
	// the considered value for PreAllocate will decrease down to 0 in order to
	// not attempt to allocate more addresses than defined.
	//
	// +kubebuilder:validation:Minimum=0
	MaxAllocate int `json:"max-allocate,omitempty"`

	// PreAllocate defines the number of IP addresses that must be
	// available for allocation in the IPAMspec. It defines the buffer of
	// addresses available immediately without requiring cilium-operator to
	// get involved.
	//
	// +kubebuilder:validation:Minimum=0
	PreAllocate int `json:"pre-allocate,omitempty"`

	// MaxAboveWatermark is the maximum number of addresses to allocate
	// beyond the addresses needed to reach the PreAllocate watermark.
	// Going above the watermark can help reduce the number of API calls to
	// allocate IPs, e.g. when a new ENI is allocated, as many secondary
	// IPs as possible are allocated. Limiting the amount can help reduce
	// waste of IPs.
	//
	// +kubebuilder:validation:Minimum=0
	MaxAboveWatermark int `json:"max-above-watermark,omitempty"`

	// StaticIPTags are used to determine the pool of IPs from which to
	// attribute a static IP to the node. For example in AWS this is used to
	// filter Elastic IP Addresses.
	//
	// +optional
	StaticIPTags map[string]string `json:"static-ip-tags,omitempty"`
}

// IPReleaseStatus defines the valid states in IP release handshake
//
// +kubebuilder:validation:Enum=marked-for-release;ready-for-release;do-not-release;released
type IPReleaseStatus string

// IPAMStatus is the IPAM status of a node
//
// This structure is embedded into v2.CiliumNode
type IPAMStatus struct {
	// Used lists all IPv4 addresses out of Spec.IPAM.Pool which have been allocated
	// and are in use.
	//
	// +optional
	Used AllocationMap `json:"used,omitempty"`

	// IPv6Used lists all IPv6 addresses out of Spec.IPAM.IPv6Pool which have been
	// allocated and are in use.
	//
	// +optional
	IPv6Used AllocationMap `json:"ipv6-used,omitempty"`

	// PodCIDRs lists the status of each pod CIDR allocated to this node.
	//
	// +optional
	PodCIDRs PodCIDRMap `json:"pod-cidrs,omitempty"`

	// Operator is the Operator status of the node
	//
	// +optional
	OperatorStatus OperatorStatus `json:"operator-status,omitempty"`

	// ReleaseIPs tracks the state for every IPv4 address considered for release.
	// The value can be one of the following strings:
	// * marked-for-release : Set by operator as possible candidate for IP
	// * ready-for-release  : Acknowledged as safe to release by agent
	// * do-not-release     : IP already in use / not owned by the node. Set by agent
	// * released           : IP successfully released. Set by operator
	//
	// +optional
	ReleaseIPs map[string]IPReleaseStatus `json:"release-ips,omitempty"`

	// ReleaseIPv6s tracks the state for every IPv6 address considered for release.
	// The value can be one of the following strings:
	// * marked-for-release : Set by operator as possible candidate for IP
	// * ready-for-release  : Acknowledged as safe to release by agent
	// * do-not-release     : IP already in use / not owned by the node. Set by agent
	// * released           : IP successfully released. Set by operator
	//
	// +optional
	ReleaseIPv6s map[string]IPReleaseStatus `json:"release-ipv6s,omitempty"`

	// AssignedStaticIP is the static IP assigned to the node (ex: public Elastic IP address in AWS)
	//
	// +optional
	AssignedStaticIP string `json:"assigned-static-ip,omitempty"`
}

// IPAMPoolRequest is a request from the agent to the operator, indicating how
// may IPs it requires from a given pool
type IPAMPoolDemand struct {
	// IPv4Addrs contains the number of requested IPv4 addresses out of a given
	// pool
	//
	// +optional
	IPv4Addrs int `json:"ipv4-addrs,omitempty"`

	// IPv6Addrs contains the number of requested IPv6 addresses out of a given
	// pool
	//
	// +optional
	IPv6Addrs int `json:"ipv6-addrs,omitempty"`
}

type PodCIDRMap map[string]PodCIDRMapEntry

// +kubebuilder:validation:Enum=released;depleted;in-use
type PodCIDRStatus string

const (
	PodCIDRStatusReleased PodCIDRStatus = "released"
	PodCIDRStatusDepleted PodCIDRStatus = "depleted"
	PodCIDRStatusInUse    PodCIDRStatus = "in-use"
)

type PodCIDRMapEntry struct {
	// Status describes the status of a pod CIDR
	//
	// +optional
	Status PodCIDRStatus `json:"status,omitempty"`
}

// OperatorStatus is the status used by cilium-operator to report
// errors in case the allocation CIDR failed.
type OperatorStatus struct {
	// Error is the error message set by cilium-operator.
	//
	// +optional
	Error string `json:"error,omitempty"`
}

// Tags implements generic key value tags
type Tags map[string]string

// Match returns true if the required tags are all found
func (t Tags) Match(required Tags) bool {
	for k, neededvalue := range required {
		haveValue, ok := t[k]
		if !ok || (ok && neededvalue != haveValue) {
			return false
		}
	}
	return true
}

// Subnet is a representation of a subnet
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type Subnet struct {
	// ID is the subnet ID
	ID string

	// Name is the subnet name
	Name string

	// CIDR is the IPv4 CIDR associated with the subnet
	CIDR netip.Prefix

	// IPv6CIDR is the IPv6 CIDR associated with the subnet
	IPv6CIDR netip.Prefix

	// AvailabilityZone is the availability zone of the subnet
	AvailabilityZone string

	// VirtualNetworkID is the virtual network the subnet is in
	VirtualNetworkID string

	// AvailableAddresses is the number of IPv4 addresses available for
	// allocation
	AvailableAddresses int

	// AvailableIPv6Addresses is the number of IPv6 addresses available for
	// allocation
	AvailableIPv6Addresses int

	// Tags is the tags of the subnet
	Tags Tags
}

// DeepEqual is a deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *Subnet) DeepEqual(other *Subnet) bool {
	if other == nil {
		return false
	}

	if in.ID != other.ID {
		return false
	}
	if in.Name != other.Name {
		return false
	}
	if in.CIDR != other.CIDR {
		return false
	}

	if in.IPv6CIDR != other.IPv6CIDR {
		return false
	}

	if in.AvailabilityZone != other.AvailabilityZone {
		return false
	}
	if in.VirtualNetworkID != other.VirtualNetworkID {
		return false
	}
	if in.AvailableAddresses != other.AvailableAddresses {
		return false
	}
	if in.AvailableIPv6Addresses != other.AvailableIPv6Addresses {
		return false
	}
	if ((in.Tags != nil) && (other.Tags != nil)) || ((in.Tags == nil) != (other.Tags == nil)) {
		in, other := &in.Tags, &other.Tags
		if !in.DeepEqual(other) {
			return false
		}
	}

	return true
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Subnet) DeepCopyInto(out *Subnet) {
	*out = *in
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make(Tags, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is a deepcopy function, copying the receiver, creating a new Subnet.
func (in *Subnet) DeepCopy() *Subnet {
	if in == nil {
		return nil
	}
	out := new(Subnet)
	in.DeepCopyInto(out)
	return out
}

// SubnetMap indexes subnets by subnet ID
type SubnetMap map[string]*Subnet

// FirstSubnetWithAvailableAddresses returns the first pool ID in the list of
// subnets with available addresses. If any of the preferred pool IDs have
// available addresses, the first pool ID with available addresses is returned.
func (m SubnetMap) FirstSubnetWithAvailableAddresses(preferredPoolIDs []PoolID) (PoolID, int) {
	for _, p := range preferredPoolIDs {
		if s := m[string(p)]; s != nil {
			if s.AvailableAddresses > 0 {
				return p, s.AvailableAddresses
			}
		}
	}

	for poolID, s := range m {
		if s.AvailableAddresses > 0 {
			return PoolID(poolID), s.AvailableAddresses
		}
	}

	return PoolNotExists, 0
}

// VirtualNetwork is the representation of a virtual network
type VirtualNetwork struct {
	// ID is the ID of the virtual network
	ID string

	// PrimaryCIDR is the primary IPv4 CIDR
	PrimaryCIDR string

	// CIDRs is the list of secondary IPv4 CIDR ranges associated with the VPC
	CIDRs []string

	// IPv6CIDRs is the list of IPv6 CIDR ranges associated with the VPC
	IPv6CIDRs []string
}

// VirtualNetworkMap indexes virtual networks by their ID
type VirtualNetworkMap map[string]*VirtualNetwork

// RouteTable is a representation of a route table but only for the purpose of
// to check the subnets are in the same route table. It is not a full
// representation of a route table.
type RouteTable struct {
	// ID is the ID of the route table
	ID string

	// VirtualNetworkID is the virtual network the route table is in
	VirtualNetworkID string

	// Subnets maps subnet IDs to their presence in this route table
	// +deepequal-gen=false
	Subnets map[string]struct{}
}

// RouteTableMap indexes route tables by their ID
type RouteTableMap map[string]*RouteTable

// PoolNotExists indicate that no such pool ID exists
const PoolNotExists = PoolID("")

// PoolUnspec indicates that the pool ID is unspecified
const PoolUnspec = PoolNotExists

// PoolID is the type used to identify an IPAM pool
type PoolID string

// PoolQuota defines the limits of an IPAM pool
type PoolQuota struct {
	// AvailabilityZone is the availability zone in which the IPAM pool resides in
	AvailabilityZone string

	// AvailableIPs is the number of available IPs in the pool
	AvailableIPs int

	// AvailableIPv6s is the number of available IPv6 addresses in the pool
	AvailableIPv6s int
}

// PoolQuotaMap is a map of pool quotas indexes by pool identifier
type PoolQuotaMap map[PoolID]PoolQuota

// Interface is the implementation of a IPAM relevant network interface
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type Interface interface {
	// InterfaceID must return the identifier of the interface
	InterfaceID() string

	// ForeachAddress must iterate over all addresses of the interface and
	// call fn for each address
	ForeachAddress(instanceID string, fn AddressIterator) error

	// DeepCopyInterface returns a deep copy of the underlying interface type.
	DeepCopyInterface() Interface
}

// InterfaceRevision is the configurationr revision of a network interface. It
// consists of a revision hash representing the current configuration version
// and the resource itself.
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type InterfaceRevision struct {
	// Resource is the interface resource
	Resource Interface

	// Fingerprint is the fingerprint reprsenting the network interface
	// configuration. It is typically implemented as the result of a hash
	// function calculated off the resource. This field is optional, not
	// all IPAM backends make use of fingerprints.
	Fingerprint string
}

// DeepCopy returns a deep copy
func (i *InterfaceRevision) DeepCopy() *InterfaceRevision {
	if i == nil {
		return nil
	}
	return &InterfaceRevision{
		Resource:    i.Resource.DeepCopyInterface(),
		Fingerprint: i.Fingerprint,
	}
}

// Instance is the representation of an instance, typically a VM, subject to
// per-node IPAM logic
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type Instance struct {
	// interfaces is a map of all interfaces attached to the instance
	// indexed by the interface ID
	Interfaces map[string]InterfaceRevision
}

// DeepCopy returns a deep copy
func (i *Instance) DeepCopy() *Instance {
	if i == nil {
		return nil
	}
	c := &Instance{
		Interfaces: map[string]InterfaceRevision{},
	}
	for k, v := range i.Interfaces {
		c.Interfaces[k] = *v.DeepCopy()
	}
	return c
}

// InstanceMap is the list of all instances indexed by instance ID
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type InstanceMap struct {
	mutex lock.RWMutex
	data  map[string]*Instance
}

// NewInstanceMap returns a new InstanceMap
func NewInstanceMap() *InstanceMap {
	return &InstanceMap{data: map[string]*Instance{}}
}

// UpdateInstance updates the interfaces map for a particular instance.
func (m *InstanceMap) UpdateInstance(instanceID string, instance *Instance) {
	m.mutex.Lock()
	m.data[instanceID] = instance
	m.mutex.Unlock()
}

// Update updates the definition of an interface for a particular instance. If
// the interface is already known, the definition is updated, otherwise the
// interface is added to the instance.
func (m *InstanceMap) Update(instanceID string, iface InterfaceRevision) {
	m.mutex.Lock()
	m.updateLocked(instanceID, iface)
	m.mutex.Unlock()
}

func (m *InstanceMap) updateLocked(instanceID string, iface InterfaceRevision) {
	if iface.Resource == nil {
		return
	}

	i, ok := m.data[instanceID]
	if !ok {
		i = &Instance{}
		m.data[instanceID] = i
	}

	if i.Interfaces == nil {
		i.Interfaces = map[string]InterfaceRevision{}
	}

	i.Interfaces[iface.Resource.InterfaceID()] = iface
}

type Address any

// AddressIterator is the function called by the ForeachAddress iterator
type AddressIterator func(instanceID, interfaceID, ip, poolID string, address Address) error

func foreachAddress(instanceID string, instance *Instance, fn AddressIterator) error {
	for _, rev := range instance.Interfaces {
		if err := rev.Resource.ForeachAddress(instanceID, fn); err != nil {
			return err
		}
	}

	return nil
}

// ForeachAddress calls fn for each address on each interface attached to each
// instance. If an instanceID is specified, the only the interfaces and
// addresses of the specified instance are considered.
//
// The InstanceMap is read-locked throughout the iteration process, i.e., no
// updates will occur. However, the address object given to the AddressIterator
// will point to live data and must be deep copied if used outside of the
// context of the iterator function.
func (m *InstanceMap) ForeachAddress(instanceID string, fn AddressIterator) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if instanceID != "" {
		if instance := m.data[instanceID]; instance != nil {
			return foreachAddress(instanceID, instance, fn)
		}
		return fmt.Errorf("instance does not exist: %q", instanceID)
	}

	for instanceID, instance := range m.data {
		if err := foreachAddress(instanceID, instance, fn); err != nil {
			return err
		}
	}

	return nil
}

// InterfaceIterator is the function called by the ForeachInterface iterator
type InterfaceIterator func(instanceID, interfaceID string, iface InterfaceRevision) error

func foreachInterface(instanceID string, instance *Instance, fn InterfaceIterator) error {
	for _, rev := range instance.Interfaces {
		if err := fn(instanceID, rev.Resource.InterfaceID(), rev); err != nil {
			return err
		}
	}

	return nil
}

// ForeachInterface calls fn for each interface on each interface attached to
// each instance. If an instanceID is specified, the only the interfaces and
// addresses of the specified instance are considered.
//
// The InstanceMap is read-locked throughout the iteration process, i.e., no
// updates will occur. However, the address object given to the InterfaceIterator
// will point to live data and must be deep copied if used outside of the
// context of the iterator function.
func (m *InstanceMap) ForeachInterface(instanceID string, fn InterfaceIterator) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if instanceID != "" {
		if instance := m.data[instanceID]; instance != nil {
			return foreachInterface(instanceID, instance, fn)
		}
		return fmt.Errorf("instance does not exist: %q", instanceID)
	}
	for instanceID, instance := range m.data {
		if err := foreachInterface(instanceID, instance, fn); err != nil {
			return err
		}
	}

	return nil
}

// GetInterface returns returns a particular interface of an instance. The
// boolean indicates whether the interface was found or not.
func (m *InstanceMap) GetInterface(instanceID, interfaceID string) (InterfaceRevision, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if instance := m.data[instanceID]; instance != nil {
		if rev, ok := instance.Interfaces[interfaceID]; ok {
			return rev, true
		}
	}

	return InterfaceRevision{}, false
}

// DeepCopy returns a deep copy
func (m *InstanceMap) DeepCopy() *InstanceMap {
	c := NewInstanceMap()
	m.ForeachInterface("", func(instanceID, interfaceID string, rev InterfaceRevision) error {
		// c is not exposed yet, we can access it without locking it
		rev.Resource = rev.Resource.DeepCopyInterface()
		c.updateLocked(instanceID, rev)
		return nil
	})
	return c
}

// NumInstances returns the number of instances in the instance map
func (m *InstanceMap) NumInstances() (size int) {
	m.mutex.RLock()
	size = len(m.data)
	m.mutex.RUnlock()
	return
}

// Exists returns whether the instance ID is in the instanceMap
func (m *InstanceMap) Exists(instanceID string) (exists bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if instance := m.data[instanceID]; instance != nil {
		return true
	}
	return false
}

// Delete instance from m.data
func (m *InstanceMap) Delete(instanceID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.data, instanceID)
}
