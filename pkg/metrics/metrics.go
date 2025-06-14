// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package metrics holds prometheus metrics objects and related utility functions. It
// does not abstract away the prometheus client but the caller rarely needs to
// refer to prometheus directly.
package metrics

// Adding a metric
// - Add a metric object of the appropriate type as an exported variable
// - Register the new object in the init function

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

const (
	// ErrorTimeout is the value used to notify timeout errors.
	ErrorTimeout = "timeout"

	// ErrorProxy is the value used to notify errors on Proxy.
	ErrorProxy = "proxy"

	// L7DNS is the value used to report DNS label on metrics
	L7DNS = "dns"

	// SubsystemBPF is the subsystem to scope metrics related to the bpf syscalls.
	SubsystemBPF = "bpf"

	// SubsystemDatapath is the subsystem to scope metrics related to management of
	// the datapath. It is prepended to metric names and separated with a '_'.
	SubsystemDatapath = "datapath"

	// SubsystemAgent is the subsystem to scope metrics related to the cilium agent itself.
	SubsystemAgent = "agent"

	// SubsystemFQDN is the subsystem to scope metrics related to the FQDN proxy.
	SubsystemIPCache = "ipcache"

	// SubsystemK8s is the subsystem to scope metrics related to Kubernetes
	SubsystemK8s = "k8s"

	// SubsystemK8sClient is the subsystem to scope metrics related to the kubernetes client.
	SubsystemK8sClient = "k8s_client"

	// SubsystemWorkQueue is the subsystem to scope metrics related to the workqueue.
	SubsystemWorkQueue = "k8s_workqueue"

	// SubsystemKVStore is the subsystem to scope metrics related to the kvstore.
	SubsystemKVStore = "kvstore"

	// SubsystemFQDN is the subsystem to scope metrics related to the FQDN proxy.
	SubsystemFQDN = "fqdn"

	// SubsystemNodes is the subsystem to scope metrics related to the node manager.
	SubsystemNodes = "nodes"

	// SubsystemTriggers is the subsystem to scope metrics related to the trigger package.
	SubsystemTriggers = "triggers"

	// SubsystemAPILimiter is the subsystem to scope metrics related to the API limiter package.
	SubsystemAPILimiter = "api_limiter"

	// CiliumAgentNamespace is used to scope metrics from the Cilium Agent
	CiliumAgentNamespace = "cilium"

	// CiliumClusterMeshAPIServerNamespace is used to scope metrics from the
	// Cilium Cluster Mesh API Server
	CiliumClusterMeshAPIServerNamespace = "cilium_clustermesh_apiserver"

	// CiliumClusterMeshAPIServerNamespace is used to scope metrics from
	// Cilium KVStoreMesh
	CiliumKVStoreMeshNamespace = "cilium_kvstoremesh"

	// CiliumOperatorNamespace is used to scope metrics from the Cilium Operator
	CiliumOperatorNamespace = "cilium_operator"

	// LabelError indicates the type of error (string)
	LabelError = "error"

	// LabelOutcome indicates whether the outcome of the operation was successful or not
	LabelOutcome = "outcome"

	// LabelAttempts is the number of attempts it took to complete the operation
	LabelAttempts = "attempts"

	// Labels

	// LabelValueFalse is the string value for true metric label values.
	LabelValueTrue = "true"

	// LabelValueFalse is the string value for false metric label values.
	LabelValueFalse = "false"

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"

	// LabelValueOutcomeFailure is used as an unsuccessful outcome of an operation.
	// NOTE: This should only be used for existing metrics, new metrics should use LabelValueOutcomeFail.
	LabelValueOutcomeFailure = "failure"

	// LabelDropReason is used to describe reason for dropping a packets/bytes
	LabelDropReason = "reason"

	// LabelEventSourceAPI marks event-related metrics that come from the API
	LabelEventSourceAPI = "api"

	// LabelEventSourceK8s marks event-related metrics that come from k8s
	LabelEventSourceK8s = "k8s"

	// LabelEventSourceFQDN marks event-related metrics that come from pkg/fqdn
	LabelEventSourceFQDN = "fqdn"

	// LabelEventSourceContainerd marks event-related metrics that come from docker
	LabelEventSourceContainerd = "docker"

	// LabelDatapathArea marks which area the metrics are related to (eg, which BPF map)
	LabelDatapathArea = "area"

	// LabelDatapathName marks a unique identifier for this metric.
	// The name should be defined once for a given type of error.
	LabelDatapathName = "name"

	// LabelDatapathFamily marks which protocol family (IPv4, IPV6) the metric is related to.
	LabelDatapathFamily = "family"

	// LabelProtocol marks the L4 protocol (TCP, ANY) for the metric.
	LabelProtocol = "protocol"

	// LabelSignalType marks the signal name
	LabelSignalType = "signal"

	// LabelSignalData marks the signal data
	LabelSignalData = "data"

	// LabelStatus the label from completed task
	LabelStatus = "status"

	// LabelPolicyEnforcement is the label used to see the enforcement status
	LabelPolicyEnforcement = "enforcement"

	// LabelPolicySource is the label used to see the enforcement status
	LabelPolicySource = "source"

	LabelSource = "source"

	// LabelScope is the label used to defined multiples scopes in the same
	// metric. For example, one counter may measure a metric over the scope of
	// the entire event (scope=global), or just part of an event
	// (scope=slow_path)
	LabelScope = "scope"

	// LabelProtocolL7 is the label used when working with layer 7 protocols.
	LabelProtocolL7 = "protocol_l7"

	// LabelBuildState is the state a build queue entry is in
	LabelBuildState = "state"

	// LabelBuildQueueName is the name of the build queue
	LabelBuildQueueName = "name"

	// LabelAction is the label used to defined what kind of action was performed in a metric
	LabelAction = "action"

	// LabelSubsystem is the label used to refer to any of the child process
	// started by cilium (Envoy, monitor, etc..)
	LabelSubsystem = "subsystem"

	// LabelKind is the kind of a label
	LabelKind = "kind"

	// LabelEventSource is the source of a label for event metrics
	// i.e. k8s, containerd, api.
	LabelEventSource = "source"

	// LabelPath is the label for the API path
	LabelPath = "path"
	// LabelMethod is the label for the HTTP method
	LabelMethod = "method"

	// LabelAPIReturnCode is the HTTP code returned for that API path
	LabelAPIReturnCode = "return_code"

	// LabelOperation is the label for BPF maps operations
	LabelOperation = "operation"

	// LabelMapName is the label for the BPF map name
	LabelMapName = "map_name"

	LabelMapGroup = "map_group"

	// LabelVersion is the label for the version number
	LabelVersion = "version"

	// LabelVersionRevision is the label for the version revision
	LabelVersionRevision = "revision"

	// LabelArch is the label for the platform architecture (e.g. linux/amd64)
	LabelArch = "arch"

	// LabelDirection is the label for traffic direction
	LabelDirection = "direction"

	// LabelSourceCluster is the label for source cluster name
	LabelSourceCluster = "source_cluster"

	// LabelSourceNodeName is the label for source node name
	LabelSourceNodeName = "source_node_name"

	// LabelTargetCluster is the label for target cluster name
	LabelTargetCluster = "target_cluster"

	// Rule label is a label for a L7 rule name.
	LabelL7Rule = "rule"

	// LabelL7ProxyType is the label for denoting a L7 proxy type.
	LabelL7ProxyType = "proxy_type"

	// LabelType is the label for type in general (e.g. endpoint, node)
	LabelType         = "type"
	LabelPeerEndpoint = "endpoint"
	LabelPeerNode     = "node"

	LabelTrafficHTTP = "http"
	LabelTrafficICMP = "icmp"

	LabelAddressType          = "address_type"
	LabelAddressTypePrimary   = "primary"
	LabelAddressTypeSecondary = "secondary"

	// LabelConnectivityStatus is the label for connectivity statuses
	LabelConnectivityStatus = "status"
	LabelReachable          = "reachable"
	LabelUnreachable        = "unreachable"
	LabelUnknown            = "unknown"
)

var (
	// LabelValuesBool is metric label value set for boolean type.
	LabelValuesBool = metric.NewValues(LabelValueTrue, LabelValueFalse)

	// Namespace is used to scope metrics from cilium. It is prepended to metric
	// names and separated with a '_'
	Namespace = CiliumAgentNamespace

	registryResolver, registry = promise.New[*Registry]()

	BPFMapPressure = true

	// BootstrapTimes is the durations of cilium-agent bootstrap sequence.
	BootstrapTimes = NoOpGaugeVec

	// APIInteractions is the total time taken to process an API call made
	// to the cilium-agent
	APIInteractions = NoOpObserverVec

	// Status

	// NodeHealthConnectivityStatus is the number of connections with connectivity status
	// between local node to other node intra or inter cluster.
	NodeHealthConnectivityStatus = NoOpGaugeVec

	// NodeHealthConnectivityLatency is the histogram connectivity latency between local node to
	// other node intra or inter cluster.
	NodeHealthConnectivityLatency = NoOpObserverVec

	// Endpoint

	// Endpoint is a function used to collect this metric.
	// It must be thread-safe.
	Endpoint metric.GaugeFunc

	// EndpointMaxIfindex is the maximum observed interface index for existing endpoints
	EndpointMaxIfindex = NoOpGauge

	// EndpointRegenerationTotal is a count of the number of times any endpoint
	// has been regenerated and success/fail outcome
	EndpointRegenerationTotal = NoOpCounterVec

	// EndpointStateCount is the total count of the endpoints in various states.
	EndpointStateCount = NoOpGaugeVec

	// EndpointRegenerationTimeStats is the total time taken to regenerate
	// endpoints, labeled by span name and status ("success" or "failure")
	EndpointRegenerationTimeStats = NoOpObserverVec

	// EndpointPropagationDelay is the delay between creation of local CiliumEndpoint
	// and update for that CiliumEndpoint received through CiliumEndpointSlice.
	// Measure of local CEP roundtrip time with CiliumEndpointSlice feature enabled.
	EndpointPropagationDelay = NoOpObserverVec

	// Policy
	// Policy is the number of policies loaded into the agent
	Policy = NoOpGauge

	// PolicyRevision is the current policy revision number for this agent
	PolicyRevision = NoOpGauge

	// PolicyChangeTotal is a count of policy changes by outcome ("success" or
	// "failure")
	PolicyChangeTotal = NoOpCounterVec

	// PolicyEndpointStatus is the number of endpoints with policy labeled by enforcement type
	PolicyEndpointStatus = NoOpGaugeVec

	// PolicyImplementationDelay is a distribution of times taken from adding a
	// policy (and incrementing the policy revision) to seeing it in the datapath
	// per Endpoint. This reflects the actual delay perceived by traffic flowing
	// through the datapath. The longest times will roughly correlate with the
	// time taken to fully deploy an endpoint.
	PolicyImplementationDelay = NoOpObserverVec

	// PolicyIncrementalUpdateDuration is the time it takes to apply an incremental update
	// to the policy engine. An incremental update is a newly-learned identity that can be
	// directly added to policy maps without a full policy recalculation.
	PolicyIncrementalUpdateDuration = NoOpObserverVec

	// Identity

	// Identity is the number of identities currently in use on the node by type
	Identity = NoOpGaugeVec

	// IdentityLabelSources is the number of identities in use on the node with
	// have a particular label source. Note that an identity may contain labels
	// from multiple sources and thus might be counted in multiple buckets
	IdentityLabelSources = NoOpGaugeVec

	// Events

	// EventTS is the time in seconds since epoch that we last received an
	// event that was handled by Cilium. This metric tracks the source of the
	// event which can be one of K8s or Cilium's API.
	EventTS = NoOpGaugeVec

	// EventLagK8s is the lag calculation for k8s Pod events.
	EventLagK8s = NoOpGauge

	// L7 statistics

	// ProxyRedirects is the number of redirects labeled by protocol
	ProxyRedirects = NoOpGaugeVec

	// ProxyPolicyL7Total is a count of all l7 requests handled by proxy
	ProxyPolicyL7Total = NoOpCounterVec

	// ProxyUpstreamTime is how long the upstream server took to reply labeled
	// by error, protocol and span time
	ProxyUpstreamTime = NoOpObserverVec

	// ProxyDatapathUpdateTimeout is a count of all the timeouts encountered while
	// updating the datapath due to an FQDN IP update
	ProxyDatapathUpdateTimeout = NoOpCounter

	// L3-L4 statistics

	// Datapath statistics

	// ConntrackGCRuns is the number of times that the conntrack GC
	// process was run.
	ConntrackGCRuns = NoOpCounterVec

	// ConntrackGCKeyFallbacks number of times that the conntrack key fallback was invalid.
	ConntrackGCKeyFallbacks = NoOpCounterVec

	// ConntrackGCSize the number of entries in the conntrack table
	ConntrackGCSize = NoOpGaugeVec

	// NatGCSize the number of entries in the nat table
	NatGCSize = NoOpGaugeVec

	// ConntrackGCDuration the duration of the conntrack GC process in milliseconds.
	ConntrackGCDuration = NoOpObserverVec

	// ConntrackInterval is the interval in secodns between conntrack GC runs
	ConntrackInterval = NoOpGaugeVec

	// ConntrackDumpReset marks the count for conntrack dump resets
	ConntrackDumpResets = NoOpCounterVec

	// Signals

	// SignalsHandled is the number of signals received.
	SignalsHandled = NoOpCounterVec

	// Services

	// ServicesEventsCount counts the number of services
	ServicesEventsCount = NoOpCounterVec

	// ServiceImplementationDelay the execution duration of the service handler in milliseconds.
	// The metric reflects the time it took to program the service excluding the event queue latency.
	ServiceImplementationDelay = NoOpObserverVec

	// Errors and warnings

	// ErrorsWarnings is the number of errors and warnings in cilium-agent instances
	ErrorsWarnings = NoOpCounterVec

	// ControllerRuns is the number of times that a controller process runs.
	ControllerRuns = NoOpCounterVec

	// ControllerRunsDuration the duration of the controller process in seconds
	ControllerRunsDuration = NoOpObserverVec

	// subprocess, labeled by Subsystem
	SubprocessStart = NoOpCounterVec

	// Kubernetes Events

	// KubernetesEventProcessed is the number of Kubernetes events
	// processed labeled by scope, action and execution result
	KubernetesEventProcessed = NoOpCounterVec

	// KubernetesEventReceived is the number of Kubernetes events received
	// labeled by scope, action, valid data and equalness.
	KubernetesEventReceived = NoOpCounterVec

	// Kubernetes interactions

	// KubernetesAPIInteractions is the total time taken to process an API call made
	// to the kube-apiserver
	KubernetesAPIInteractions = NoOpObserverVec

	// KubernetesAPIRateLimiterLatency is the client side rate limiter latency metric
	KubernetesAPIRateLimiterLatency = NoOpObserverVec

	// KubernetesAPICallsTotal is the counter for all API calls made to
	// kube-apiserver.
	KubernetesAPICallsTotal = NoOpCounterVec

	// TerminatingEndpointsEvents is the number of terminating endpoint events received from kubernetes.
	TerminatingEndpointsEvents = NoOpCounter

	// IPAM events

	// IPAMEvent is the number of IPAM events received labeled by action and
	// datapath family type
	IPAMEvent = NoOpCounterVec

	// IPAMCapacity tracks the total number of IPs that could be allocated. To
	// get the current number of available IPs, it would be this metric
	// subtracted by IPAMEvent{allocated}.
	IPAMCapacity = NoOpGaugeVec

	// KVstore events

	// KVStoreOperationsDuration records the duration of kvstore operations
	KVStoreOperationsDuration = NoOpObserverVec

	// KVStoreEventsQueueDuration records the duration in seconds of time
	// received event was blocked before it could be queued
	KVStoreEventsQueueDuration = NoOpObserverVec

	// KVStoreQuorumErrors records the number of kvstore quorum errors
	KVStoreQuorumErrors = NoOpCounterVec

	// FQDNGarbageCollectorCleanedTotal is the number of domains cleaned by the
	// GC job.
	FQDNGarbageCollectorCleanedTotal = NoOpCounter

	// FQDNActiveNames is the number of domains inside the DNS cache that have
	// not expired (by TTL), per endpoint.
	FQDNActiveNames = NoOpGaugeVec

	// FQDNActiveIPs is the number of IPs inside the DNS cache associated with
	// a domain that has not expired (by TTL) and are currently active, per
	// endpoint.
	FQDNActiveIPs = NoOpGaugeVec

	// FQDNAliveZombieConnections is the number IPs associated with domains
	// that have expired (by TTL) yet still associated with an active
	// connection (aka zombie), per endpoint.
	FQDNAliveZombieConnections = NoOpGaugeVec

	// FQDNSelectors is the total number of registered ToFQDN selectors
	FQDNSelectors = NoOpGauge

	// FQDNSemaphoreRejectedTotal is the total number of DNS requests rejected
	// by the DNS proxy because too many requests were in flight, as enforced by
	// the admission semaphore.
	FQDNSemaphoreRejectedTotal = NoOpCounter

	// IPCacheErrorsTotal is the total number of IPCache events handled in
	// the IPCache subsystem that resulted in errors.
	IPCacheErrorsTotal = NoOpCounterVec

	// IPCacheEventsTotal is the total number of IPCache events handled in
	// the IPCache subsystem.
	IPCacheEventsTotal = NoOpCounterVec

	// BPFSyscallDuration is the metric for bpf syscalls duration.
	BPFSyscallDuration = NoOpObserverVec

	// BPFMapOps is the metric to measure the number of operations done to a
	// bpf map.
	BPFMapOps = NoOpCounterVec

	// BPFMapCapacity is the max capacity of bpf maps, labelled by map group classification.
	BPFMapCapacity = NoOpGaugeVec

	// VersionMetric labelled by Cilium version
	VersionMetric = NoOpGaugeVec

	// APILimiterWaitHistoryDuration is a histogram that measures the
	// individual wait durations of API limiters
	APILimiterWaitHistoryDuration = NoOpObserverVec

	// APILimiterWaitDuration is the gauge of the current mean, min, and
	// max wait duration
	APILimiterWaitDuration = NoOpGaugeVec

	// APILimiterProcessingDuration is the gauge of the mean and estimated
	// processing duration
	APILimiterProcessingDuration = NoOpGaugeVec

	// APILimiterRequestsInFlight is the gauge of the current and max
	// requests in flight
	APILimiterRequestsInFlight = NoOpGaugeVec

	// APILimiterRateLimit is the gauge of the current rate limiting
	// configuration including limit and burst
	APILimiterRateLimit = NoOpGaugeVec

	// APILimiterAdjustmentFactor is the gauge representing the latest
	// adjustment factor that was applied
	APILimiterAdjustmentFactor = NoOpGaugeVec

	// APILimiterProcessedRequests is the counter of the number of
	// processed (successful and failed) requests
	APILimiterProcessedRequests = NoOpCounterVec

	// WorkQueueDepth is the depth of the workqueue
	//
	// We set actual metrics here instead of NoOp for the workqueue metrics
	// because these metrics will be registered with workqueue.SetProvider
	// by init function in watcher.go. Otherwise, we will register NoOps.
	//
	WorkQueueDepth = metric.NewGaugeVec(metric.GaugeOpts{
		ConfigName: Namespace + "_" + SubsystemWorkQueue + "_depth",
		Namespace:  Namespace,
		Subsystem:  SubsystemWorkQueue,
		Name:       "depth",
		Help:       "Current depth of workqueue.",
	}, []string{"name"})

	// WorkQueueAddsTotal is the total number of adds to the workqueue
	WorkQueueAddsTotal = metric.NewCounterVec(metric.CounterOpts{
		ConfigName: Namespace + "_" + SubsystemWorkQueue + "_adds_total",
		Namespace:  Namespace,
		Subsystem:  SubsystemWorkQueue,
		Name:       "adds_total",
		Help:       "Total number of adds handled by workqueue.",
	}, []string{"name"})

	// WorkQueueLatency is the latency of how long an item stays in the workqueue
	WorkQueueLatency = metric.NewHistogramVec(metric.HistogramOpts{
		ConfigName: Namespace + "_" + SubsystemWorkQueue + "_queue_duration_seconds",
		Namespace:  Namespace,
		Subsystem:  SubsystemWorkQueue,
		Name:       "queue_duration_seconds",
		Help:       "How long in seconds an item stays in workqueue before being requested.",
		Buckets:    prometheus.ExponentialBuckets(10e-9, 10, 10),
	}, []string{"name"})

	// WorkQueueDuration is the duration of how long processing an item for the workqueue
	WorkQueueDuration = metric.NewHistogramVec(metric.HistogramOpts{
		ConfigName: Namespace + "_" + SubsystemWorkQueue + "_work_duration_seconds",
		Namespace:  Namespace,
		Subsystem:  SubsystemWorkQueue,
		Name:       "work_duration_seconds",
		Help:       "How long in seconds processing an item from workqueue takes.",
		Buckets:    prometheus.ExponentialBuckets(10e-9, 10, 10),
	}, []string{"name"})

	// WorkQueueUnfinishedWork is how many seconds of work has been done that is in progress
	WorkQueueUnfinishedWork = metric.NewGaugeVec(metric.GaugeOpts{
		ConfigName: Namespace + "_" + SubsystemWorkQueue + "_unfinished_work_seconds",
		Namespace:  Namespace,
		Subsystem:  SubsystemWorkQueue,
		Name:       "unfinished_work_seconds",
		Help: "How many seconds of work has been done that " +
			"is in progress and hasn't been observed by work_duration. Large " +
			"values indicate stuck threads. One can deduce the number of stuck " +
			"threads by observing the rate at which this increases.",
	}, []string{"name"})

	// WorkQueueLongestRunningProcessor is the longest running processor in the workqueue
	WorkQueueLongestRunningProcessor = metric.NewGaugeVec(metric.GaugeOpts{
		ConfigName: Namespace + "_" + SubsystemWorkQueue + "_longest_running_processor_seconds",
		Namespace:  Namespace,
		Subsystem:  SubsystemWorkQueue,
		Name:       "longest_running_processor_seconds",
		Help: "How many seconds has the longest running " +
			"processor for workqueue been running.",
	}, []string{"name"})

	// WorkQueueRetries is the number of retries for handled by the workqueue
	WorkQueueRetries = metric.NewCounterVec(metric.CounterOpts{
		ConfigName: Namespace + "_" + SubsystemWorkQueue + "_retries_total",
		Namespace:  Namespace,
		Subsystem:  SubsystemWorkQueue,
		Name:       "retries_total",
		Help:       "Total number of retries handled by workqueue.",
	}, []string{"name"})
)

type LegacyMetrics struct {
	BootstrapTimes                   metric.Vec[metric.Gauge]
	APIInteractions                  metric.Vec[metric.Observer]
	NodeHealthConnectivityStatus     metric.Vec[metric.Gauge]
	NodeHealthConnectivityLatency    metric.Vec[metric.Observer]
	Endpoint                         metric.GaugeFunc
	EndpointMaxIfindex               metric.Gauge
	EndpointRegenerationTotal        metric.Vec[metric.Counter]
	EndpointStateCount               metric.Vec[metric.Gauge]
	EndpointRegenerationTimeStats    metric.Vec[metric.Observer]
	EndpointPropagationDelay         metric.Vec[metric.Observer]
	Policy                           metric.Gauge
	PolicyRevision                   metric.Gauge
	PolicyChangeTotal                metric.Vec[metric.Counter]
	PolicyEndpointStatus             metric.Vec[metric.Gauge]
	PolicyImplementationDelay        metric.Vec[metric.Observer]
	PolicyIncrementalUpdateDuration  metric.Vec[metric.Observer]
	Identity                         metric.Vec[metric.Gauge]
	IdentityLabelSources             metric.Vec[metric.Gauge]
	EventTS                          metric.Vec[metric.Gauge]
	EventLagK8s                      metric.Gauge
	ProxyRedirects                   metric.Vec[metric.Gauge]
	ProxyPolicyL7Total               metric.Vec[metric.Counter]
	ProxyUpstreamTime                metric.Vec[metric.Observer]
	ProxyDatapathUpdateTimeout       metric.Counter
	ConntrackGCRuns                  metric.Vec[metric.Counter]
	ConntrackGCKeyFallbacks          metric.Vec[metric.Counter]
	ConntrackGCSize                  metric.Vec[metric.Gauge]
	NatGCSize                        metric.Vec[metric.Gauge]
	ConntrackGCDuration              metric.Vec[metric.Observer]
	ConntrackInterval                metric.Vec[metric.Gauge]
	ConntrackDumpResets              metric.Vec[metric.Counter]
	SignalsHandled                   metric.Vec[metric.Counter]
	ServicesEventsCount              metric.Vec[metric.Counter]
	ServiceImplementationDelay       metric.Vec[metric.Observer]
	ErrorsWarnings                   metric.Vec[metric.Counter]
	ControllerRuns                   metric.Vec[metric.Counter]
	ControllerRunsDuration           metric.Vec[metric.Observer]
	SubprocessStart                  metric.Vec[metric.Counter]
	KubernetesEventProcessed         metric.Vec[metric.Counter]
	KubernetesEventReceived          metric.Vec[metric.Counter]
	KubernetesAPIInteractions        metric.Vec[metric.Observer]
	KubernetesAPIRateLimiterLatency  metric.Vec[metric.Observer]
	KubernetesAPICallsTotal          metric.Vec[metric.Counter]
	TerminatingEndpointsEvents       metric.Counter
	IPAMEvent                        metric.Vec[metric.Counter]
	IPAMCapacity                     metric.Vec[metric.Gauge]
	KVStoreOperationsDuration        metric.Vec[metric.Observer]
	KVStoreEventsQueueDuration       metric.Vec[metric.Observer]
	KVStoreQuorumErrors              metric.Vec[metric.Counter]
	FQDNGarbageCollectorCleanedTotal metric.Counter
	FQDNActiveNames                  metric.Vec[metric.Gauge]
	FQDNActiveIPs                    metric.Vec[metric.Gauge]
	FQDNAliveZombieConnections       metric.Vec[metric.Gauge]
	FQDNSelectors                    metric.Gauge
	FQDNSemaphoreRejectedTotal       metric.Counter
	IPCacheErrorsTotal               metric.Vec[metric.Counter]
	IPCacheEventsTotal               metric.Vec[metric.Counter]
	BPFSyscallDuration               metric.Vec[metric.Observer]
	BPFMapOps                        metric.Vec[metric.Counter]
	BPFMapCapacity                   metric.Vec[metric.Gauge]
	VersionMetric                    metric.Vec[metric.Gauge]
	APILimiterWaitHistoryDuration    metric.Vec[metric.Observer]
	APILimiterWaitDuration           metric.Vec[metric.Gauge]
	APILimiterProcessingDuration     metric.Vec[metric.Gauge]
	APILimiterRequestsInFlight       metric.Vec[metric.Gauge]
	APILimiterRateLimit              metric.Vec[metric.Gauge]
	APILimiterAdjustmentFactor       metric.Vec[metric.Gauge]
	APILimiterProcessedRequests      metric.Vec[metric.Counter]
	WorkQueueDepth                   metric.Vec[metric.Gauge]
	WorkQueueAddsTotal               metric.Vec[metric.Counter]
	WorkQueueLatency                 metric.Vec[metric.Observer]
	WorkQueueDuration                metric.Vec[metric.Observer]
	WorkQueueUnfinishedWork          metric.Vec[metric.Gauge]
	WorkQueueLongestRunningProcessor metric.Vec[metric.Gauge]
	WorkQueueRetries                 metric.Vec[metric.Counter]
}

func NewLegacyMetrics() *LegacyMetrics {
	lm := &LegacyMetrics{
		BootstrapTimes: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemAgent + "_bootstrap_seconds",
			Namespace:  Namespace,
			Subsystem:  SubsystemAgent,
			Name:       "bootstrap_seconds",
			Help:       "Duration of bootstrap sequence",
		}, []string{LabelScope, LabelOutcome}),

		APIInteractions: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_" + SubsystemAgent + "_api_process_time_seconds",

			Namespace: Namespace,
			Subsystem: SubsystemAgent,
			Name:      "api_process_time_seconds",
			Help:      "Duration of processed API calls labeled by path, method and return code.",
		}, []string{LabelPath, LabelMethod, LabelAPIReturnCode}),

		EndpointRegenerationTotal: metric.NewCounterVecWithLabels(metric.CounterOpts{
			ConfigName: Namespace + "_endpoint_regenerations_total",

			Namespace: Namespace,
			Name:      "endpoint_regenerations_total",
			Help:      "Count of all endpoint regenerations that have completed, tagged by outcome",
		}, metric.Labels{
			{
				Name:   LabelOutcome,
				Values: metric.NewValues(LabelValueOutcomeSuccess, LabelValueOutcomeFail),
			},
		}),

		EndpointStateCount: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_endpoint_state",
			Namespace:  Namespace,
			Name:       "endpoint_state",
			Help:       "Count of all endpoints, tagged by different endpoint states",
		},
			[]string{"endpoint_state"},
		),

		EndpointRegenerationTimeStats: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_endpoint_regeneration_time_stats_seconds",

			Namespace: Namespace,
			Name:      "endpoint_regeneration_time_stats_seconds",
			Help:      "Endpoint regeneration time stats labeled by the scope",
		}, []string{LabelScope, LabelStatus}),

		Policy: metric.NewGauge(metric.GaugeOpts{
			ConfigName: Namespace + "_policy",
			Namespace:  Namespace,
			Name:       "policy",
			Help:       "Number of policies currently loaded",
		}),

		PolicyRevision: metric.NewGauge(metric.GaugeOpts{
			ConfigName: Namespace + "_policy_max_revision",
			Namespace:  Namespace,
			Name:       "policy_max_revision",
			Help:       "Highest policy revision number in the agent",
		}),

		PolicyChangeTotal: metric.NewCounterVecWithLabels(metric.CounterOpts{
			ConfigName: Namespace + "_policy_change_total",

			Namespace: Namespace,
			Name:      "policy_change_total",
			Help:      "Number of policy changes by outcome",
		}, metric.Labels{
			{
				Name:   LabelOutcome,
				Values: metric.NewValues(LabelValueOutcomeSuccess, LabelValueOutcomeFailure),
			},
		}),

		PolicyEndpointStatus: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_policy_endpoint_enforcement_status",

			Namespace: Namespace,
			Name:      "policy_endpoint_enforcement_status",
			Help:      "Number of endpoints labeled by policy enforcement status",
		}, []string{LabelPolicyEnforcement}),

		PolicyImplementationDelay: metric.NewHistogramVecWithLabels(metric.HistogramOpts{
			ConfigName: Namespace + "_policy_implementation_delay",

			Namespace: Namespace,
			Name:      "policy_implementation_delay",
			Help:      "Time between a policy change and it being fully deployed into the datapath",
		}, metric.Labels{
			{
				Name:   LabelPolicySource,
				Values: metric.NewValues(string(source.Kubernetes), string(source.CustomResource), string(source.LocalAPI)),
			},
		}),

		PolicyIncrementalUpdateDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_policy_incremental_update_duration",

			Namespace: Namespace,
			Name:      "policy_incremental_update_duration",
			Help:      "Time between learning about a new identity and it being fully added to all policies.",
			Buckets:   prometheus.ExponentialBuckets(10e-6, 10, 8),
		}, []string{"scope"}),

		Identity: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_identity",

			Namespace: Namespace,
			Name:      "identity",
			Help:      "Number of identities currently allocated",
		}, []string{LabelType}),

		IdentityLabelSources: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_identity_label_sources",

			Namespace: Namespace,
			Name:      "identity_label_sources",
			Help:      "Number of identities which contain at least one label of the given label source",
		}, []string{LabelSource}),

		EventTS: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_event_ts",
			Namespace:  Namespace,
			Name:       "event_ts",
			Help:       "Last timestamp when Cilium received an event from a control plane source, per resource and per action",
		}, []string{LabelEventSource, LabelScope, LabelAction}),

		EventLagK8s: metric.NewGauge(metric.GaugeOpts{
			ConfigName:  Namespace + "_k8s_event_lag_seconds",
			Disabled:    true,
			Namespace:   Namespace,
			Name:        "k8s_event_lag_seconds",
			Help:        "Lag for Kubernetes events - computed value between receiving a CNI ADD event from kubelet and a Pod event received from kube-api-server",
			ConstLabels: prometheus.Labels{"source": LabelEventSourceK8s},
		}),

		ProxyRedirects: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_proxy_redirects",

			Namespace: Namespace,
			Name:      "proxy_redirects",
			Help:      "Number of redirects installed for endpoints, labeled by protocol",
		}, []string{LabelProtocolL7}),

		ProxyPolicyL7Total: metric.NewCounterVecWithLabels(metric.CounterOpts{
			ConfigName: Namespace + "_policy_l7_total",
			Namespace:  Namespace,
			Name:       "policy_l7_total",
			Help:       "Number of total proxy requests handled",
		}, metric.Labels{
			{
				Name:   LabelL7Rule,
				Values: metric.NewValues("received", "forwarded", "denied", "parse_errors"),
			},
			{
				Name:   LabelL7ProxyType,
				Values: metric.NewValues("fqdn", "envoy"),
			},
		}),

		ProxyUpstreamTime: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_proxy_upstream_reply_seconds",
			Namespace:  Namespace,
			Name:       "proxy_upstream_reply_seconds",
			Help:       "Seconds waited to get a reply from a upstream server",
		}, []string{"error", LabelProtocolL7, LabelScope}),

		ProxyDatapathUpdateTimeout: metric.NewCounter(metric.CounterOpts{
			ConfigName: Namespace + "_proxy_datapath_update_timeout_total",
			Disabled:   true,

			Namespace: Namespace,
			Name:      "proxy_datapath_update_timeout_total",
			Help:      "Number of total datapath update timeouts due to FQDN IP updates",
		}),

		ConntrackGCRuns: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemDatapath + "_conntrack_gc_runs_total",
			Namespace:  Namespace,
			Subsystem:  SubsystemDatapath,
			Name:       "conntrack_gc_runs_total",
			Help: "Number of times that the conntrack garbage collector process was run " +
				"labeled by completion status",
		}, []string{LabelDatapathFamily, LabelProtocol, LabelStatus}),

		ConntrackGCKeyFallbacks: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemDatapath + "_conntrack_gc_key_fallbacks_total",
			Namespace:  Namespace,
			Subsystem:  SubsystemDatapath,
			Name:       "conntrack_gc_key_fallbacks_total",
			Help:       "Number of times a key fallback was needed when iterating over the BPF map",
		}, []string{LabelDatapathFamily, LabelProtocol}),

		ConntrackGCSize: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemDatapath + "_conntrack_gc_entries",
			Namespace:  Namespace,
			Subsystem:  SubsystemDatapath,
			Name:       "conntrack_gc_entries",
			Help: "The number of alive and deleted conntrack entries at the end " +
				"of a garbage collector run labeled by datapath family.",
		}, []string{LabelDatapathFamily, LabelProtocol, LabelStatus}),

		NatGCSize: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemDatapath + "_nat_gc_entries",
			Disabled:   true,
			Namespace:  Namespace,
			Subsystem:  SubsystemDatapath,
			Name:       "nat_gc_entries",
			Help: "The number of alive and deleted nat entries at the end " +
				"of a garbage collector run labeled by datapath family.",
		}, []string{LabelDatapathFamily, LabelDirection, LabelStatus}),

		ConntrackGCDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_" + SubsystemDatapath + "_conntrack_gc_duration_seconds",
			Namespace:  Namespace,
			Subsystem:  SubsystemDatapath,
			Name:       "conntrack_gc_duration_seconds",
			Help: "Duration in seconds of the garbage collector process " +
				"labeled by datapath family and completion status",
		}, []string{LabelDatapathFamily, LabelProtocol, LabelStatus}),

		ConntrackInterval: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemDatapath + "_conntrack_gc_interval_seconds",
			Namespace:  Namespace,
			Subsystem:  SubsystemDatapath,
			Name:       "conntrack_gc_interval_seconds",
			Help:       "Interval in seconds between conntrack garbage collector runs",
		}, []string{"global"}),

		ConntrackDumpResets: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemDatapath + "_conntrack_dump_resets_total",
			Namespace:  Namespace,
			Subsystem:  SubsystemDatapath,
			Name:       "conntrack_dump_resets_total",
			Help:       "Number of conntrack dump resets. Happens when a BPF entry gets removed while dumping the map is in progress",
		}, []string{LabelDatapathArea, LabelDatapathName, LabelDatapathFamily}),

		SignalsHandled: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemDatapath + "_signals_handled_total",

			Namespace: Namespace,
			Subsystem: SubsystemDatapath,
			Name:      "signals_handled_total",
			Help: "Number of times that the datapath signal handler process was run " +
				"labeled by signal type, data and completion status",
		}, []string{LabelSignalType, LabelSignalData, LabelStatus}),

		ServicesEventsCount: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_services_events_total",
			Namespace:  Namespace,
			Name:       "services_events_total",
			Help:       "Number of services events labeled by action type",
		}, []string{LabelAction}),

		ServiceImplementationDelay: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_service_implementation_delay",
			Namespace:  Namespace,
			Name:       "service_implementation_delay",
			Help: "Duration in seconds to propagate the data plane programming of a service, its network and endpoints " +
				"from the time the service or the service pod was changed excluding the event queue latency",
		}, []string{LabelAction}),

		ErrorsWarnings: newErrorsWarningsMetric(),

		ControllerRuns: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_controllers_runs_total",
			Namespace:  Namespace,
			Name:       "controllers_runs_total",
			Help:       "Number of times that a controller process was run labeled by completion status",
		}, []string{LabelStatus}),

		ControllerRunsDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_controllers_runs_duration_seconds",
			Namespace:  Namespace,
			Name:       "controllers_runs_duration_seconds",
			Help:       "Duration in seconds of the controller process labeled by completion status",
		}, []string{LabelStatus}),

		SubprocessStart: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_subprocess_start_total",
			Namespace:  Namespace,
			Name:       "subprocess_start_total",
			Help:       "Number of times that Cilium has started a subprocess, labeled by subsystem",
		}, []string{LabelSubsystem}),

		KubernetesEventProcessed: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_kubernetes_events_total",
			Namespace:  Namespace,
			Name:       "kubernetes_events_total",
			Help:       "Number of Kubernetes events processed labeled by scope, action and execution result",
		}, []string{LabelScope, LabelAction, LabelStatus}),

		KubernetesEventReceived: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_kubernetes_events_received_total",
			Namespace:  Namespace,
			Name:       "kubernetes_events_received_total",
			Help:       "Number of Kubernetes events received labeled by scope, action, valid data and equalness",
		}, []string{LabelScope, LabelAction, "valid", "equal"}),

		KubernetesAPIInteractions: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_" + SubsystemK8sClient + "_api_latency_time_seconds",
			Namespace:  Namespace,
			Subsystem:  SubsystemK8sClient,
			Name:       "api_latency_time_seconds",
			Help:       "Duration of processed API calls labeled by path and method.",
		}, []string{LabelPath, LabelMethod}),

		KubernetesAPIRateLimiterLatency: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_" + SubsystemK8sClient + "_rate_limiter_duration_seconds",
			Namespace:  Namespace,
			Subsystem:  SubsystemK8sClient,
			Name:       "rate_limiter_duration_seconds",
			Help:       "Kubernetes client rate limiter latency in seconds. Broken down by path and method.",
			Buckets:    []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0, 60.0},
		}, []string{LabelPath, LabelMethod}),

		KubernetesAPICallsTotal: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemK8sClient + "_api_calls_total",
			Namespace:  Namespace,
			Subsystem:  SubsystemK8sClient,
			Name:       "api_calls_total",
			Help:       "Number of API calls made to kube-apiserver labeled by host, method and return code.",
		}, []string{"host", LabelMethod, LabelAPIReturnCode}),

		TerminatingEndpointsEvents: metric.NewCounter(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemK8s + "_terminating_endpoints_events_total",
			Namespace:  Namespace,
			Subsystem:  SubsystemK8s,
			Name:       "terminating_endpoints_events_total",
			Help:       "Number of terminating endpoint events received from Kubernetes",
		}),

		IPAMEvent: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_ipam_events_total",
			Namespace:  Namespace,
			Name:       "ipam_events_total",
			Help:       "Number of IPAM events received labeled by action and datapath family type",
		}, []string{LabelAction, LabelDatapathFamily}),

		IPAMCapacity: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_ipam_capacity",
			Namespace:  Namespace,
			Name:       "ipam_capacity",
			Help:       "Total number of IPs in the IPAM pool labeled by family",
		}, []string{LabelDatapathFamily}),

		KVStoreOperationsDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_" + SubsystemKVStore + "_operations_duration_seconds",
			Namespace:  Namespace,
			Subsystem:  SubsystemKVStore,
			Name:       "operations_duration_seconds",
			Help:       "Duration in seconds of kvstore operations",
		}, []string{LabelScope, LabelKind, LabelAction, LabelOutcome}),

		KVStoreEventsQueueDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_" + SubsystemKVStore + "_events_queue_seconds",
			Namespace:  Namespace,
			Subsystem:  SubsystemKVStore,
			Name:       "events_queue_seconds",
			Help:       "Seconds waited before a received event was queued",
			Buckets:    []float64{.002, .005, .01, .015, .025, .05, .1, .25, .5, .75, 1},
		}, []string{LabelScope, LabelAction}),

		KVStoreQuorumErrors: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemKVStore + "_quorum_errors_total",
			Namespace:  Namespace,
			Subsystem:  SubsystemKVStore,
			Name:       "quorum_errors_total",
			Help:       "Number of quorum errors",
		}, []string{LabelError}),

		IPCacheErrorsTotal: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemIPCache + "_errors_total",
			Namespace:  Namespace,
			Subsystem:  SubsystemIPCache,
			Name:       "errors_total",
			Help:       "Number of errors interacting with the IP to Identity cache",
		}, []string{LabelType, LabelError}),

		IPCacheEventsTotal: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemIPCache + "_events_total",
			Disabled:   true,
			Namespace:  Namespace,
			Subsystem:  SubsystemIPCache,
			Name:       "events_total",
			Help:       "Number of events interacting with the IP to Identity cache",
		}, []string{LabelType}),

		FQDNGarbageCollectorCleanedTotal: metric.NewCounter(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemFQDN + "_gc_deletions_total",
			Namespace:  Namespace,
			Subsystem:  SubsystemFQDN,
			Name:       "gc_deletions_total",
			Help:       "Number of FQDNs that have been cleaned on FQDN Garbage collector job",
		}),

		FQDNActiveNames: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemFQDN + "_active_names",
			Disabled:   true,
			Namespace:  Namespace,
			Subsystem:  SubsystemFQDN,
			Name:       "active_names",
			Help:       "Number of domains inside the DNS cache that have not expired (by TTL), per endpoint",
		}, []string{LabelPeerEndpoint}),

		FQDNActiveIPs: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemFQDN + "_active_ips",
			Disabled:   true,
			Namespace:  Namespace,
			Subsystem:  SubsystemFQDN,
			Name:       "active_ips",
			Help:       "Number of IPs inside the DNS cache associated with a domain that has not expired (by TTL), per endpoint",
		}, []string{LabelPeerEndpoint}),

		FQDNAliveZombieConnections: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemFQDN + "_alive_zombie_connections",
			Disabled:   true,
			Namespace:  Namespace,
			Subsystem:  SubsystemFQDN,
			Name:       "alive_zombie_connections",
			Help:       "Number of IPs associated with domains that have expired (by TTL) yet still associated with an active connection (aka zombie), per endpoint",
		}, []string{LabelPeerEndpoint}),

		FQDNSelectors: metric.NewGauge(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemFQDN + "_selectors",
			Namespace:  Namespace,
			Subsystem:  SubsystemFQDN,
			Name:       "selectors",
			Help:       "Number of registered ToFQDN selectors",
		}),

		FQDNSemaphoreRejectedTotal: metric.NewCounter(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemFQDN + "_semaphore_rejected_total",
			Disabled:   true,
			Namespace:  Namespace,
			Subsystem:  SubsystemFQDN,
			Name:       "semaphore_rejected_total",
			Help:       "Number of DNS request rejected by the DNS Proxy's admission semaphore",
		}),

		BPFSyscallDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_" + SubsystemBPF + "_syscall_duration_seconds",
			Disabled:   true,
			Namespace:  Namespace,
			Subsystem:  SubsystemBPF,
			Name:       "syscall_duration_seconds",
			Help:       "Duration of BPF system calls",
		}, []string{LabelOperation, LabelOutcome}),

		BPFMapOps: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemBPF + "_map_ops_total",
			Namespace:  Namespace,
			Subsystem:  SubsystemBPF,
			Name:       "map_ops_total",
			Help:       "Total operations on map, tagged by map name",
		}, []string{LabelMapName, LabelOperation, LabelOutcome}),

		BPFMapCapacity: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemBPF + "_map_capacity",
			Namespace:  Namespace,
			Subsystem:  SubsystemBPF,
			Name:       "map_capacity",
			Help:       "Capacity of map, tagged by map group. All maps with a capacity of 65536 are grouped under 'default'",
		}, []string{LabelMapGroup}),

		VersionMetric: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_version",
			Namespace:  Namespace,
			Name:       "version",
			Help:       "Cilium version",
		}, []string{LabelVersion, LabelVersionRevision, LabelArch}),

		APILimiterWaitHistoryDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_" + SubsystemAPILimiter + "_wait_history_duration_seconds",
			Disabled:   true,
			Namespace:  Namespace,
			Subsystem:  SubsystemAPILimiter,
			Name:       "wait_history_duration_seconds",
			Help:       "Histogram over duration of waiting period for API calls subjects to rate limiting",
		}, []string{"api_call"}),

		APILimiterWaitDuration: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemAPILimiter + "_wait_duration_seconds",
			Namespace:  Namespace,
			Subsystem:  SubsystemAPILimiter,
			Name:       "wait_duration_seconds",
			Help:       "Current wait time for api calls",
		}, []string{"api_call", "value"}),

		APILimiterProcessingDuration: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemAPILimiter + "_processing_duration_seconds",
			Namespace:  Namespace,
			Subsystem:  SubsystemAPILimiter,
			Name:       "processing_duration_seconds",
			Help:       "Current processing time of api call",
		}, []string{"api_call", "value"}),

		APILimiterRequestsInFlight: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemAPILimiter + "_requests_in_flight",
			Namespace:  Namespace,
			Subsystem:  SubsystemAPILimiter,
			Name:       "requests_in_flight",
			Help:       "Current requests in flight",
		}, []string{"api_call", "value"}),

		APILimiterRateLimit: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemAPILimiter + "_rate_limit",
			Namespace:  Namespace,
			Subsystem:  SubsystemAPILimiter,
			Name:       "rate_limit",
			Help:       "Current rate limiting configuration",
		}, []string{"api_call", "value"}),

		APILimiterAdjustmentFactor: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_" + SubsystemAPILimiter + "_adjustment_factor",
			Namespace:  Namespace,
			Subsystem:  SubsystemAPILimiter,
			Name:       "adjustment_factor",
			Help:       "Current adjustment factor while auto adjusting",
		}, []string{"api_call"}),

		APILimiterProcessedRequests: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_" + SubsystemAPILimiter + "_processed_requests_total",
			Namespace:  Namespace,
			Subsystem:  SubsystemAPILimiter,
			Name:       "processed_requests_total",
			Help:       "Total number of API requests processed",
		}, []string{"api_call", LabelOutcome, LabelAPIReturnCode}),

		EndpointPropagationDelay: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_endpoint_propagation_delay_seconds",
			Namespace:  Namespace,
			Name:       "endpoint_propagation_delay_seconds",
			Help:       "CiliumEndpoint roundtrip propagation delay in seconds",
			Buckets:    []float64{.05, .1, 1, 5, 30, 60, 120, 240, 300, 600},
		}, []string{}),

		NodeHealthConnectivityStatus: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_node_health_connectivity_status",
			Namespace:  Namespace,
			Name:       "node_health_connectivity_status",
			Help:       "The number of endpoints with last observed status of both ICMP and HTTP connectivity between the current Cilium agent and other Cilium nodes",
		}, []string{
			LabelSourceCluster,
			LabelSourceNodeName,
			LabelType,
			LabelConnectivityStatus,
		}),

		NodeHealthConnectivityLatency: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_node_health_connectivity_latency_seconds",
			Namespace:  Namespace,
			Name:       "node_health_connectivity_latency_seconds",
			Help:       "The histogram for last observed latency between the current Cilium agent and other Cilium nodes in seconds",
			Buckets:    []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0},
		}, []string{
			LabelSourceCluster,
			LabelSourceNodeName,
			LabelType,
			LabelProtocol,
			LabelAddressType,
		}),

		WorkQueueDepth:                   WorkQueueDepth,
		WorkQueueAddsTotal:               WorkQueueAddsTotal,
		WorkQueueLatency:                 WorkQueueLatency,
		WorkQueueDuration:                WorkQueueDuration,
		WorkQueueUnfinishedWork:          WorkQueueUnfinishedWork,
		WorkQueueLongestRunningProcessor: WorkQueueLongestRunningProcessor,
		WorkQueueRetries:                 WorkQueueRetries,
	}

	ifindexOpts := metric.GaugeOpts{
		ConfigName: Namespace + "_endpoint_max_ifindex",
		Disabled:   true,
		Namespace:  Namespace,
		Name:       "endpoint_max_ifindex",
		Help:       "Maximum interface index observed for existing endpoints",
	}
	lm.EndpointMaxIfindex = metric.NewGauge(ifindexOpts)

	v := version.GetCiliumVersion()
	lm.VersionMetric.WithLabelValues(v.Version, v.Revision, v.Arch)
	lm.BPFMapCapacity.WithLabelValues("default").Set(DefaultMapCapacity)

	BootstrapTimes = lm.BootstrapTimes
	APIInteractions = lm.APIInteractions
	NodeHealthConnectivityStatus = lm.NodeHealthConnectivityStatus
	NodeHealthConnectivityLatency = lm.NodeHealthConnectivityLatency
	Endpoint = lm.Endpoint
	EndpointMaxIfindex = lm.EndpointMaxIfindex
	EndpointRegenerationTotal = lm.EndpointRegenerationTotal
	EndpointStateCount = lm.EndpointStateCount
	EndpointRegenerationTimeStats = lm.EndpointRegenerationTimeStats
	EndpointPropagationDelay = lm.EndpointPropagationDelay
	Policy = lm.Policy
	PolicyRevision = lm.PolicyRevision
	PolicyChangeTotal = lm.PolicyChangeTotal
	PolicyEndpointStatus = lm.PolicyEndpointStatus
	PolicyImplementationDelay = lm.PolicyImplementationDelay
	PolicyIncrementalUpdateDuration = lm.PolicyIncrementalUpdateDuration
	Identity = lm.Identity
	IdentityLabelSources = lm.IdentityLabelSources
	EventTS = lm.EventTS
	EventLagK8s = lm.EventLagK8s
	ProxyRedirects = lm.ProxyRedirects
	ProxyPolicyL7Total = lm.ProxyPolicyL7Total
	ProxyUpstreamTime = lm.ProxyUpstreamTime
	ProxyDatapathUpdateTimeout = lm.ProxyDatapathUpdateTimeout
	ConntrackGCRuns = lm.ConntrackGCRuns
	ConntrackGCKeyFallbacks = lm.ConntrackGCKeyFallbacks
	ConntrackGCSize = lm.ConntrackGCSize
	NatGCSize = lm.NatGCSize
	ConntrackGCDuration = lm.ConntrackGCDuration
	ConntrackInterval = lm.ConntrackInterval
	ConntrackDumpResets = lm.ConntrackDumpResets
	SignalsHandled = lm.SignalsHandled
	ServicesEventsCount = lm.ServicesEventsCount
	ServiceImplementationDelay = lm.ServiceImplementationDelay
	ErrorsWarnings = lm.ErrorsWarnings
	ControllerRuns = lm.ControllerRuns
	ControllerRunsDuration = lm.ControllerRunsDuration
	SubprocessStart = lm.SubprocessStart
	KubernetesEventProcessed = lm.KubernetesEventProcessed
	KubernetesEventReceived = lm.KubernetesEventReceived
	KubernetesAPIInteractions = lm.KubernetesAPIInteractions
	KubernetesAPIRateLimiterLatency = lm.KubernetesAPIRateLimiterLatency
	KubernetesAPICallsTotal = lm.KubernetesAPICallsTotal
	TerminatingEndpointsEvents = lm.TerminatingEndpointsEvents
	IPAMEvent = lm.IPAMEvent
	IPAMCapacity = lm.IPAMCapacity
	KVStoreOperationsDuration = lm.KVStoreOperationsDuration
	KVStoreEventsQueueDuration = lm.KVStoreEventsQueueDuration
	KVStoreQuorumErrors = lm.KVStoreQuorumErrors
	FQDNGarbageCollectorCleanedTotal = lm.FQDNGarbageCollectorCleanedTotal
	FQDNActiveNames = lm.FQDNActiveNames
	FQDNActiveIPs = lm.FQDNActiveIPs
	FQDNAliveZombieConnections = lm.FQDNAliveZombieConnections
	FQDNSelectors = lm.FQDNSelectors
	FQDNSemaphoreRejectedTotal = lm.FQDNSemaphoreRejectedTotal
	IPCacheErrorsTotal = lm.IPCacheErrorsTotal
	IPCacheEventsTotal = lm.IPCacheEventsTotal
	BPFSyscallDuration = lm.BPFSyscallDuration
	BPFMapOps = lm.BPFMapOps
	BPFMapCapacity = lm.BPFMapCapacity
	VersionMetric = lm.VersionMetric
	APILimiterWaitHistoryDuration = lm.APILimiterWaitHistoryDuration
	APILimiterWaitDuration = lm.APILimiterWaitDuration
	APILimiterProcessingDuration = lm.APILimiterProcessingDuration
	APILimiterRequestsInFlight = lm.APILimiterRequestsInFlight
	APILimiterRateLimit = lm.APILimiterRateLimit
	APILimiterAdjustmentFactor = lm.APILimiterAdjustmentFactor
	APILimiterProcessedRequests = lm.APILimiterProcessedRequests

	return lm
}

// InitOperatorMetrics is used to init legacy metrics necessary during operator init.
func InitOperatorMetrics() {
	ErrorsWarnings = newErrorsWarningsMetric()
}

func newErrorsWarningsMetric() metric.Vec[metric.Counter] {
	return metric.NewCounterVec(metric.CounterOpts{
		ConfigName: Namespace + "_errors_warnings_total",
		Namespace:  Namespace,
		Name:       "errors_warnings_total",
		Help:       "Number of total errors in cilium-agent instances",
	}, []string{"level", "subsystem"})
}

// GaugeWithThreshold is a prometheus gauge that registers itself with
// prometheus if over a threshold value and unregisters when under.
type GaugeWithThreshold struct {
	// reg is the registry to register the gauge to. If nil the global registry
	// is used.
	reg *Registry

	gauge     prometheus.Gauge
	threshold float64
	active    bool
}

// Set the value of the GaugeWithThreshold.
func (gwt *GaugeWithThreshold) Set(value float64) {
	if gwt.reg == nil {
		return
	}
	overThreshold := value > gwt.threshold
	if gwt.active && !overThreshold {
		gwt.active = !gwt.reg.Unregister(gwt.gauge)
		if gwt.active {
			gwt.reg.params.Logger.Warn("Failed to unregister metric", logfields.MetricConfig, gwt.gauge.Desc())
		}
	} else if !gwt.active && overThreshold {
		err := gwt.reg.Register(gwt.gauge)
		gwt.active = err == nil
		if err != nil {
			gwt.reg.params.Logger.Warn("Failed to register metric",
				logfields.Error, err,
				logfields.MetricConfig, gwt.gauge.Desc(),
			)
		}
	}

	gwt.gauge.Set(value)
}

// NewGaugeWithThresholdForRegistry creates a new GaugeWithThreshold.
func (reg *Registry) NewGaugeWithThreshold(name, subsystem, desc string, labels map[string]string, threshold float64) *GaugeWithThreshold {
	return &GaugeWithThreshold{
		reg: reg,
		gauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   subsystem,
			Name:        name,
			Help:        desc,
			ConstLabels: labels,
		}),
		threshold: threshold,
		active:    false,
	}
}

// NewBPFMapPressureGauge creates a new GaugeWithThreshold for the
// cilium_bpf_map_pressure metric with the map name as constant label.
func (reg *Registry) NewBPFMapPressureGauge(mapname string, threshold float64) *GaugeWithThreshold {
	return reg.NewGaugeWithThreshold(
		"map_pressure",
		SubsystemBPF,
		"Fill percentage of map, tagged by map name",
		map[string]string{
			LabelMapName: mapname,
		},
		threshold,
	)
}

func Reinitialize() {
	reg, err := registry.Await(context.Background())
	if err == nil {
		reg.inner = prometheus.NewPedanticRegistry()
		reg.registerMetrics()
	}
}

// Register registers a collector
func Register(c prometheus.Collector) error {
	var err error

	withRegistry(func(reg *Registry) {
		err = reg.Register(c)
	})

	return err
}

// RegisterList registers a list of collectors. If registration of one
// collector fails, no collector is registered.
func RegisterList(list []prometheus.Collector) error {
	withRegistry(func(reg *Registry) {
		reg.RegisterList(list)
	})

	return nil
}

// Unregister unregisters a collector
func Unregister(c prometheus.Collector) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reg, err := registry.Await(ctx)
	if err == nil {
		return reg.Unregister(c)
	}

	return false
}

// withRegistry waits up to 1 second for the registry promise to resolve, if it does not then
// we might be calling this function before hive has been started, so to avoid a deadlock,
// wait in a routine so actions are deferred until the registry is initialized.
func withRegistry(fn func(reg *Registry)) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	reg, err := registry.Await(ctx)
	if err == nil {
		fn(reg)
		cancel()
		return
	}
	cancel()

	go func() {
		reg, err := registry.Await(context.Background())
		if err == nil {
			fn(reg)
		}
	}()
}

// GetCounterValue returns the current value
// stored for the counter
func GetCounterValue(m prometheus.Counter) float64 {
	var pm dto.Metric
	err := m.Write(&pm)
	if err == nil && pm.Counter != nil && pm.Counter.Value != nil {
		return *pm.Counter.Value
	}
	return 0
}

// GetGaugeValue returns the current value stored for the gauge. This function
// is useful in tests.
func GetGaugeValue(m prometheus.Gauge) float64 {
	var pm dto.Metric
	err := m.Write(&pm)
	if err == nil && pm.Gauge != nil && pm.Gauge.Value != nil {
		return *pm.Gauge.Value
	}
	return 0
}

// Error2Outcome converts an error to LabelOutcome
func Error2Outcome(err error) string {
	if err != nil {
		return LabelValueOutcomeFail
	}

	return LabelValueOutcomeSuccess
}

// LabelOutcome2Code converts a label outcome to a code
func LabelOutcome2Code(outcome string) int {
	if outcome == LabelValueOutcomeSuccess {
		return 200
	}
	return 500
}

func BoolToFloat64(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

// In general, most bpf maps are allocated to occupy a 16-bit key size.
// To reduce the number of metrics that need to be emitted for map capacity,
// we assume a default map size of 2^16 entries for all maps, which can be
// assumed unless specified otherwise.
const DefaultMapCapacity = 65536

func UpdateMapCapacity(groupName string, capacity uint32) {
	if capacity == 0 || capacity == DefaultMapCapacity {
		return
	}
	BPFMapCapacity.WithLabelValues(groupName).Set(float64(capacity))
}
