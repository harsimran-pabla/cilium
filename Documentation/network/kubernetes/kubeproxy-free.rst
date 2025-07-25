.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _kubeproxy-free:

*****************************
Kubernetes Without kube-proxy
*****************************

This guide explains how to provision a Kubernetes cluster without ``kube-proxy``,
and to use Cilium to fully replace it. For simplicity, we will use ``kubeadm`` to
bootstrap the cluster.

For help with installing ``kubeadm`` and for more provisioning options please refer to
`the official Kubeadm documentation <https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/>`_.

.. note::

   Cilium's kube-proxy replacement depends on the socket-LB feature.

Quick-Start
###########

Initialize the control-plane node via ``kubeadm init`` and skip the
installation of the ``kube-proxy`` add-on:

.. note::
    Depending on what CRI implementation you are using, you may need to use the
    ``--cri-socket`` flag with your ``kubeadm init ...`` command.
    For example: if you're using Docker CRI you would use
    ``--cri-socket unix:///var/run/cri-dockerd.sock``.

.. code-block:: shell-session

    $ kubeadm init --skip-phases=addon/kube-proxy

Afterwards, join worker nodes by specifying the control-plane node IP address and
the token returned by ``kubeadm init``
(for this tutorial, you will want to add at least one worker node to the cluster):

.. code-block:: shell-session

    $ kubeadm join <..>

.. note::

    Please ensure that
    `kubelet <https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/>`_'s
    ``--node-ip`` is set correctly on each worker if you have multiple interfaces.
    Cilium's kube-proxy replacement may not work correctly otherwise.
    You can validate this by running ``kubectl get nodes -o wide`` to see whether
    each node has an ``InternalIP`` which is assigned to a device with the same
    name on each node.

For existing installations with ``kube-proxy`` running as a DaemonSet, remove it
by using the following commands below.

.. warning::
   Be aware that removing ``kube-proxy`` will break existing service connections. It will also stop service related traffic
   until the Cilium replacement has been installed.

.. warning::
   When deploying the eBPF kube-proxy replacement under co-existence with
   kube-proxy on the system, be aware that both mechanisms operate independent of each
   other. Meaning, if the eBPF kube-proxy replacement is added or removed on an already
   *running* cluster in order to delegate operation from respectively back to kube-proxy,
   then it must be expected that existing connections will break since, for example,
   both NAT tables are not aware of each other. If deployed in co-existence on a newly
   spawned up node/cluster which does not yet serve user traffic, then this is not an
   issue.

.. code-block:: shell-session

   $ kubectl -n kube-system delete ds kube-proxy
   $ # Delete the configmap as well to avoid kube-proxy being reinstalled during a Kubeadm upgrade
   $ kubectl -n kube-system delete cm kube-proxy
   $ # Run on each node with root permissions:
   $ iptables-save | grep -v KUBE | iptables-restore

.. include:: ../../installation/k8s-install-download-release.rst

Next, generate the required YAML files and deploy them.

.. important::

   Make sure you correctly set your ``API_SERVER_IP`` and ``API_SERVER_PORT``
   below with the control-plane node IP address and the kube-apiserver port
   number reported by ``kubeadm init`` (Kubeadm will use port ``6443`` by default).

Specifying this is necessary as ``kubeadm init`` is run explicitly without setting
up kube-proxy and as a consequence, although it exports ``KUBERNETES_SERVICE_HOST``
and ``KUBERNETES_SERVICE_PORT`` with a ClusterIP of the kube-apiserver service
to the environment, there is no kube-proxy in our setup provisioning that service.
Therefore, the Cilium agent needs to be made aware of this information with the following configuration:

.. parsed-literal::

    API_SERVER_IP=<your_api_server_ip>
    # Kubeadm default is 6443
    API_SERVER_PORT=<your_api_server_port>
    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=true \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}

.. note::

    Cilium will automatically mount cgroup v2 filesystem required to attach BPF
    cgroup programs by default at the path ``/run/cilium/cgroupv2``. To do that,
    it needs to mount the host ``/proc`` inside an init container
    launched by the DaemonSet temporarily. If you need to disable the auto-mount,
    specify ``--set cgroup.autoMount.enabled=false``, and set the host mount point
    where cgroup v2 filesystem is already mounted by using ``--set cgroup.hostRoot``.
    For example, if not already mounted, you can mount cgroup v2 filesystem by
    running the below command on the host, and specify ``--set cgroup.hostRoot=/sys/fs/cgroup``.

    .. code:: shell-session

        mount -t cgroup2 none /sys/fs/cgroup

This will install Cilium as a CNI plugin with the eBPF kube-proxy replacement to
implement handling of Kubernetes services of type ClusterIP, NodePort, LoadBalancer
and services with externalIPs. As well, the eBPF kube-proxy replacement also
supports hostPort for containers such that using portmap is not necessary anymore.

Finally, as a last step, verify that Cilium has come up correctly on all nodes and
is ready to operate:

.. code-block:: shell-session

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-fmh8d        1/1       Running   0          10m
    cilium-mkcmb        1/1       Running   0          10m

Note, in above Helm configuration, the ``kubeProxyReplacement`` has been set to
``true`` mode. This means that the Cilium agent will bail out in case the
underlying Linux kernel support is missing.

By default, Helm sets ``kubeProxyReplacement=false``, which only enables
per-packet in-cluster load-balancing of ClusterIP services.

Cilium's eBPF kube-proxy replacement is supported in direct routing as well as in
tunneling mode.

Validate the Setup
##################

After deploying Cilium with above Quick-Start guide, we can first validate that
the Cilium agent is running in the desired mode:

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium-dbg status | grep KubeProxyReplacement
    KubeProxyReplacement:   True	[eth0 (Direct Routing), eth1]

Use ``--verbose`` for full details:

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium-dbg status --verbose
    [...]
    KubeProxyReplacement Details:
      Status:                True
      Socket LB:             Enabled
      Protocols:             TCP, UDP
      Devices:               eth0 (Direct Routing), eth1
      Mode:                  SNAT
      Backend Selection:     Random
      Session Affinity:      Enabled
      Graceful Termination:  Enabled
      NAT46/64 Support:      Enabled
      XDP Acceleration:      Disabled
      Services:
      - ClusterIP:      Enabled
      - NodePort:       Enabled (Range: 30000-32767)
      - LoadBalancer:   Enabled
      - externalIPs:    Enabled
      - HostPort:       Enabled
    [...]

As an optional next step, we will create an Nginx Deployment. Then we'll create a new NodePort service and
validate that Cilium installed the service correctly.

The following YAML is used for the backend pods:

.. code-block:: yaml

    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: my-nginx
    spec:
      selector:
        matchLabels:
          run: my-nginx
      replicas: 2
      template:
        metadata:
          labels:
            run: my-nginx
        spec:
          containers:
          - name: my-nginx
            image: nginx
            ports:
            - containerPort: 80

Verify that the Nginx pods are up and running:

.. code-block:: shell-session

    $ kubectl get pods -l run=my-nginx -o wide
    NAME                        READY   STATUS    RESTARTS   AGE   IP             NODE   NOMINATED NODE   READINESS GATES
    my-nginx-756fb87568-gmp8c   1/1     Running   0          62m   10.217.0.149   apoc   <none>           <none>
    my-nginx-756fb87568-n5scv   1/1     Running   0          62m   10.217.0.107   apoc   <none>           <none>

In the next step, we create a NodePort service for the two instances:

.. code-block:: shell-session

    $ kubectl expose deployment my-nginx --type=NodePort --port=80
    service/my-nginx exposed

Verify that the NodePort service has been created:

.. code-block:: shell-session

    $ kubectl get svc my-nginx
    NAME       TYPE       CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
    my-nginx   NodePort   10.104.239.135   <none>        80:31940/TCP   24m

With the help of the ``cilium-dbg service list`` command, we can validate that
Cilium's eBPF kube-proxy replacement created the new NodePort service.
In this example, services with port ``31940`` were created (one for each of devices ``eth0`` and ``eth1``):

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium-dbg service list
    ID   Frontend               Service Type   Backend
    [...]
    4    10.104.239.135:80/TCP      ClusterIP      1 => 10.217.0.107:80/TCP
                                                   2 => 10.217.0.149:80/TCP
    5    0.0.0.0:31940/TCP          NodePort       1 => 10.217.0.107:80/TCP
                                                   2 => 10.217.0.149:80/TCP
    6    192.168.178.29:31940/TCP   NodePort       1 => 10.217.0.107:80/TCP
                                                   2 => 10.217.0.149:80/TCP
    7    172.16.0.29:31940/TCP      NodePort       1 => 10.217.0.107:80/TCP
                                                   2 => 10.217.0.149:80/TCP

Create a variable with the node port for testing:

.. code-block:: shell-session

    $ node_port=$(kubectl get svc my-nginx -o=jsonpath='{@.spec.ports[0].nodePort}')

At the same time we can verify, using ``iptables`` in the host namespace,
that no ``iptables`` rule for the service is present:

.. code-block:: shell-session

    $ iptables-save | grep KUBE-SVC
    [ empty line ]

Last but not least, a simple ``curl`` test shows connectivity for the exposed
NodePort as well as for the ClusterIP:

.. code-block:: shell-session

    $ curl 127.0.0.1:$node_port
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    [....]

.. code-block:: shell-session

    $ curl 192.168.178.29:$node_port
    <!doctype html>
    <html>
    <head>
    <title>welcome to nginx!</title>
    [....]

.. code-block:: shell-session

    $ curl 172.16.0.29:$node_port
    <!doctype html>
    <html>
    <head>
    <title>welcome to nginx!</title>
    [....]

.. code-block:: shell-session

    $ curl 10.104.239.135:80
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    [....]

As can be seen, Cilium's eBPF kube-proxy replacement is set up correctly.

Advanced Configuration
######################

This section covers a few advanced configuration modes for the kube-proxy replacement
that go beyond the above Quick-Start guide and are entirely optional.

Client Source IP Preservation
*****************************

Cilium's eBPF kube-proxy replacement implements various options to avoid
performing SNAT on NodePort requests where the client source IP address would otherwise
be lost on its path to the service endpoint.

- ``externalTrafficPolicy=Local``: The ``Local`` policy is generally supported through
  the eBPF implementation. In-cluster connectivity for services with ``externalTrafficPolicy=Local``
  is possible and can also be reached from nodes which have no local backends, meaning,
  given SNAT does not need to be performed, all service endpoints are available for
  load balancing from in-cluster side.

- ``externalTrafficPolicy=Cluster``: For the ``Cluster`` policy which is the default
  upon service creation, multiple options exist for achieving client source IP preservation
  for external traffic, that is, operating the kube-proxy replacement in :ref:`DSR<DSR Mode>`
  or :ref:`Hybrid<Hybrid Mode>` mode if only TCP-based services are exposed to the outside
  world for the latter.

Internal Traffic Policy
***********************

Similar to ``externalTrafficPolicy`` described above, Cilium's eBPF kube-proxy replacement
supports ``internalTrafficPolicy``, which translates the above semantics to in-cluster traffic.

- For services with ``internalTrafficPolicy=Local``, traffic originated from pods in the
  current cluster is routed only to endpoints within the same node the traffic originated from.

- ``internalTrafficPolicy=Cluster`` is the default, and it doesn't restrict the endpoints that
  can handle internal (in-cluster) traffic.

The following table gives an idea of what backends are used to serve connections to a service,
depending on the external and internal traffic policies:

+---------------------+-------------------------------------------------+
| Traffic policy      | Service backends used                           |
+----------+----------+-------------------------+-----------------------+
| Internal | External | for North-South traffic | for East-West traffic |
+==========+==========+=========================+=======================+
| Cluster  | Cluster  | All (default)           | All (default)         |
+----------+----------+-------------------------+-----------------------+
| Cluster  | Local    | Node-local only         | All (default)         |
+----------+----------+-------------------------+-----------------------+
| Local    | Cluster  | All (default)           | Node-local only       |
+----------+----------+-------------------------+-----------------------+
| Local    | Local    | Node-local only         | Node-local only       |
+----------+----------+-------------------------+-----------------------+

Selective Service Type Exposure
*******************************

By default, for a ``LoadBalancer`` service Cilium exposes corresponding
``NodePort`` and ``ClusterIP`` services. Likewise, for a new ``NodePort``
service, Cilium exposes the corresponding ``ClusterIP`` service.

If this behavior is not desired, then the ``service.cilium.io/type``
annotation can be used to pin the service creation only to a specific
service type:

.. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: example-service
    annotations:
      service.cilium.io/type: LoadBalancer
  spec:
    ports:
      - port: 80
        targetPort: 80
    type: LoadBalancer
    allocateLoadBalancerNodePorts: false

In the above example only the ``LoadBalancer`` service is created without
corresponding ``NodePort`` and ``ClusterIP`` services. If the annotation
would be set to e.g. ``service.cilium.io/type: NodePort``, then only the
``NodePort`` service would be installed.

Host Proxy Delegation
*********************

If the selected service backend IP for a given service matches the local
node IP, the annotation ``service.cilium.io/proxy-delegation: delegate-if-local``
will pass the received packet unmodified to the upper stack, so that a
L7 proxy such as Envoy (if present) can handle the request in the host
namespace. This mechanism is mainly targeted for north/south traffic.

If the selected service backend is a remote IP, then the received packet
is not pushed to the upper stack and instead the BPF code forwards the
packet natively with the configured forwarding method to the remote IP.

.. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: example-service
    annotations:
      service.cilium.io/proxy-delegation: delegate-if-local
  spec:
    ports:
      - port: 80
        targetPort: 80
    type: LoadBalancer

In combination with ``externalTrafficPolicy=Local`` this mechanism also allows
for pushing all traffic to the upper proxy.

For east/west traffic, the service translation is skipped and the packet goes
out of the node without any DNAT.

Non-presence of the ``service.cilium.io/proxy-delegation`` annotation leaves
all forwarding to BPF natively which is also the default for the kube-proxy
replacement case.

Selective Service Node Exposure
*******************************

By default, Cilium exposes Kubernetes services on all nodes in the cluster. To expose a
service only on a subset of the nodes instead, use the ``service.cilium.io/node`` label for
the relevant nodes. For example, label a node as follows:

.. code-block:: shell-session

  $ kubectl label node node_name service.cilium.io/node=beefy

To add a new service that should only be exposed to nodes with label ``service.cilium.io/node=beefy``, install the service as follows:

.. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: example-service
    annotations:
      service.cilium.io/node: beefy
  spec:
    selector:
      app: example
    ports:
      - port: 8765
        targetPort: 9376
    type: LoadBalancer

It's also possible to control the service node exposure via the annotation ``service.cilium.io/node-selector`` - where
the annotation value contains the label selector. This way, the service is only exposed on nodes that match the
node label selector. The annotation ``service.cilium.io/node-selector`` always has priority over 
``service.cilium.io/node`` if both exist on the same service.

.. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: example-service
    annotations:
      service.cilium.io/node-selector: "service.cilium.io/node in ( beefy , slow )"
  spec:
    selector:
      app: example
    ports:
      - port: 8765
        targetPort: 9376
    type: LoadBalancer

Note that changing a node label after a service has been exposed matching that label does not
automatically update the list of nodes where the service is exposed. To update exposure of the
service after changing node labels, restart the Cilium agent. Generally it is advised to fixate the
node label upon joining the Kubernetes cluster and retain it throughout the node's lifetime.

.. _maglev:

Maglev Consistent Hashing
*************************

Cilium's eBPF kube-proxy replacement supports consistent hashing by implementing a variant
of `The Maglev hashing <https://static.googleusercontent.com/media/research.google.com/ko//pubs/archive/44824.pdf>`_
in its load balancer for backend selection. This improves resiliency in case of
failures. As well, it provides better load balancing properties since Nodes added to the cluster will
make consistent backend selection throughout the cluster for a given 5-tuple without
having to synchronize state with the other Nodes. Similarly, upon backend removal the backend
lookup tables are reprogrammed with minimal disruption for unrelated backends (at most 1%
difference in the reassignments) for the given service.

Maglev hashing for services load balancing can be enabled by setting ``loadBalancer.algorithm=maglev``:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=true \\
        --set loadBalancer.algorithm=maglev \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}

Note that Maglev hashing is applied only to external (N-S) traffic. For
in-cluster service connections (E-W), sockets are assigned to service backends
directly, e.g. at TCP connect time, without any intermediate hop and thus are
not subject to Maglev. Maglev hashing is also supported for Cilium's
:ref:`XDP<XDP Acceleration>` acceleration.

There are two more Maglev-specific configuration settings: ``maglev.tableSize``
and ``maglev.hashSeed``.

``maglev.tableSize`` specifies the size of the Maglev lookup table for each single service.
`Maglev <https://static.googleusercontent.com/media/research.google.com/ko//pubs/archive/44824.pdf>`__
recommends the table size (``M``) to be significantly larger than the number of maximum expected
backends (``N``). In practice that means that ``M`` should be larger than ``100 * N`` in
order to guarantee the property of at most 1% difference in the reassignments on backend
changes. ``M`` must be a prime number. Cilium uses a default size of ``16381`` for ``M``.
The following sizes for ``M`` are supported as ``maglev.tableSize`` Helm option:

+----------------------------+
| ``maglev.tableSize`` value |
+============================+
| 251                        |
+----------------------------+
| 509                        |
+----------------------------+
| 1021                       |
+----------------------------+
| 2039                       |
+----------------------------+
| 4093                       |
+----------------------------+
| 8191                       |
+----------------------------+
| 16381                      |
+----------------------------+
| 32749                      |
+----------------------------+
| 65521                      |
+----------------------------+
| 131071                     |
+----------------------------+

For example, a ``maglev.tableSize`` of ``16381`` is suitable for a maximum of ``~160`` backends
per service. If a higher number of backends are provisioned under this setting, then the
difference in reassignments on backend changes will increase. Note that changing the table
size (``M``) triggers a recalculation of the lookup table and can temporarily lead to inconsistent
backend selection for new traffic until all nodes have converged and completed their agent restart.

The ``maglev.hashSeed`` option is recommended to be set in order for Cilium to not rely on the
fixed built-in seed. The seed is a base64-encoded 12 byte-random number, and can be
generated once through ``head -c12 /dev/urandom | base64 -w0``, for example.
Every Cilium agent in the cluster must use the same hash seed for Maglev to work.

The below deployment example is generating and passing such seed to Helm as well as setting the
Maglev table size to ``65521`` to allow for ``~650`` maximum backends for a
given service (with the property of at most 1% difference on backend reassignments):

.. parsed-literal::

    SEED=$(head -c12 /dev/urandom | base64 -w0)
    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=true \\
        --set loadBalancer.algorithm=maglev \\
        --set maglev.tableSize=65521 \\
        --set maglev.hashSeed=$SEED \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}


Note that enabling Maglev will have a higher memory consumption on each Cilium-managed Node compared
to the default of ``loadBalancer.algorithm=random`` given ``random`` does not need the extra lookup
tables. However, ``random`` won't have consistent backend selection.

.. _DSR mode:

Direct Server Return (DSR)
**************************

By default, Cilium's eBPF NodePort implementation operates in SNAT mode. That is,
when node-external traffic arrives and the node determines that the backend for
the LoadBalancer, NodePort, or services with externalIPs is at a remote node, then the
node is redirecting the request to the remote backend on its behalf by performing
SNAT. This does not require any additional MTU changes. The cost is that replies
from the backend need to make the extra hop back to that node to perform the
reverse SNAT translation there before returning the packet directly to the external
client.

This setting can be changed through the ``loadBalancer.mode`` Helm option to
``dsr`` in order to let Cilium's eBPF NodePort implementation operate in DSR mode.
In this mode, the backends reply directly to the external client without taking
the extra hop, meaning, backends reply by using the service IP/port as a source.

Another advantage in DSR mode is that the client's source IP is preserved, so policy
can match on it at the backend node. In the SNAT mode this is not possible.
Given a specific backend can be used by multiple services, the backends need to be
made aware of the service IP/port which they need to reply with. Cilium encodes this
information into the packet (using one of the dispatch mechanisms described below),
at the cost of advertising a lower MTU. For TCP services, Cilium
only encodes the service IP/port for the SYN packet, but not subsequent ones. This
optimization also allows to operate Cilium in a hybrid mode as detailed in the later
subsection where DSR is used for TCP and SNAT for UDP in order to avoid an otherwise
needed MTU reduction.

In some public cloud provider environments that implement source /
destination IP address checking (e.g. AWS), the checking has to be disabled in
order for the DSR mode to work.

By default Cilium uses special ExternalIP mitigation for CVE-2020-8554 MITM vulnerability.
This may affect connectivity targeted to ExternalIP on the same cluster.
This mitigation can be disabled by setting ``bpf.disableExternalIPMitigation`` to ``true``.

.. _DSR mode with Option:

Direct Server Return (DSR) with IPv4 option / IPv6 extension Header
*******************************************************************

In this DSR dispatch mode, the service IP/port information is transported to the
backend through a Cilium-specific IPv4 Option or IPv6 Destination Option extension header.
It requires Cilium to be deployed in :ref:`arch_direct_routing`, i.e.
it will not work in :ref:`arch_overlay` mode.

This DSR mode might not work in some public cloud provider environments
due to the Cilium-specific IP options that could be dropped by an underlying network fabric.
In case of connectivity issues to services where backends are located on
a remote node from the node that is processing the given NodePort request,
first check whether the NodePort request actually arrived on the node
containing the backend. If this was not the case, then consider either switching to
DSR with Geneve (as described below), or switching back to the default SNAT mode.

The above Helm example configuration in a kube-proxy-free environment with DSR-only mode
enabled would look as follows:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set routingMode=native \\
        --set kubeProxyReplacement=true \\
        --set loadBalancer.mode=dsr \\
        --set loadBalancer.dsrDispatch=opt \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}

.. _DSR mode with Geneve:

Direct Server Return (DSR) with Geneve
**************************************
By default, Cilium with DSR mode encodes the service IP/port in a Cilium-specific
IPv4 option or IPv6 Destination Option extension so that the backends are aware of
the service IP/port, which they need to reply with.

However, some data center routers pass packets with unknown IP options to software
processing called "Layer 2 slow path". Those routers drop the packets if the amount
of packets with IP options exceeds a given threshold, which may significantly affect
network performance.

Cilium offers another dispatch mode, DSR with Geneve, to avoid this problem.
In DSR with Geneve, Cilium encapsulates packets to the Loadbalancer with the Geneve
header that includes the service IP/port in the Geneve option and redirects them
to the backends.

The Helm example configuration in a kube-proxy-free environment with DSR and
Geneve dispatch enabled would look as follows:

.. parsed-literal::
    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set routingMode=native \\
        --set tunnelProtocol=geneve \\
        --set kubeProxyReplacement=true \\
        --set loadBalancer.mode=dsr \\
        --set loadBalancer.dsrDispatch=geneve \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}

DSR with Geneve is compatible with the Geneve encapsulation mode (:ref:`arch_overlay`).
It works with either the direct routing mode or the Geneve tunneling mode. Unfortunately,
it doesn't work with the vxlan encapsulation mode.

The example configuration in DSR with Geneve dispatch and tunneling mode is as follows.

.. parsed-literal::
    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set routingMode=tunnel \\
        --set tunnelProtocol=geneve \\
        --set kubeProxyReplacement=true \\
        --set loadBalancer.mode=dsr \\
        --set loadBalancer.dsrDispatch=geneve \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}

.. _Hybrid mode:

Hybrid DSR and SNAT Mode
************************

Cilium also supports a hybrid DSR and SNAT mode, that is, DSR is performed for TCP
and SNAT for UDP connections.

This removes the need for manual MTU changes in the network while still benefiting
from the latency improvements through the removed extra hop for replies, in particular,
when TCP is the main transport for workloads.

The mode setting ``loadBalancer.mode`` allows to control the behavior through the
options ``dsr``, ``snat``, ``annotation``, and ``hybrid``. By default the ``snat``
mode is used in the agent.

A Helm example configuration in a kube-proxy-free environment with DSR enabled in
hybrid mode would look as follows:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set routingMode=native \\
        --set kubeProxyReplacement=true \\
        --set loadBalancer.mode=hybrid \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}

Annotation-based DSR and SNAT Mode
**********************************

Cilium also supports an annotation-based DSR and SNAT mode, that is, services
can be exposed by default via SNAT and on-demand as DSR (or vice versa):

.. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: example-service
    annotations:
      service.cilium.io/type: LoadBalancer
      service.cilium.io/forwarding-mode: dsr
  spec:
    ports:
      - port: 80
        targetPort: 80
    type: LoadBalancer

Note that the ``forwarding-mode`` annotation must be set at service creation time
and should not be changed during the lifetime of that service. Changing the value
of the annotation or removing the annotation while the service is installed breaks
connections.

The above example installs the Kubernetes service only as type ``LoadBalancer``,
that is, without the corresponding ``NodePort`` and ``ClusterIP`` services, and
uses the configured DSR method to forward the packets instead of default SNAT.
The Helm setting ``loadBalancer.mode=snat`` defines the default as SNAT in this
example. A ``loadBalancer.mode=dsr`` would have switched the default to DSR instead
and then ``service.cilium.io/forwarding-mode: snat`` annotation can be used to
switch to SNAT instead.

A Helm example configuration in a kube-proxy-free environment with DSR enabled in
annotation mode with SNAT default would look as follows:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set routingMode=native \\
        --set kubeProxyReplacement=true \\
        --set loadBalancer.mode=snat \\
        --set bpf.lbModeAnnotation=true \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}

Annotation-based Load Balancing Algorithm Selection
***************************************************

Cilium has the ability to specify the load balancing algorithm on a per-service
basis through the ``service.cilium.io/lb-algorithm`` annotation. Setting
``bpf.lbAlgorithmAnnotation=true`` opts into this ability for the BPF and
corresponding agent code. A typical use-case is to reduce the memory footprint
which comes with Maglev given the latter requires large lookup tables for each
service. Thus, if not all services need consistent hashing, then these can
fallback to a random selection instead.

By default, if no service annotation is provided, the logic falls back to use
whichever method was specified globally through ``loadBalancer.algorithm``. The
latter supports either ``random`` or ``maglev`` as values today with ``random``
being the default if ``loadBalancer.algorithm`` was not explicitly set via Helm.

To add a new service which must use ``random`` as its load balancing algorithm:

.. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: example-service
    annotations:
      service.cilium.io/lb-algorithm: random
  spec:
    selector:
      app: example
    ports:
      - port: 8765
        targetPort: 9376
    type: LoadBalancer

Similarly, for opting into ``maglev``, use the following:

 .. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: example-service
    annotations:
      service.cilium.io/lb-algorithm: maglev
  spec:
    selector:
      app: example
    ports:
      - port: 8765
        targetPort: 9376
    type: LoadBalancer

All north-south traffic is now subsequently subject to ``maglev``-based load
balancing for the latter example.

Note that ``service.cilium.io/lb-algorithm`` only takes effect upon initial
service creation and cannot be changed during the lifetime of the given
Kubernetes service. Switching between load balancing algorithms requires
recreation of a service.

.. _socketlb-host-netns-only:

Socket LoadBalancer Bypass in Pod Namespace
*******************************************

The socket-level loadbalancer acts transparent to Cilium's lower layer datapath
in that upon ``connect`` (TCP, connected UDP), ``sendmsg`` (UDP), or ``recvmsg``
(UDP) system calls, the destination IP is checked for an existing service IP and
one of the service backends is selected as a target. This means that although
the application assumes it is connected to the service address, the
corresponding kernel socket is actually connected to the backend address and
therefore no additional lower layer NAT is required.

Cilium has built-in support for bypassing the socket-level loadbalancer and falling back
to the tc loadbalancer at the veth interface when a custom redirection/operation relies
on the original ClusterIP within pod namespace (e.g., Istio sidecar) or due to the Pod's
nature the socket-level loadbalancer is ineffective (e.g., KubeVirt, Kata Containers,
gVisor).

Setting ``socketLB.hostNamespaceOnly=true`` enables this bypassing mode. When enabled,
this circumvents socket rewrite in the ``connect()`` and ``sendmsg()`` syscall bpf hook and
will pass the original packet to next stage of operation (e.g., stack in
``per-endpoint-routing`` mode) and re-enables service lookup in the tc bpf program.

A Helm example configuration in a kube-proxy-free environment with socket LB bypass
looks as follows:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set routingMode=native \\
        --set kubeProxyReplacement=true \\
        --set socketLB.hostNamespaceOnly=true

.. _XDP acceleration:

LoadBalancer & NodePort XDP Acceleration
****************************************

Cilium has built-in support for accelerating NodePort, LoadBalancer services and
services with externalIPs for the case where the arriving request needs to be
forwarded and the backend is located on a remote node. This feature was introduced
in Cilium version `1.8 <https://cilium.io/blog/2020/06/22/cilium-18/#kube-proxy-replacement-at-the-xdp-layer>`_ at
the XDP (eXpress Data Path) layer where eBPF is operating directly in the networking
driver instead of a higher layer.

Setting ``loadBalancer.acceleration`` to option ``native`` enables this acceleration.
The option ``disabled`` is the default and disables the acceleration. The majority
of drivers supporting 10G or higher rates also support ``native`` XDP on a recent
kernel. For cloud based deployments most of these drivers have SR-IOV variants that
support native XDP as well. For on-prem deployments the Cilium XDP acceleration can
be used in combination with LoadBalancer service implementations for Kubernetes such
as `MetalLB <https://metallb.universe.tf/>`_. The acceleration can be enabled only
on a single device which is used for direct routing.

For high-scale environments, also consider tweaking the default map sizes to a larger
number of entries e.g. through setting a higher ``config.bpfMapDynamicSizeRatio``.
See :ref:`bpf_map_limitations` for further details.

The ``loadBalancer.acceleration`` setting is supported for DSR, SNAT and hybrid
modes and can be enabled as follows for ``loadBalancer.mode=hybrid`` in this example:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set routingMode=native \\
        --set kubeProxyReplacement=true \\
        --set loadBalancer.acceleration=native \\
        --set loadBalancer.mode=hybrid \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}


In case of a multi-device environment, where Cilium's device auto-detection selects
more than a single device to expose NodePort or a user specifies multiple devices
with ``devices``, the XDP acceleration is enabled on all devices. This means that
each underlying device's driver must have native XDP support on all Cilium managed
nodes. If you have an environment where some devices support XDP but others do not
you can have XDP enabled on the supported devices by setting
``loadBalancer.acceleration`` to ``best-effort``.

A list of drivers supporting XDP can be found in :ref:`the XDP documentation<xdp_drivers>`.

The current Cilium kube-proxy XDP acceleration mode can also be introspected through
the ``cilium-dbg status`` CLI command. If it has been enabled successfully, ``Native``
is shown:

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium-dbg status --verbose | grep XDP
      XDP Acceleration:    Native

Note that packets which have been pushed back out of the device for NodePort handling
right at the XDP layer are not visible in tcpdump since packet taps come at a much
later stage in the networking stack. Cilium's monitor command or metric counters can be used
instead for gaining visibility.

NodePort XDP on AWS
===================

In order to run with NodePort XDP on AWS, follow the instructions in the :ref:`k8s_install_quick`
guide to set up an EKS cluster or use any other method of your preference to set up a
Kubernetes cluster.

If you are following the EKS guide, make sure to create a node group with SSH access, since
we need few additional setup steps as well as create a larger instance type which supports
the `Elastic Network Adapter <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html>`__ (ena).
As an instance example, ``m5n.xlarge`` is used in the config ``nodegroup-config.yaml``:

.. code-block:: yaml

  apiVersion: eksctl.io/v1alpha5
  kind: ClusterConfig

  metadata:
    name: test-cluster
    region: us-west-2

  nodeGroups:
    - name: ng-1
      instanceType: m5n.xlarge
      desiredCapacity: 2
      ssh:
        allow: true
      ## taint nodes so that application pods are
      ## not scheduled/executed until Cilium is deployed.
      ## Alternatively, see the note below.
      taints:
        - key: "node.cilium.io/agent-not-ready"
          value: "true"
          effect: "NoExecute"

.. note::

  Please make sure to read and understand the documentation page on :ref:`taint effects and unmanaged pods<taint_effects>`.

The nodegroup is created with:

.. code-block:: shell-session

  $ eksctl create nodegroup -f nodegroup-config.yaml

Each of the nodes need the ``kernel-ng`` and ``ethtool`` package installed. The former is
needed in order to run a sufficiently recent kernel for eBPF in general and native XDP
support on the ena driver. The latter is needed to configure channel parameters for the NIC.

.. code-block:: shell-session

  $ IPS=$(kubectl get no -o jsonpath='{$.items[*].status.addresses[?(@.type=="ExternalIP")].address }{"\\n"}' | tr ' ' '\\n')

  $ for ip in $IPS ; do ssh ec2-user@$ip "sudo amazon-linux-extras install -y kernel-ng && sudo yum install -y ethtool && sudo reboot"; done

Once the nodes come back up their kernel version should say ``5.4.58-27.104.amzn2.x86_64`` or
similar through ``uname -r``. In order to run XDP on ena, make sure the driver version is at
least `2.2.8 <https://github.com/amzn/amzn-drivers/commit/ccbb1fe2c2f2ab3fc6d7827b012ba8ec06f32c39>`__.
The driver version can be inspected through ``ethtool -i eth0``. For the given kernel version
the driver version should be reported as ``2.2.10g``.

Before Cilium's XDP acceleration can be deployed, there are two settings needed on the
network adapter side, that is, MTU needs to be lowered in order to be able to operate
with XDP, and number of combined channels need to be adapted.

The default MTU is set to 9001 on the ena driver. Given XDP buffers are linear, they
operate on a single page. A driver typically reserves some headroom for XDP as well
(e.g. for encapsulation purpose), therefore, the highest possible MTU for XDP would
be 3498.

In terms of ena channels, the settings can be gathered via ``ethtool -l eth0``. For the
``m5n.xlarge`` instance, the default output should look like::

  Channel parameters for eth0:
  Pre-set maximums:
  RX:             0
  TX:             0
  Other:          0
  Combined:       4
  Current hardware settings:
  RX:             0
  TX:             0
  Other:          0
  Combined:       4

In order to use XDP the channels must be set to at most 1/2 of the value from
``Combined`` above. Both, MTU and channel changes are applied as follows:

.. code-block:: shell-session

  $ for ip in $IPS ; do ssh ec2-user@$ip "sudo ip link set dev eth0 mtu 3498"; done
  $ for ip in $IPS ; do ssh ec2-user@$ip "sudo ethtool -L eth0 combined 2"; done

In order to deploy Cilium, the Kubernetes API server IP and port is needed:

.. code-block:: shell-session

  $ export API_SERVER_IP=$(kubectl get ep kubernetes -o jsonpath='{$.subsets[0].addresses[0].ip}')
  $ export API_SERVER_PORT=443

Finally, the deployment can be upgraded and later rolled-out with the
``loadBalancer.acceleration=native`` setting to enable XDP in Cilium:

.. parsed-literal::

  helm upgrade cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --reuse-values \\
        --set kubeProxyReplacement=true \\
        --set loadBalancer.acceleration=native \\
        --set loadBalancer.mode=snat \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}


NodePort XDP on Azure
=====================

To enable NodePort XDP on Azure AKS or a self-managed Kubernetes running on Azure, the virtual
machines running Kubernetes must have `Accelerated Networking
<https://azure.microsoft.com/en-us/updates/accelerated-networking-in-expanded-preview/>`_
enabled. In addition, the Linux kernel on the nodes must also have support for
native XDP in the ``hv_netvsc`` driver, which is available in kernel >= 5.6 and was backported to
the Azure Linux kernel in 5.4.0-1022.

On AKS, make sure to use the AKS Ubuntu 22.04 node image with Kubernetes version v1.26 which will
provide a Linux kernel with the necessary backports to the ``hv_netvsc`` driver. Please refer to the
documentation on `how to configure an AKS cluster
<https://docs.microsoft.com/en-us/azure/aks/cluster-configuration>`_ for more details.

To enable accelerated networking when creating a virtual machine or
virtual machine scale set, pass the ``--accelerated-networking`` option to the
Azure CLI. Please refer to the guide on how to `create a Linux virtual machine
with Accelerated Networking using Azure CLI
<https://docs.microsoft.com/en-us/azure/virtual-network/create-vm-accelerated-networking-cli>`_
for more details.

When *Accelerated Networking* is enabled, ``lspci`` will show a
Mellanox ConnectX NIC:

.. code-block:: shell-session

    $ lspci | grep Ethernet
    2846:00:02.0 Ethernet controller: Mellanox Technologies MT27710 Family [ConnectX-4 Lx Virtual Function] (rev 80)

XDP acceleration can only be enabled on NICs ConnectX-4 Lx and onwards.

In order to run XDP, large receive offload (LRO) needs to be disabled on the
``hv_netvsc`` device. If not the case already, this can be achieved by:

.. code-block:: shell-session

   $ ethtool -K eth0 lro off

It is recommended to use Azure IPAM for the pod IP address allocation, which
will automatically configure your virtual network to route pod traffic correctly:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set ipam.mode=azure \\
     --set azure.enabled=true \\
     --set azure.resourceGroup=$AZURE_NODE_RESOURCE_GROUP \\
     --set azure.subscriptionID=$AZURE_SUBSCRIPTION_ID \\
     --set azure.tenantID=$AZURE_TENANT_ID \\
     --set azure.clientID=$AZURE_CLIENT_ID \\
     --set azure.clientSecret=$AZURE_CLIENT_SECRET \\
     --set routingMode=native \\
     --set enableIPv4Masquerade=false \\
     --set devices=eth0 \\
     --set kubeProxyReplacement=true \\
     --set loadBalancer.acceleration=native \\
     --set loadBalancer.mode=snat \\
     --set k8sServiceHost=${API_SERVER_IP} \\
     --set k8sServicePort=${API_SERVER_PORT}


When running Azure IPAM on a self-managed Kubernetes cluster, each ``v1.Node``
must have the resource ID of its VM in the ``spec.providerID`` field.
Refer to the :ref:`ipam_azure` reference for more information.

NodePort XDP on GCP
===================

NodePort XDP on the Google Cloud Platform is currently not supported. Both
virtual network interfaces available on Google Compute Engine (the older
virtIO-based interface and the newer `gVNIC
<https://cloud.google.com/compute/docs/instances/create-vm-with-gvnic>`_) are
currently lacking support for native XDP.

.. _NodePort Devices:

NodePort Devices, Port and Bind settings
****************************************

When running Cilium's eBPF kube-proxy replacement, by default, a NodePort or
LoadBalancer service or a service with externalIPs will be accessible through
the IP addresses of native devices which have the default route on the host or
have Kubernetes InternalIP or ExternalIP assigned. InternalIP is preferred over
ExternalIP if both exist. To change the devices, set their names in the
``devices`` Helm option, e.g. ``devices='{eth0,eth1,eth2}'``. Each
listed device has to be named the same on all Cilium managed nodes. Alternatively
if the devices do not match across different nodes, the wildcard option can be
used, e.g. ``devices=eth+``, which would match any device starting with prefix
``eth``. If no device can be matched the Cilium agent will try to perform auto
detection.

When multiple devices are used, only one device can be used for direct routing
between Cilium nodes. By default, if a single device was detected or specified
via ``devices`` then Cilium will use that device for direct routing.
Otherwise, Cilium will use a device with Kubernetes InternalIP or ExternalIP
set. InternalIP is preferred over ExternalIP if both exist. To change
the direct routing device, set the ``nodePort.directRoutingDevice`` Helm
option, e.g. ``nodePort.directRoutingDevice=eth1``. The wildcard option can be
used as well as the devices option, e.g. ``directRoutingDevice=eth+``.
If more than one devices match the wildcard option, Cilium will sort them
in increasing alphanumerical order and pick the first one. If the direct routing
device does not exist within ``devices``, Cilium will add the device to the latter
list. The direct routing device is used for
:ref:`the NodePort XDP acceleration<XDP Acceleration>` as well (if enabled).

In addition, thanks to the socket-LB feature, the NodePort service can
be accessed by default from a host or a pod within a cluster via its public, any
local (except for ``docker*`` prefixed names) or loopback address, e.g.
``127.0.0.1:NODE_PORT``.

If ``kube-apiserver`` was configured to use a non-default NodePort port range,
then the same range must be passed to Cilium via the ``nodePort.range``
option, for example, as ``nodePort.range="10000\,32767"`` for a
range of ``10000-32767``. The default Kubernetes NodePort range is ``30000-32767``.

If the NodePort port range overlaps with the ephemeral port range
(``net.ipv4.ip_local_port_range``), Cilium will append the NodePort range to
the reserved ports (``net.ipv4.ip_local_reserved_ports``). This is needed to
prevent a NodePort service from hijacking traffic of a host local application
which source port matches the service port. To disable the modification of
the reserved ports, set ``nodePort.autoProtectPortRanges`` to ``false``.

By default, the NodePort implementation prevents application ``bind(2)`` requests
to NodePort service ports. In such case, the application will typically see a
``bind: Operation not permitted`` error. By default this happens only for the host
namespace and therefore does not affect any application pod ``bind(2)`` requests.
In order to opt-out from this behavior in general, this setting can be changed for
expert users by switching ``nodePort.bindProtection`` to ``false``.

.. _Configuring Maps:

Configuring BPF Map Sizes
*************************

For high-scale environments, Cilium's BPF maps can be configured to have higher
limits on the number of entries. Overriding Helm options can be used to tweak
these limits.

To increase the number of entries in Cilium's BPF LB service, backend and
affinity maps consider overriding ``bpf.lbMapMax`` Helm option.
The default value of this LB map size is 65536.

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=true \\
        --set bpf.lbMapMax=131072

.. _kubeproxyfree_hostport:

Container HostPort Support
**************************

Although not part of kube-proxy, Cilium's eBPF kube-proxy replacement also
natively supports ``hostPort`` service mapping without having to use the
Helm CNI chaining option of ``cni.chainingMode=portmap``.

By specifying ``kubeProxyReplacement=true`` the native hostPort support is
automatically enabled and therefore no further action is required.

If the ``hostPort`` is specified without an additional ``hostIP``, then the
Pod will be exposed to the outside world with the same local addresses from
the node that were detected and used for exposing NodePort services, e.g.
the Kubernetes InternalIP or ExternalIP if set.

Additionally, the Pod is also accessible through the loopback address on the
node such as ``127.0.0.1:hostPort``. If in addition to ``hostPort`` also
a ``hostIP`` has been specified for the Pod, then the Pod will only be
exposed on the given ``hostIP`` instead. A ``hostIP`` of ``0.0.0.0`` will
have the same behavior as if a ``hostIP`` was not specified.

The ``hostPort`` must not reside in the configured NodePort port range to
avoid collisions.

Note that ``hostPort`` support relies on Cilium's eBPF kube-proxy replacement
and in the background plumbs service entries to direct traffic to the local
host port backend. Given host port is not configured through a Kubernetes
service object, the full feature set of Kubernetes services (such as custom
Cilium service annotations) is not available. Instead, host port piggy-backs
on user-configured defaults of the service handling behavior.

An example deployment in a kube-proxy-free environment therefore is the same
as in the earlier getting started deployment:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=true \\
        --set k8sServiceHost=${API_SERVER_IP} \\
        --set k8sServicePort=${API_SERVER_PORT}

Also, ensure that each node IP is known via ``INTERNAL-IP`` or ``EXTERNAL-IP``,
for example:

.. code-block:: shell-session

    $ kubectl get nodes -o wide
    NAME   STATUS   ROLES    AGE     VERSION   INTERNAL-IP      EXTERNAL-IP   [...]
    apoc   Ready    master   6h15m   v1.17.3   192.168.178.29   <none>        [...]
    tank   Ready    <none>   6h13m   v1.17.3   192.168.178.28   <none>        [...]

If this is not the case, then ``kubelet`` needs to be made aware of it through
specifying ``--node-ip`` through ``KUBELET_EXTRA_ARGS``. Assuming ``eth0`` is
the public facing interface, this can be achieved by:

.. code-block:: shell-session

    $ echo KUBELET_EXTRA_ARGS=\"--node-ip=$(ip -4 -o a show eth0 | awk '{print $4}' | cut -d/ -f1)\" | tee -a /etc/default/kubelet

After updating ``/etc/default/kubelet``, kubelet needs to be restarted.

In order to verify whether the HostPort feature has been enabled in Cilium, the
``cilium-dbg status`` CLI command provides visibility through the ``KubeProxyReplacement``
info line. If it has been enabled successfully, ``HostPort`` is shown as ``Enabled``,
for example:

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium-dbg status --verbose | grep HostPort
      - HostPort:       Enabled

The following modified example yaml from the setup validation with an additional
``hostPort: 8080`` parameter can be used to verify the mapping:

.. code-block:: yaml

    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: my-nginx
    spec:
      selector:
        matchLabels:
          run: my-nginx
      replicas: 1
      template:
        metadata:
          labels:
            run: my-nginx
        spec:
          containers:
          - name: my-nginx
            image: nginx
            ports:
            - containerPort: 80
              hostPort: 8080

After deployment, we can validate that Cilium's eBPF kube-proxy replacement
exposed the container as HostPort under the specified port ``8080``:

.. code-block:: shell-session

    $ kubectl exec -it -n kube-system cilium-fmh8d -- cilium-dbg service list
    ID   Frontend               Service Type   Backend
    [...]
    5    192.168.178.29:8080    HostPort       1 => 10.29.207.199:80

Similarly, we can inspect through ``iptables`` in the host namespace that
no ``iptables`` rule for the HostPort service is present:

.. code-block:: shell-session

    $ iptables-save | grep HOSTPORT
    [ empty line ]

Last but not least, a simple ``curl`` test shows connectivity for the
exposed HostPort container under the node's IP:

.. code-block:: shell-session

    $ curl 192.168.178.29:8080
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    [....]

Removing the deployment also removes the corresponding HostPort from
the ``cilium-dbg service list`` dump:

.. code-block:: shell-session

    $ kubectl delete deployment my-nginx

Graceful Termination
********************

Cilium's eBPF kube-proxy replacement supports graceful termination of service
endpoint pods. The Cilium agent detects such terminating Pod events, and
increments the metric ``k8s_terminating_endpoints_events_total``.

When Cilium agent receives a Kubernetes update event for a terminating endpoint,
the datapath state for the endpoint is removed such that it won't service new
connections, but the endpoint's active connections are able to terminate
gracefully. The endpoint state is fully removed when the agent receives
a Kubernetes delete event for the endpoint. The `Kubernetes
pod termination <https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination>`_
documentation contains more background on the behavior and configuration using ``terminationGracePeriodSeconds``.
There are some special cases, like zero disruption during rolling updates, that require to be able to send traffic
to Terminating Pods that are still Serving traffic during the Terminating period, the Kubernetes blog
`Advancements in Kubernetes Traffic Engineering
<https://kubernetes.io/blog/2022/12/30/advancements-in-kubernetes-traffic-engineering/#traffic-loss-from-load-balancers-during-rolling-updates>`_
explains it in detail.

.. admonition:: Video
  :class: attention

  To learn more about Cilium's graceful termination support, check out `eCHO Episode 49: Graceful Termination Support with Cilium 1.11 <https://www.youtube.com/watch?v=9GBxJMp6UkI&t=980s>`__.

.. _session-affinity:

Session Affinity
****************

Cilium's eBPF kube-proxy replacement supports Kubernetes service session affinity.
Each connection from the same pod or host to a service configured with
``sessionAffinity: ClientIP`` will always select the same service endpoint.
The default timeout for the affinity is three hours (updated by each request to
the service), but it can be configured through Kubernetes' ``sessionAffinityConfig``
if needed.

The source for the affinity depends on the origin of a request. If a request is
sent from outside the cluster to the service, the request's source IP address is
used for determining the endpoint affinity. If a request is sent from inside
the cluster, then the source depends on whether the socket-LB feature
is used to load balance ClusterIP services. If yes, then the client's network
namespace cookie is used as the source - it allows to implement affinity at the
socket layer at which the socket-LB operates (a source IP is not available there,
as the endpoint selection happens before a network packet has been built by the
kernel). If the socket-LB is not used (i.e. the loadbalancing is done
at the pod network interface, on a per-packet basis), then the request's source
IP address is used as the source.

The session affinity support is enabled by default. To disable the feature,
set ``config.sessionAffinity=false``.

The session affinity of a service with multiple ports is per service IP and port.
Meaning that all requests for a given service sent from the same source and to the
same service port will be routed to the same service endpoints; but two requests
for the same service, sent from the same source but to different service ports may
be routed to distinct service endpoints.

Note that if the session affinity feature is used in combination with Maglev
consistent hashing to select backends, then Maglev will not take the source
port as input for its hashing in order to respect the user's ClientIP choice
(see also `GH#26709 <https://github.com/cilium/cilium/issues/26709>`__ for
further details).

kube-proxy Replacement Health Check server
******************************************
To enable health check server for the kube-proxy replacement, the
``kubeProxyReplacementHealthzBindAddr`` option has to be set (disabled by
default). The option accepts the IP address with port for the health check server
to serve on.
E.g. to enable for IPv4 interfaces set ``kubeProxyReplacementHealthzBindAddr='0.0.0.0:10256'``,
for IPv6 - ``kubeProxyReplacementHealthzBindAddr='[::]:10256'``. The health check server is
accessible via the HTTP ``/healthz`` endpoint.

LoadBalancer Source Ranges Checks
*********************************

When a ``LoadBalancer`` service is configured with ``spec.loadBalancerSourceRanges``,
Cilium's eBPF kube-proxy replacement restricts access from outside (e.g. external
world traffic) to the service to the white-listed CIDRs specified in the field. If
the field is empty, no restrictions for the access will be applied.

When accessing the service from inside a cluster, the kube-proxy replacement will
ignore the field regardless whether it is set. This means that any pod or any host
process in the cluster will be able to access the ``LoadBalancer`` service internally.

By default the specified white-listed CIDRs in ``spec.loadBalancerSourceRanges``
only apply to the ``LoadBalancer`` service, but not the corresponding ``NodePort``
or ``ClusterIP`` service which get installed along with the ``LoadBalancer`` service.

If this behavior is not desired, then there are two options available: One possibility
is to avoid the creation of corresponding ``NodePort`` and ``ClusterIP`` services via
``service.cilium.io/type`` annotation:

.. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: example-service
    annotations:
      service.cilium.io/type: LoadBalancer
  spec:
    ports:
      - port: 80
        targetPort: 80
    type: LoadBalancer
    loadBalancerSourceRanges:
    - 192.168.1.0/24

The other possibility is to propagate the white-listed CIDRs to all externally
exposed service types. Meaning, ``NodePort`` as well as ``ClusterIP`` (if
externally accessible, see :ref:`External Access To ClusterIP Services <external_access_to_clusterip_services>`
section) also filter traffic based on the source IP addresses.
This option can be enabled in Helm via ``bpf.lbSourceRangeAllTypes=true``.

The ``loadBalancerSourceRanges`` by default specifies an allow-list of CIDRs,
meaning, traffic originating not from those CIDRs is automatically dropped.

Cilium also supports the option to turn this list into a deny-list, in order
to block traffic from certain CIDRs while allowing everything else. This
behavior can be achieved through the ``service.cilium.io/src-ranges-policy``
annotation which accepts the values of ``allow`` or ``deny``.

The default ``loadBalancerSourceRanges`` behavior equals to
``service.cilium.io/src-ranges-policy: allow``:

.. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: example-service
    annotations:
      service.cilium.io/type: LoadBalancer
      service.cilium.io/src-ranges-policy: allow
  spec:
    ports:
      - port: 80
        targetPort: 80
    type: LoadBalancer
    loadBalancerSourceRanges:
    - 192.168.1.0/24

In order to turn the CIDR list into a deny-list while allowing traffic not
originating from this set, this can be changed into ``service.cilium.io/src-ranges-policy: deny``:

.. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: example-service
    annotations:
      service.cilium.io/type: LoadBalancer
      service.cilium.io/src-ranges-policy: deny
  spec:
    ports:
      - port: 80
        targetPort: 80
    type: LoadBalancer
    loadBalancerSourceRanges:
    - 192.168.1.0/24

Service Proxy Name Configuration
********************************

Like kube-proxy, Cilium also honors the ``service.kubernetes.io/service-proxy-name`` service annotation
and only manages services that contain a matching service-proxy-name label. This name can be configured
by setting ``k8s.serviceProxyName`` option and the behavior is identical to that of
kube-proxy. The service proxy name defaults to an empty string which instructs Cilium to
only manage services not having ``service.kubernetes.io/service-proxy-name`` label.

For more details on the usage of ``service.kubernetes.io/service-proxy-name`` label and its
working, take a look at `this KEP
<https://github.com/kubernetes/enhancements/blob/3ad891202dab1fd5211946f10f31b48003bf8113/keps/sig-network/2447-Make-kube-proxy-service-abstraction-optional/README.md>`__.

.. note::

    If Cilium with a non-empty service proxy name is meant to manage all services in kube-proxy
    free mode, make sure that default Kubernetes services like ``kube-dns`` and ``kubernetes``
    have the required label value.

Traffic Distribution and Topology Aware Hints
*********************************************

The kube-proxy replacement implements both Kubernetes `Topology Aware Routing
<https://kubernetes.io/docs/concepts/services-networking/topology-aware-routing>`__,
and the more recent `Traffic Distribution
<https://kubernetes.io/docs/concepts/services-networking/service/#traffic-distribution>`__
features.

Both of these features work by setting ``hints`` on EndpointSlices that enable
Cilium to route to endpoints residing in the same zone. To enable the feature,
set ``loadBalancer.serviceTopology=true``.

Neighbor Discovery
******************

When kube-proxy replacement and XDP acceleration are enabled, Cilium does L2 neighbor discovery 
of nodes and service backends in the cluster. This is required for the service load-balancing 
to populate L2 addresses for backends since it is not possible to dynamically resolve neighbors
on demand in the fast-path.

L2 neighbor discovery is automatically enabled when the agent detects that XDP is in use, but
can also be manually turned on by setting the ``--enable-l2-neigh-discovery=true`` flag or
``l2NeighDiscovery.enabled=true`` Helm option.

The agent fully relies on the Linux kernel to discover gateways or hosts on the same L2 network. 
Both IPv4 and IPv6 neighbor discovery is supported in the Cilium agent. As per our
kernel work `presented at Plumbers <https://linuxplumbersconf.org/event/11/contributions/953/>`__,
"managed" neighbor entries have been `upstreamed <https://lore.kernel.org/netdev/20211011121238.25542-1-daniel@iogearbox.net/>`__
and will be available in Linux kernel v5.16 or later which the Cilium agent will detect
and transparently use. In this case, the agent pushes down L3 addresses of new nodes
joining the cluster as externally learned "managed" neighbor entries. For introspection,
iproute2 displays them as "managed extern_learn". The ``extern_learn`` attribute prevents
garbage collection of the entries by the kernel's neighboring subsystem. Such "managed"
neighbor entries are dynamically resolved and periodically refreshed by the Linux kernel
itself in case there is no active traffic for a certain period of time. That is, the
kernel attempts to always keep them in ``REACHABLE`` state. For Linux kernels v5.15 or
earlier where "managed" neighbor entries are not present, the Cilium agent similarly
pushes L3 addresses of new nodes into the kernel for dynamic resolution. For introspection, 
iproute2 displays them only as ``extern_learn`` in this case. If there is no active traffic 
for a certain period of time and entries become state, the Cilium agent triggers the 
Linux kernel-based re-resolution for attempting to keep them in ``REACHABLE`` state.

The Cilium agent actively monitors devices, routes, and neighbors and reconciles the
neighbor entries in the kernel. For example if a device is added new neighbor entries 
for the device are added. When routes change, such as a change to the next-hop, the 
Cilium agent updates the neighbor entries accordingly. And when neighbor entries
are flushed due to for example a carrier-down event, the Cilium agent restores the 
neighbor entries as soon as possible.

The neighbor discovery supports multi-device environments where each node has multiple devices
and multiple next-hops to another node. The Cilium agent pushes neighbor entries for all target
devices, including the direct routing device. Currently, it supports one next-hop per device.
The following example illustrates how the neighbor discovery works in a multi-device environment.
Each node has two devices connected to different L3 networks (10.69.0.64/26 and 10.69.0.128/26),
and global scope addresses each (10.69.0.1/26 and 10.69.0.2/26). A next-hop from node1 to node2 is
either ``10.69.0.66 dev eno1`` or ``10.69.0.130 dev eno2``. The Cilium agent pushes neighbor
entries for both ``10.69.0.66 dev eno1`` and ``10.69.0.130 dev eno2`` in this case.

::

    +---------------+     +---------------+
    |    node1      |     |    node2      |
    | 10.69.0.1/26  |     | 10.69.0.2/26  |
    |           eno1+-----+eno1           |
    |           |   |     |   |           |
    | 10.69.0.65/26 |     |10.69.0.66/26  |
    |               |     |               |
    |           eno2+-----+eno2           |
    |           |   |     | |             |
    | 10.69.0.129/26|     | 10.69.0.130/26|
    +---------------+     +---------------+

With, on node1:

.. code-block:: shell-session

    $ ip route show
    10.69.0.2
            nexthop via 10.69.0.66 dev eno1 weight 1
            nexthop via 10.69.0.130 dev eno2 weight 1

    $ ip neigh show
    10.69.0.66 dev eno1 lladdr 96:eb:75:fd:89:fd extern_learn  REACHABLE
    10.69.0.130 dev eno2 lladdr 52:54:00:a6:62:56 extern_learn  REACHABLE

.. _external_access_to_clusterip_services:

External Access To ClusterIP Services
*************************************

As per `k8s Service <https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types>`__,
Cilium's eBPF kube-proxy replacement by default disallows access to a ClusterIP service from outside the cluster.
This can be allowed by setting ``bpf.lbExternalClusterIP=true``.

Kubernetes API server high availability
***************************************

If you are running multiple instances of Kubernetes API servers in your cluster, you can set the ``k8s-api-server-urls`` flag
so that Cilium can fail over to an active instance. Cilium switches to the ``kubernetes`` service address so that
API requests are load-balanced to API server endpoints during runtime. However, if the initially configured API servers
are rotated while the agent is down, you can update the ``k8s-api-server-urls`` flag with the updated API servers.

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set kubeProxyReplacement=true \\
        --set k8s.apiServerURLs="https://172.21.0.4:6443 https://172.21.0.5:6443 https://172.21.0.6:6443"

Observability
*************

You can trace socket LB related datapath events using Hubble and cilium monitor.

Apply the following pod and service:

.. code-block:: yaml

    apiVersion: v1
    kind: Pod
    metadata:
      name: nginx
      labels:
        app: proxy
    spec:
      containers:
      - name: nginx
        image: nginx:stable
        ports:
          - containerPort: 80
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: nginx-service
    spec:
      selector:
        app: proxy
      ports:
      - port: 80

Deploy a client pod to start traffic.

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-sw-app.yaml

.. code-block:: shell-session

    $ kubectl get svc | grep nginx
      nginx-service   ClusterIP   10.96.128.44   <none>        80/TCP    140m

    $ kubectl exec -it mediabot -- curl -v --connect-timeout 5 10.96.128.44

Follow the Hubble :ref:`hubble_cli` guide  to see the network flows. The Hubble
output prints datapath events before and after socket LB translation between service
and selected service endpoint.

.. code-block:: shell-session

    $ hubble observe --all | grep mediabot
    Jan 13 13:47:20.932: default/mediabot (ID:5618) <> default/nginx-service:80 (world) pre-xlate-fwd TRACED (TCP)
    Jan 13 13:47:20.932: default/mediabot (ID:5618) <> default/nginx:80 (ID:35772) post-xlate-fwd TRANSLATED (TCP)
    Jan 13 13:47:20.932: default/nginx:80 (ID:35772) <> default/mediabot (ID:5618) pre-xlate-rev TRACED (TCP)
    Jan 13 13:47:20.932: default/nginx-service:80 (world) <> default/mediabot (ID:5618) post-xlate-rev TRANSLATED (TCP)
    Jan 13 13:47:20.932: default/mediabot:38750 (ID:5618) <> default/nginx (ID:35772) pre-xlate-rev TRACED (TCP)

Socket LB tracing with Hubble requires cilium agent to detect pod cgroup paths.
If you see a message in cilium agent ``Failed to setup socket load-balancing tracing with Hubble.``,
you can trace packets using ``cilium-dbg monitor`` instead.

.. note::

    If you observe the message about socket load-balancing setup failure in the logs,
    please file a GitHub issue with the cgroup path for any of your pods,
    obtained by running the following command on a Kubernetes node in your
    cluster: ``sudo crictl inspectp -o=json $POD_ID | grep cgroup``.

.. code-block:: shell-session

    $ kubectl get pods -o wide
    NAME       READY   STATUS    RESTARTS   AGE     IP             NODE          NOMINATED NODE   READINESS GATES
    mediabot   1/1     Running   0          54m     10.244.1.237   kind-worker   <none>           <none>
    nginx      1/1     Running   0          3h25m   10.244.1.246   kind-worker   <none>           <none>

    $ kubectl exec -n kube-system cilium-rt2jh -- cilium-dbg monitor -v -t trace-sock
    CPU 11: [pre-xlate-fwd] cgroup_id: 479586 sock_cookie: 7123674, dst [10.96.128.44]:80 tcp
    CPU 11: [post-xlate-fwd] cgroup_id: 479586 sock_cookie: 7123674, dst [10.244.1.246]:80 tcp
    CPU 11: [pre-xlate-rev] cgroup_id: 479586 sock_cookie: 7123674, dst [10.244.1.246]:80 tcp
    CPU 11: [post-xlate-rev] cgroup_id: 479586 sock_cookie: 7123674, dst [10.96.128.44]:80 tcp

You can identify the client pod using its printed ``cgroup id`` metadata. The pod
``cgroup path`` corresponding to the ``cgroup id`` has its UUID. The socket
cookie is a unique socket identifier allocated in the Linux kernel. The socket
cookie metadata can be used to identify all the trace events from a socket.

.. code-block:: shell-session

    $ kubectl get pods -o custom-columns=PodName:.metadata.name,PodUID:.metadata.uid
    PodName    PodUID
    mediabot   b620703c-c446-49c7-84c8-e23f4ba5626b
    nginx      73b9938b-7e4b-4cbd-8c4c-67d4f253ccf4

    $ kubectl exec -n kube-system cilium-rt2jh -- find /run/cilium/cgroupv2/ -inum 479586
    Defaulted container "cilium-agent" out of: cilium-agent, mount-cgroup (init), apply-sysctl-overwrites (init), clean-cilium-state (init)
    /run/cilium/cgroupv2/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-podb620703c_c446_49c7_84c8_e23f4ba5626b.slice/cri-containerd-4e7fc71c8bef8c05c9fb76d93a186736fca266e668722e1239fe64503b3e80d3.scope

Troubleshooting
***************

Validate BPF cgroup programs attachment
=======================================

Cilium attaches BPF ``cgroup`` programs to enable socket-based load-balancing (aka
``host-reachable`` services). If you see connectivity issues for ``clusterIP`` services,
check if the programs are attached to the host ``cgroup root``. The default ``cgroup``
root is set to ``/run/cilium/cgroupv2``.
Run the following commands from a Cilium agent pod as well as the underlying
kubernetes node where the pod is running. If the container runtime in your cluster
is running in the cgroup namespace mode, Cilium agent pod can attach BPF ``cgroup``
programs to the ``virtualized cgroup root``. In such cases, Cilium kube-proxy replacement
based load-balancing may not be effective leading to connectivity issues.
For more information, ensure that you have the fix `Pull Request <https://github.com/cilium/cilium/pull/16259>`__.

.. code-block:: shell-session

    $ mount | grep cgroup2
    none on /run/cilium/cgroupv2 type cgroup2 (rw,relatime)

    $ bpftool cgroup tree /run/cilium/cgroupv2/
    CgroupPath
    ID       AttachType      AttachFlags     Name
    /run/cilium/cgroupv2
    10613    device          multi
    48497    connect4
    48493    connect6
    48499    sendmsg4
    48495    sendmsg6
    48500    recvmsg4
    48496    recvmsg6
    48498    getpeername4
    48494    getpeername6

Known Issues
############

For clusters deployed with Cilium version 1.11.14 or earlier, service backend entries could
be leaked in the BPF maps in some instances. The known cases that could lead
to such leaks are due to race conditions between deletion of a service backend
while it's terminating, and simultaneous deletion of the service the backend is
associated with. This could lead to duplicate backend entries that could eventually
fill up the ``cilium_lb4_backends_v2`` map.
In such cases, you might see error messages like these in the Cilium agent logs::

    Unable to update element for cilium_lb4_backends_v2 map with file descriptor 15: the map is full, please consider resizing it. argument list too long

While the leak was fixed in Cilium version 1.11.15, in some cases, any affected clusters upgrading
from the problematic cilium versions 1.11.14 or earlier to any subsequent versions may not
see the leaked backends cleaned up from the BPF maps after the Cilium agent restarts.
The fixes to clean up leaked duplicate backend entries were backported to older
releases, and are available as part of Cilium versions v1.11.16, v1.12.9 and v1.13.2.
Fresh clusters deploying Cilium versions 1.11.15 or later don't experience this leak issue.

For more information, see `this GitHub issue <https://github.com/cilium/cilium/issues/23551>`__.

Limitations
###########

    * Cilium's eBPF kube-proxy replacement relies upon the socket-LB feature
      which uses eBPF cgroup hooks to implement the service translation. Using it with libceph
      deployments currently requires support for the getpeername(2) hook address translation in
      eBPF.
    * NFS and SMB mounts may break when mounted to a ``Service`` cluster IP while using socket-LB.
      This issue is known to impact Longhorn, Portworx, and Robin, but may impact other storage
      systems that implement ``ReadWriteMany`` volumes using this pattern. To avoid this problem,
      ensure that the following commits are part of your underlying kernel:

      * ``0bdf399342c5 ("net: Avoid address overwrite in kernel_connect")``
      * ``86a7e0b69bd5 ("net: prevent rewrite of msg_name in sock_sendmsg()")``
      * ``01b2885d9415 ("net: Save and restore msg_namelen in sock_sendmsg")``
      * ``cedc019b9f26 ("smb: use kernel_connect() and kernel_bind()")`` (SMB only)

      These patches have been backported to all stable kernels and some distro-specific kernels:

      * **Ubuntu**: ``5.4.0-187-generic``, ``5.15.0-113-generic``, ``6.5.0-41-generic`` or newer.
      * **RHEL 8**: ``4.18.0-553.8.1.el8_10.x86_64`` or newer (RHEL 8.10+).
      * **RHEL 9**: ``kernel-5.14.0-427.31.1.el9_4`` or newer (RHEL 9.4+).

      For a more detailed discussion see :gh-issue:`21541`.
    * Cilium's DSR NodePort mode currently does not operate well in environments with
      TCP Fast Open (TFO) enabled. It is recommended to switch to ``snat`` mode in this
      situation.
    * Cilium's eBPF kube-proxy replacement does not support the SCTP transport protocol except
      in a few basic cases. For more information, see :ref:`sctp`. Only TCP and UDP are fully 
      supported as a transport for services at this time.
    * Cilium's eBPF kube-proxy replacement does not allow ``hostPort`` port configurations
      for Pods that overlap with the configured NodePort range. In such case, the ``hostPort``
      setting will be ignored and a warning emitted to the Cilium agent log. Similarly,
      explicitly binding the ``hostIP`` to the loopback address in the host namespace is
      currently not supported and will log a warning to the Cilium agent log.
    * The neighbor discovery in a multi-device environment doesn't work with the runtime device
      detection which means that the target devices for the neighbor discovery doesn't follow the
      device changes.
    * When socket-LB feature is enabled, pods sending (connected) UDP traffic to services
      can continue to send traffic to a service backend even after it's deleted. Cilium agent
      handles such scenarios by forcefully terminating application sockets that are connected
      to deleted backends, so that the applications can be load-balanced to active backends.
      This functionality requires these kernel configs to be enabled:
      ``CONFIG_INET_DIAG``, ``CONFIG_INET_UDP_DIAG`` and ``CONFIG_INET_DIAG_DESTROY``.
    * Cilium's BPF-based masquerading is recommended over iptables when using the
      BPF-based NodePort. Otherwise, there is a risk for port collisions between
      BPF and iptables SNAT, which might result in dropped NodePort
      connections :gh-issue:`23604`.

Further Readings
################

The following presentations describe inner-workings of the kube-proxy replacement in eBPF
in great details:

    * "Liberating Kubernetes from kube-proxy and iptables" (KubeCon North America 2019, `slides
      <https://docs.google.com/presentation/d/1cZJ-pcwB9WG88wzhDm2jxQY4Sh8adYg0-N3qWQ8593I/edit>`__,
      `video <https://www.youtube.com/watch?v=bIRwSIwNHC0>`__)
    * "Kubernetes service load-balancing at scale with BPF & XDP" (Linux Plumbers 2020, `slides
      <https://linuxplumbersconf.org/event/7/contributions/674/attachments/568/1002/plumbers_2020_cilium_load_balancer.pdf>`__,
      `video <https://www.youtube.com/watch?v=UkvxPyIJAko&t=21s>`__)
    * "eBPF as a revolutionary technology for the container landscape" (Fosdem 2020, `slides
      <https://docs.google.com/presentation/d/1VOUcoIxgM_c6M_zAV1dLlRCjyYCMdR3tJv6CEdfLMh8/edit>`__,
      `video <https://fosdem.org/2020/schedule/event/containers_bpf/>`__)
    * "Kernel improvements for Cilium socket LB" (LSF/MM/BPF 2020, `slides
      <https://docs.google.com/presentation/d/1w2zlpGWV7JUhHYd37El_AUZzyUNSvDfktrF5MJ5G8Bs/edit#slide=id.g746fc02b5b_2_0>`__)
