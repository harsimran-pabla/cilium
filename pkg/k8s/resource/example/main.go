// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"

	"github.com/cilium/hive/cell"
	"github.com/cilium/workerpool"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// PrintServices for the pkg/k8s/resource which observers pods and services and once a second prints the list of
// services with the pods associated with each service.
//
// Run with:
//
//  go run . --k8s-kubeconfig-path ~/.kube/config
//
// To test, try running:
//
//  kubectl run -it --rm --image=nginx  --port=80 --expose nginx

var (
	// slogloggercheck: it's just an example, so we can use the default logger
	log = logging.DefaultSlogLogger.With(logfields.LogSubsys, "example")
)

func main() {
	hive := hive.New(
		client.Cell,
		resourcesCell,
		printServicesCell,

		cell.Invoke(func(*PrintServices) {}),
	)
	hive.RegisterFlags(pflag.CommandLine)
	pflag.Parse()
	hive.Run(slog.Default())
}

var resourcesCell = cell.Module(
	"resources",
	"Kubernetes Pod and Service resources",

	cell.Provide(
		func(lc cell.Lifecycle, c client.Clientset) resource.Resource[*corev1.Pod] {
			if !c.IsEnabled() {
				return nil
			}
			lw := utils.ListerWatcherFromTyped[*corev1.PodList](c.CoreV1().Pods(""))
			return resource.New[*corev1.Pod](lc, lw, resource.WithMetric("Pod"))
		},
		func(lc cell.Lifecycle, c client.Clientset) resource.Resource[*corev1.Service] {
			if !c.IsEnabled() {
				return nil
			}
			lw := utils.ListerWatcherFromTyped[*corev1.ServiceList](c.CoreV1().Services(""))
			return resource.New[*corev1.Service](lc, lw, resource.WithMetric("Service"))
		},
	),
)

var printServicesCell = cell.Module(
	"print-services",
	"Prints Kubernetes Services",

	cell.Provide(newPrintServices),
)

type PrintServices struct {
	wp *workerpool.WorkerPool

	pods     resource.Resource[*corev1.Pod]
	services resource.Resource[*corev1.Service]
}

type printServicesParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Pods      resource.Resource[*corev1.Pod]
	Services  resource.Resource[*corev1.Service]
}

func newPrintServices(p printServicesParams) (*PrintServices, error) {
	if p.Pods == nil || p.Services == nil {
		return nil, fmt.Errorf("Resources not available. Missing --k8s-kubeconfig-path?")
	}
	ps := &PrintServices{
		pods:     p.Pods,
		services: p.Services,
	}
	p.Lifecycle.Append(ps)
	return ps, nil
}

func (ps *PrintServices) Start(startCtx cell.HookContext) error {
	ps.wp = workerpool.New(1)
	ps.wp.Submit("processLoop", ps.processLoop)

	// Using the start context, do a blocking dump of all
	// services. Using the start context here makes sure that
	// this operation is aborted if it blocks too long.
	ps.printServices(startCtx)

	return nil
}

func (ps *PrintServices) Stop(cell.HookContext) error {
	ps.wp.Close()
	return nil
}

// printServices prints services at start to show how Store() can be used.
func (ps *PrintServices) printServices(ctx context.Context) {

	// Retrieve a handle to the store. Blocks until the store has synced.
	// Can fail if the context is cancelled (e.g. PrintServices is being stopped).
	store, err := ps.services.Store(ctx)
	if err != nil {
		log.Error("Failed to retrieve store, aborting", logfields.Error, err)
		return
	}

	log.Info("Services:")
	for _, svc := range store.List() {
		labels := labels.Map2Labels(svc.Spec.Selector, labels.LabelSourceK8s)
		log.Info(fmt.Sprintf("  - %s/%s\ttype=%s\tselector=%s", svc.Namespace, svc.Name, svc.Spec.Type, labels))
	}

}

// processLoop observes changes to pods and services and periodically prints the
// services and the pods that each service selects.
func (ps *PrintServices) processLoop(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// Subscribe to pods and services.
	pods := ps.pods.Events(ctx)
	services := ps.services.Events(ctx)

	// State:
	podLabels := make(map[resource.Key]labels.Labels)
	serviceSelectors := make(map[resource.Key]labels.Labels)

	// Process the pod and service events and periodically print the services.
	// Loop until the pods and services have completed. We need to process
	// both streams to the end to make sure we're not blocking the resource even
	// if we're stopping (e.g. context cancelled).
	for pods != nil || services != nil {
		select {
		case <-ticker.C:
			for key, selectors := range serviceSelectors {
				log.Info(fmt.Sprintf("%s (%s)", key, selectors))
				for podName, lbls := range podLabels {
					match := true
					for _, sel := range selectors {
						match = match && lbls.Has(sel)
					}
					if match {
						log.Info(fmt.Sprintf("  - %s", podName))
					}
				}
			}
			log.Info("----------------------------------------------------------")

		case ev, ok := <-pods:
			if !ok {
				pods = nil
				continue
			}

			switch ev.Kind {
			case resource.Sync:
				// Pods have now been synced and the set of Upsert events
				// received thus far forms a coherent snapshot of the pods
				// at a specific point in time. This is usually used in the context
				// of garbage collection at startup: we now know what is the set of pods that
				// existed at the api-server brief moment ago and can remove persisted
				// data of pods that are not part of this set.
			case resource.Upsert:
				log.Info("Pod updated", logfields.Pod, ev.Key)
				podLabels[ev.Key] = labels.Map2Labels(ev.Object.Labels, labels.LabelSourceK8s)
			case resource.Delete:
				log.Info("Pod deleted", logfields.Pod, ev.Key)
				delete(podLabels, ev.Key)
			}

			// Always mark the event as processed. This tells the resource that more
			// events can be now emitted for this key and if error is nil it clears
			// any rate limiting state related to failed attempts.
			ev.Done(nil)

		case ev, ok := <-services:
			if !ok {
				services = nil
				continue
			}

			// Simulate a fault 10% of the time. This will cause this event to be retried
			// later.
			if rand.IntN(10) == 1 {
				log.Info("Injecting a fault!")
				ev.Done(errors.New("injected fault"))
				continue
			}

			switch ev.Kind {
			case resource.Sync:
				log.Info("Services synced")
			case resource.Upsert:
				log.Info("Service updated", logfields.Service, ev.Key)
				if len(ev.Object.Spec.Selector) > 0 {
					serviceSelectors[ev.Key] = labels.Map2Labels(ev.Object.Spec.Selector, labels.LabelSourceK8s)
				}
			case resource.Delete:
				log.Info("Service deleted", logfields.Service, ev.Key)
				delete(serviceSelectors, ev.Key)
			}
			ev.Done(nil)
		}
	}

	return nil
}
