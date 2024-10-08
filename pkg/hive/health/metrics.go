// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"context"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

type Metrics struct {
	HealthStatusGauge         metric.Vec[metric.Gauge]
	DegradedHealthStatusGauge metric.DeletableVec[metric.Gauge]
}

func newMetrics() *Metrics {
	return &Metrics{
		HealthStatusGauge: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: "hive_health_status_levels",
			Namespace:  "cilium",
			Subsystem:  "hive",
			Name:       "status",
			Help:       "Counts of health status levels of Hive components",
		}, []string{"status"}),

		DegradedHealthStatusGauge: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: "cilium",
			Subsystem: "hive",
			Name:      "degraded_status",
			Help:      "Counts degraded health status levels of Hive components labeled by modules",
			Disabled:  true,
		}, []string{"module"}),
	}
}

type publishFunc func(map[types.Level]uint64, map[string]uint64)

type metricPublisherParams struct {
	cell.In

	DB       *statedb.DB
	Table    statedb.Table[types.Status]
	JobGroup job.Group
	Metrics  *Metrics
}

// metricPublisher periodically publishes the hive module health metric
// * cilium_hive_status
// * cilium_hive_degraded_status
func metricPublisher(p metricPublisherParams) {
	// Performs the actual writing to the metric. Extracted to make testing easy.
	publish := func(stats map[types.Level]uint64, degradedModuleCount map[string]uint64) {
		for l, v := range stats {
			p.Metrics.HealthStatusGauge.WithLabelValues(strings.ToLower(string(l))).Set(float64(v))
		}
		for k, v := range degradedModuleCount {
			// If the module is healthy attempt to remove any associated metrics with that module
			if v == 0 {
				p.Metrics.DegradedHealthStatusGauge.DeleteLabelValues(k)
				continue
			}

			p.Metrics.DegradedHealthStatusGauge.WithLabelValues(k).Set(float64(v))
		}
	}

	if p.Metrics.HealthStatusGauge.IsEnabled() {
		p.JobGroup.Add(job.OneShot("module-status-metrics",
			func(ctx context.Context, health cell.Health) error {
				return publishJob(ctx, p, publish)
			}))
	}
}

func publishJob(ctx context.Context, p metricPublisherParams, publish publishFunc) error {
	// Limit rate of updates to the metric. The status table is updated often, the
	// watch channel is closed on every modification (since we're watching all) and
	// traversing the full table is somewhat expensive, so let's limit ourselves.
	limiter := rate.NewLimiter(15*time.Second, 3)
	defer limiter.Stop() // Avoids leaking a goroutine.

	idToStatus := make(map[string]uint64)
	it, watch := p.Table.AllWatch(p.DB.ReadTxn())
	for {
		stats := make(map[types.Level]uint64)
		// Reset health ID status counts
		for k := range idToStatus {
			idToStatus[k] = 0
		}

		for obj := range it {
			stats[obj.Level]++

			_, ok := idToStatus[obj.ID.Module.String()]
			if obj.Level == types.LevelDegraded {
				idToStatus[obj.ID.Module.String()]++
			} else if !ok {
				idToStatus[obj.ID.Module.String()] = 0
			}
		}

		publish(stats, idToStatus)

		// Removed old IDs
		for k, v := range idToStatus {
			if v == 0 {
				delete(idToStatus, k)
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}

		if err := limiter.Wait(ctx); err != nil {
			return err
		}

		it, watch = p.Table.AllWatch(p.DB.ReadTxn())
	}
}
