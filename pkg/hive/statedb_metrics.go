// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"strings"
	"time"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type StateDBMetrics struct {
	// How long a read transaction was held.
	WriteTxnDuration metric.Vec[metric.Observer]
	// How long it took to acquire a write transaction for all tables.
	WriteTxnAcquisition metric.Vec[metric.Observer]
	// How long writers were blocked while waiting to acquire a write transaction for a specific table.
	TableContention metric.Vec[metric.Gauge]
	// The amount of objects in a given table.
	TableObjectCount metric.Vec[metric.Gauge]
	// The current revision of a given table.
	TableRevision metric.Vec[metric.Gauge]
	// The amount of delete trackers for a given table.
	TableDeleteTrackerCount metric.Vec[metric.Gauge]
	// The amount of objects in the graveyard for a given table.
	TableGraveyardObjectCount metric.Vec[metric.Gauge]
	// The lowest revision of a given table that has been processed by the graveyard garbage collector.
	TableGraveyardLowWatermark metric.Vec[metric.Gauge]
	// The time it took to clean the graveyard for a given table.
	TableGraveyardCleaningDuration metric.Vec[metric.Observer]
}

const (
	labelTable  = "table"
	labelTables = "tables"
	labelHandle = "handle"
)

type stateDBMetricsImpl struct {
	m StateDBMetrics
}

// DeleteTrackerCount implements statedb.Metrics.
func (i stateDBMetricsImpl) DeleteTrackerCount(tableName string, numTrackers int) {
	if i.m.TableDeleteTrackerCount.IsEnabled() {
		i.m.TableDeleteTrackerCount.WithLabelValues(tableName).Set(float64(numTrackers))
	}
}

// GraveyardCleaningDuration implements statedb.Metrics.
func (i stateDBMetricsImpl) GraveyardCleaningDuration(tableName string, duration time.Duration) {
	if i.m.TableGraveyardCleaningDuration.IsEnabled() {
		i.m.TableGraveyardCleaningDuration.WithLabelValues(tableName).Observe(float64(duration.Seconds()))
	}
}

// GraveyardLowWatermark implements statedb.Metrics.
func (i stateDBMetricsImpl) GraveyardLowWatermark(tableName string, lowWatermark uint64) {
	if i.m.TableGraveyardLowWatermark.IsEnabled() {
		i.m.TableGraveyardLowWatermark.WithLabelValues(tableName).Set(float64(lowWatermark))
	}
}

// GraveyardObjectCount implements statedb.Metrics.
func (i stateDBMetricsImpl) GraveyardObjectCount(tableName string, numDeletedObjects int) {
	if i.m.TableGraveyardObjectCount.IsEnabled() {
		i.m.TableGraveyardObjectCount.WithLabelValues(tableName).Set(float64(numDeletedObjects))
	}
}

// ObjectCount implements statedb.Metrics.
func (i stateDBMetricsImpl) ObjectCount(tableName string, numObjects int) {
	if i.m.TableObjectCount.IsEnabled() {
		i.m.TableObjectCount.WithLabelValues(tableName).Set(float64(numObjects))
	}
}

// Revision implements statedb.Metrics.
func (i stateDBMetricsImpl) Revision(tableName string, revision uint64) {
	if i.m.TableRevision.IsEnabled() {
		i.m.TableRevision.WithLabelValues(tableName).Set(float64(revision))
	}
}

// WriteTxnDuration implements statedb.Metrics.
func (i stateDBMetricsImpl) WriteTxnDuration(handle string, tables []string, acquire time.Duration) {
	if i.m.WriteTxnDuration.IsEnabled() {
		i.m.WriteTxnDuration.WithLabelValues(
			handle, strings.Join(tables, ","),
		).Observe(acquire.Seconds())
	}
}

// WriteTxnTableAcquisition implements statedb.Metrics.
func (i stateDBMetricsImpl) WriteTxnTableAcquisition(handle string, tableName string, acquire time.Duration) {
	if i.m.TableContention.IsEnabled() {
		i.m.TableContention.WithLabelValues(handle, tableName)
	}
}

// WriteTxnTotalAcquisition implements statedb.Metrics.
func (i stateDBMetricsImpl) WriteTxnTotalAcquisition(handle string, tables []string, acquire time.Duration) {
	if i.m.WriteTxnAcquisition.IsEnabled() {
		i.m.WriteTxnAcquisition.WithLabelValues(
			handle, strings.Join(tables, ","),
		)
	}
}

var _ statedb.Metrics = stateDBMetricsImpl{}

func NewStateDBMetrics() StateDBMetrics {
	m := StateDBMetrics{
		WriteTxnDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statedb",
			Name:      "write_txn_duration_seconds",
			Help:      "How long a write transaction was held.",
			Disabled:  true,
		}, []string{labelHandle, labelTables}),
		WriteTxnAcquisition: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statedb",
			Name:      "write_txn_acquisition_seconds",
			Help:      "How long it took to acquire a write transaction for all tables.",
			Disabled:  true,
		}, []string{labelHandle, labelTables}),
		TableContention: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statedb",
			Name:      "table_contention_seconds",
			Help:      "How long writers were blocked while waiting to acquire a write transaction for a specific table.",
			Disabled:  true,
		}, []string{labelHandle, labelTable}),
		TableObjectCount: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statedb",
			Name:      "table_objects",
			Help:      "The amount of objects in a given table.",
			Disabled:  true,
		}, []string{labelTable}),
		TableRevision: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statedb",
			Name:      "table_revision",
			Help:      "The current revision of a given table.",
			Disabled:  true,
		}, []string{labelTable}),
		TableDeleteTrackerCount: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statedb",
			Name:      "table_delete_trackers",
			Help:      "The amount of delete trackers for a given table.",
			Disabled:  true,
		}, []string{labelTable}),
		TableGraveyardObjectCount: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statedb",
			Name:      "table_graveyard_objects",
			Help:      "The amount of objects in the graveyard for a given table.",
			Disabled:  true,
		}, []string{labelTable}),
		TableGraveyardLowWatermark: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statedb",
			Name:      "table_graveyard_low_watermark",
			Help:      "The lowest revision of a given table that has been processed by the graveyard garbage collector.",
			Disabled:  true,
		}, []string{labelTable}),
		TableGraveyardCleaningDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "statedb",
			Name:      "table_graveyard_cleaning_duration_seconds",
			Help:      "The time it took to clean the graveyard for a given table.",
			Disabled:  true,
		}, []string{labelTable}),
	}
	return m
}

func NewStateDBMetricsImpl(m StateDBMetrics) statedb.Metrics {
	return stateDBMetricsImpl{m}
}
