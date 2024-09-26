// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"

	"github.com/sirupsen/logrus"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	// "github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/lock"
)

// DynamicFlowProcessor represents instance of hubble exporter with dynamic
// configuration reload.
type DynamicFlowProcessor struct {
	// FlowLogExporter
	logger                logrus.FieldLogger
	watcher               *metricConfigWatcher
	managedFlowProcessors map[string]*managedFlowProcessor
	// mutex protects from concurrent modification of managedFlowProcessors by config
	// reloader when hubble events are processed
	mutex lock.RWMutex
}

// OnDecodedEvent distributes events across all managed exporters.
func (d *DynamicFlowProcessor) OnDecodedFlow(ctx context.Context, flow *flowpb.Flow) (bool, error) {
	select {
	case <-ctx.Done():
		// return false, d.Stop()
		return false, nil
	default:
	}

	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var errs error
	if enabledMetrics != nil {
		errs = enabledMetrics.ProcessFlow(ctx, flow)
	}
	// for _, me := range d.managedFlowProcessors {
	// 	_, err := me.exporter.OnDecodedFlow(ctx, event)
	// 	errs = errors.Join(errs, err)
	// }
	if errs != nil {
		d.logger.WithError(errs).Error("Failed to ProcessFlow in metrics handler")
	}
	return false, errs
}

// Stop stops configuration watcher  and all managed flow log exporters.
// func (d *DynamicFlowProcessor) Stop() error {
// 	d.watcher.Stop()

// 	d.mutex.Lock()
// 	defer d.mutex.Unlock()

// 	var errs error
// 	for _, me := range d.managedFlowProcessors {
// 		errs = errors.Join(errs, me.exporter.Stop())
// 	}

// 	return errs
// }

// NewDynamicFlowProcessor creates instance of dynamic hubble flow exporter.
func NewDynamicFlowProcessor(logger logrus.FieldLogger, configFilePath string) *DynamicFlowProcessor {
	dynamicFlowProcessor := &DynamicFlowProcessor{
		logger:                logger,
		managedFlowProcessors: make(map[string]*managedFlowProcessor),
	}

	// registerMetrics(dynamicExporter)

	watcher := NewMetricConfigWatcher(configFilePath, dynamicFlowProcessor.onConfigReload)
	dynamicFlowProcessor.watcher = watcher
	return dynamicFlowProcessor
}

func (d *DynamicFlowProcessor) onConfigReload(ctx context.Context, hash uint64, config api.Config) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// TODO For now always init all metrics.
	e, err := InitMetricHandlers(Registry, &config)
	if err != nil {
		// 	return err
	}
	enabledMetrics = e
	// TODO add error return

	// quick hash comparison to avoid all processing below, even if without stats

	// configuredFlowLogNames := make(map[string]interface{})
	// for _, flowlog := range config.FlowLogs {
	// 	configuredFlowLogNames[flowlog.Name] = struct{}{}
	// 	if _, ok := d.managedFlowProcessors[flowlog.Name]; ok {
	// 		if d.applyUpdatedConfig(ctx, flowlog) {
	// 			// 	DynamicFlowProcessorReconfigurations.WithLabelValues("update").Inc()
	// 		}
	// 	} else {
	// 		d.applyNewConfig(ctx, flowlog)
	// 		// DynamicFlowProcessorReconfigurations.WithLabelValues("add").Inc()
	// 	}
	// }

	// for flowLogName := range d.managedFlowProcessors {
	// 	if _, ok := configuredFlowLogNames[flowLogName]; !ok {
	// 		d.applyRemovedConfig(flowLogName)
	// 		// DynamicFlowProcessorReconfigurations.WithLabelValues("remove").Inc()
	// 	}
	// }

	// d.updateLastAppliedConfigGauges(hash)
}

func (d *DynamicFlowProcessor) applyNewConfig(ctx context.Context, flowlog *api.MetricConfig) {
	// exporterOpts := []exporteroption.Option{
	// 	exporteroption.WithPath(flowlog.FilePath),
	// 	exporteroption.WithAllowList(d.logger, flowlog.IncludeFilters),
	// 	exporteroption.WithDenyList(d.logger, flowlog.ExcludeFilters),
	// 	exporteroption.WithFieldMask(flowlog.FieldMask),
	// }

	// exporter, err := NewExporter(ctx, d.logger.WithField("flowLogName", flowlog.Name), exporterOpts...)
	// if err != nil {
	// 	d.logger.Errorf("Failed to apply flowlog for name %s: %v", flowlog.Name, err)
	// }

	// d.managedFlowProcessors[flowlog.Name] = &managedFlowProcessor{
	// 	config:   flowlog,
	// 	exporter: exporter,
	// }

}

func (d *DynamicFlowProcessor) applyUpdatedConfig(ctx context.Context, flowlog *api.MetricConfig) bool {
	// m, ok := d.managedFlowProcessors[flowlog.Name]
	// if ok && m.config.equals(flowlog) {
	// 	return false
	// }
	// d.applyRemovedConfig(flowlog.Name)
	// d.applyNewConfig(ctx, flowlog)
	return true
}

func (d *DynamicFlowProcessor) applyRemovedConfig(name string) {
	// m, ok := d.managedFlowProcessors[name]
	// if !ok {
	// 	return
	// }
	// if err := m.exporter.Stop(); err != nil {
	// 	d.logger.Errorf("failed to stop exporter: %w", err)
	// }
	// delete(d.managedFlowProcessors, name)
}

func (d *DynamicFlowProcessor) updateLastAppliedConfigGauges(hash uint64) {
	// DynamicFlowProcessorConfigHash.WithLabelValues().Set(float64(hash))
	// DynamicFlowProcessorConfigLastApplied.WithLabelValues().SetToCurrentTime()
}

type managedFlowProcessor struct {
	config *api.MetricConfig
	fp     api.FlowProcessor
}
