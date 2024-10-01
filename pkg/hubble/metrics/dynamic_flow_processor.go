// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"reflect"

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
	logger  logrus.FieldLogger
	watcher *metricConfigWatcher
	// namedFps      map[string]*api.NamedFp
	// namedHandlers map[string]*api.NamedHandler // TODO move config from handler to here and use this type instead
	// mutex protects from concurrent modification of managedFlowProcessors by config
	// reloader when hubble events are processed
	mutex   lock.RWMutex
	Metrics *api.Handlers // TODO add getnames for testing encapsulation?
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
	// TODO move filtering from each handler here
	// if enabledMetrics != nil {
	// 	errs = enabledMetrics.ProcessFlow(ctx, flow)
	// }
	if d.Metrics != nil {
		d.Metrics.ProcessFlow(ctx, flow)
	}

	if errs != nil {
		d.logger.WithError(errs).Error("Failed to ProcessFlow in metrics handler")
	}
	return false, errs
}

// NewDynamicFlowProcessor creates instance of dynamic hubble flow exporter.
func NewDynamicFlowProcessor(logger logrus.FieldLogger, configFilePath string) *DynamicFlowProcessor {
	dynamicFlowProcessor := &DynamicFlowProcessor{
		logger: logger,
		// namedHandlers: make(map[string]*api.NamedHandler),
		// namedFps:      make(map[string]*api.NamedFp),
	}
	watcher := NewMetricConfigWatcher(configFilePath, dynamicFlowProcessor.onConfigReload)
	dynamicFlowProcessor.watcher = watcher
	return dynamicFlowProcessor
}

func (d *DynamicFlowProcessor) onConfigReload(ctx context.Context, isSameHash bool, hash uint64, config api.Config) {
	if isSameHash {
		return
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	// //// START deinit all, TODO only diff
	// if d.Metrics != nil {
	// 	for _, m := range d.Metrics.Handlers {
	// 		m.Handler.Deinit(Registry)
	// 	}
	// }

	// enabledHandlers, err := InitMetricHandlers(Registry, &config)
	// if err != nil {
	// 	// 	return err
	// }
	// d.Metrics = enabledHandlers
	// //// END deinit all
	// // also ^ breaks conflicting plugins detection.. need to do one by one as below :()

	//////
	var newHandlers api.Handlers
	metricNames := config.GetMetricNames()

	curHandlerMap := make(map[string]api.NamedHandler)
	if d.Metrics != nil {
		for _, m := range d.Metrics.Handlers {
			curHandlerMap[m.Name] = m
		}

		configuredMetricNames := make(map[string]*api.MetricConfig)
		for _, cm := range config.Metrics {
			configuredMetricNames[cm.Name] = cm
		}
		// Unregister handlers not present in the new config.
		// This needs to happen first to properly check for conflicting plugins later during registration.
		for _, m := range d.Metrics.Handlers {
			if _, ok := configuredMetricNames[m.Name]; !ok {
				h, _ := curHandlerMap[m.Name]
				h.Handler.Deinit(Registry)
				delete(curHandlerMap, m.Name)
			}
		}
	}

	for _, v := range curHandlerMap {
		newHandlers.Handlers = append(newHandlers.Handlers, v)
	}

	for _, cm := range config.Metrics {
		// Existing handler matches new config entry:
		//   no-op, if config unchanged;
		//   deregister and re-register, if config changed.
		if m, ok := curHandlerMap[cm.Name]; ok {
			if reflect.DeepEqual(*m.MetricConfig, *cm) {
				continue
			} else {
				if h, ok := curHandlerMap[cm.Name]; ok {
					h.Handler.Deinit(Registry)
				}
				d.applyNewConfig(cm, metricNames, &newHandlers)
			}
		} else {
			// New handler found in config.
			d.applyNewConfig(cm, metricNames, &newHandlers)
		}
	}
	d.Metrics = &newHandlers
}

func (d *DynamicFlowProcessor) applyNewConfig(cm *api.MetricConfig, metricNames map[string]struct{}, newMetrics *api.Handlers) {
	// TODO locks?
	nh, err := api.DefaultRegistry().ConfigureHandler(Registry, cm, &metricNames)
	if err != nil {
		panic(err)
	}
	// TODO later remove Metrics and refactor helper funcs
	err = api.NewHandler(d.logger, Registry, nh, newMetrics)
	if err != nil {
		panic(err)
	}
}
