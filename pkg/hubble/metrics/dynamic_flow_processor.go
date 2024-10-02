// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"errors"
	"reflect"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	// "github.com/cilium/cilium/pkg/hubble/metrics"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/lock"
)

// DynamicHandler represents instance of hubble exporter with dynamic
// configuration reload.
type DynamicHandler struct {
	logger  logrus.FieldLogger
	watcher *metricConfigWatcher
	// mutex protects from concurrent modification of handlers by config
	// reloader when hubble events are processed
	mutex          lock.RWMutex
	MetricHandlers []api.NamedHandler // TODO add getnames for testing encapsulation?
	registry       *prometheus.Registry
}

// OnDecodedEvent distributes events across all managed exporters.
func (d *DynamicHandler) OnDecodedFlow(ctx context.Context, flow *flowpb.Flow) (bool, error) {
	select {
	case <-ctx.Done():
		return false, nil
	default:
	}

	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var errs error
	for _, h := range d.MetricHandlers {
		if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
			continue
		}
		errs = errors.Join(errs, h.Handler.ProcessFlow(ctx, flow))
	}

	if errs != nil {
		d.logger.WithError(errs).Error("Failed to ProcessFlow in metrics handler")
	}
	return false, errs
}

// NewDynamicHandler creates instance of dynamic hubble flow exporter.
func NewDynamicHandler(reg *prometheus.Registry, logger logrus.FieldLogger, configFilePath string) *DynamicHandler {
	DynamicHandler := &DynamicHandler{
		logger:   logger,
		registry: reg,
	}
	watcher := NewMetricConfigWatcher(configFilePath, DynamicHandler.onConfigReload)
	DynamicHandler.watcher = watcher
	return DynamicHandler
}

func (d *DynamicHandler) onConfigReload(ctx context.Context, isSameHash bool, hash uint64, config api.Config) {
	if isSameHash {
		return
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	var newHandlers api.Handlers
	metricNames := config.GetMetricNames()

	curHandlerMap := make(map[string]api.NamedHandler)
	if d.MetricHandlers != nil {
		for _, m := range d.MetricHandlers {
			curHandlerMap[m.Name] = m
		}

		configuredMetricNames := make(map[string]*api.MetricConfig)
		for _, cm := range config.Metrics {
			configuredMetricNames[cm.Name] = cm
		}
		// Unregister handlers not present in the new config.
		// This needs to happen first to properly check for conflicting plugins later during registration.
		for _, m := range d.MetricHandlers {
			if _, ok := configuredMetricNames[m.Name]; !ok {
				h, _ := curHandlerMap[m.Name]
				h.Handler.Deinit(d.registry)
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
					h.Handler.Deinit(d.registry)
				}
				d.applyNewConfig(d.registry, cm, metricNames, &newHandlers)
			}
		} else {
			// New handler found in config.
			d.applyNewConfig(d.registry, cm, metricNames, &newHandlers)
		}
	}
	d.MetricHandlers = newHandlers.Handlers
}

func (d *DynamicHandler) applyNewConfig(reg *prometheus.Registry, cm *api.MetricConfig, metricNames map[string]struct{}, newMetrics *api.Handlers) {
	// TODO locks?
	nh, err := api.DefaultRegistry().ValidateAndCreateHandler(reg, cm, &metricNames)
	if err != nil {
		panic(err)
	}

	err = api.InitHandler(d.logger, reg, nh, newMetrics)
	if err != nil {
		panic(err)
	}
	// TODO don't panic, add transaction recovery logic
}
