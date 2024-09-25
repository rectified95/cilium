// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package drop

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type dropHandler struct {
	drops     *prometheus.CounterVec
	context   *api.ContextOptions
	cfg       *api.MetricConfig
	AllowList filters.FilterFuncs
	DenyList  filters.FilterFuncs
}

func (d *dropHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	d.context = c
	d.cfg = options
	// TODO use global logger
	d.AllowList, err = filters.BuildFilterList(context.Background(), d.cfg.IncludeFilters, filters.DefaultFilters(logrus.New()))
	d.DenyList, err = filters.BuildFilterList(context.Background(), d.cfg.ExcludeFilters, filters.DefaultFilters(logrus.New()))

	contextLabels := d.context.GetLabelNames()
	labels := append(contextLabels, "reason", "protocol")

	d.drops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "drop_total",
		Help:      "Number of drops",
	}, labels)

	registry.MustRegister(d.drops)
	return nil
}

func (d *dropHandler) Status() string {
	return d.context.Status()
}

func (d *dropHandler) Context() *api.ContextOptions {
	return d.context
}

func (d *dropHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{d.drops.MetricVec}
}

func (d *dropHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if flow.GetVerdict() != flowpb.Verdict_DROPPED {
		return nil
	}

	if !filters.Apply(d.AllowList, d.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	contextLabels, err := d.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	labels := append(contextLabels, flow.GetDropReasonDesc().String(), v1.FlowProtocol(flow))

	d.drops.WithLabelValues(labels...).Inc()
	return nil
}
