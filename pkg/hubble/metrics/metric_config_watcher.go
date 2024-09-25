// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var metricReloadInterval = 5 * time.Second

type metricConfigWatcher struct {
	logger         logrus.FieldLogger
	configFilePath string
	callback       func(ctx context.Context, hash uint64, config api.Config)
	ticker         *time.Ticker
	stop           chan bool
}

// NewmetricConfigWatcher creates a config watcher instance. Config watcher notifies
// TODO dynamic exporter when config file changes and dynamic metric config should be
// reconciled.
func NewMetricConfigWatcher(
	configFilePath string,
	callback func(ctx context.Context, hash uint64, config api.Config),
) *metricConfigWatcher {
	watcher := &metricConfigWatcher{
		logger:         logrus.New().WithField(logfields.LogSubsys, "hubble").WithField("configFilePath", configFilePath),
		configFilePath: configFilePath,
		callback:       callback,
	}

	// initial configuration load
	watcher.reload()

	// TODO replace ticker reloads with inotify watchers
	watcher.ticker = time.NewTicker(metricReloadInterval)
	watcher.stop = make(chan bool)

	go func() {
		for {
			select {
			case <-watcher.stop:
				return
			case <-watcher.ticker.C:
				watcher.reload()
			}
		}
	}()

	return watcher
}

func (c *metricConfigWatcher) reload() {
	c.logger.Debug("Attempting reload")
	config, hash, err := c.readConfig()
	if err != nil {
		// DynamicExporterReconfigurations.WithLabelValues("failure").Inc()
		c.logger.Warnf("failed reading dynamic exporter config")
	} else {
		c.callback(context.TODO(), hash, *config)
	}
}

// Stop stops watcher.
func (c *metricConfigWatcher) Stop() {
	if c.ticker != nil {
		c.ticker.Stop()
	}
	c.stop <- true
}

func (c *metricConfigWatcher) readConfig() (*api.Config, uint64, error) {
	config := &api.Config{}
	yamlFile, err := os.ReadFile(c.configFilePath)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot read file '%s': %w", c.configFilePath, err)
	}
	if err := yaml.Unmarshal(yamlFile, config); err != nil {
		return nil, 0, fmt.Errorf("cannot parse yaml: %w", err)
	}

	if err := validateMetricConfig(config); err != nil {
		return nil, 0, fmt.Errorf("invalid yaml config file: %w", err)
	}

	return config, calculateMetricHash(yamlFile), nil
}

func calculateMetricHash(file []byte) uint64 {
	sum := md5.Sum(file)
	return binary.LittleEndian.Uint64(sum[0:16])
}

func validateMetricConfig(config *api.Config) error {
	// flowlogNames := make(map[string]interface{})
	// flowlogPaths := make(map[string]interface{})

	// var errs error

	// for i := range config.FlowLogs {
	// 	if config.FlowLogs[i] == nil {
	// 		errs = errors.Join(errs, fmt.Errorf("invalid flowlog at index %d", i))
	// 		continue
	// 	}
	// 	name := config.FlowLogs[i].Name
	// 	if name == "" {
	// 		errs = errors.Join(errs, fmt.Errorf("name is required"))
	// 	} else {
	// 		if _, ok := flowlogNames[name]; ok {
	// 			errs = errors.Join(errs, fmt.Errorf("duplicated flowlog name %s", name))
	// 		}
	// 		flowlogNames[name] = struct{}{}
	// 	}

	// 	filePath := config.FlowLogs[i].FilePath
	// 	if filePath == "" {
	// 		errs = errors.Join(errs, fmt.Errorf("filePath is required"))
	// 	} else {
	// 		if _, ok := flowlogPaths[filePath]; ok {
	// 			errs = errors.Join(errs, fmt.Errorf("duplicated flowlog path %s", filePath))
	// 		}
	// 		flowlogPaths[filePath] = struct{}{}
	// 	}
	// }

	// return errs
	return nil
}
