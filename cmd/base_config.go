package cmd

import (
	"context"
	"gosolo/config"
	"gosolo/module"
	"gosolo/module/updatable_configs"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

type Metrics struct {
}

// NodeConfig 除了基础配置之外，还包含基础设施的实例：数据库、网络通信、日志，性能观测、性能测量、事件分发器等等
type NodeConfig struct {
	Cancel context.CancelFunc // cancel function for the context that is passed to the networking layer
	config config.BaseConfig

	// 基础设施的实例
	ConfigManager     *updatable_configs.Manager
	Logger            zerolog.Logger
	Tracer            module.Tracer
	MetricsRegisterer prometheus.Registerer
	Metrics           Metrics
	// 依赖组件，在启动节点的组件运行之前先要运行的组件
	PeerManagerDependencies *DependencyList
}
