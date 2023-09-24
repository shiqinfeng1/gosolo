package config

import (
	"gosolo/module/module1"
	"gosolo/module/profiler"
	"os"
	"path/filepath"
	"time"
)

const NotSet = "not set"
const DefaultMaxMsgSize = 1 << (10 * 3) // 1 GiB

// BaseConfig 是节点的公共配置
// 对于作为独立进程运行的节点，配置字段将从命令行参数填充，而对于作为库运行的节点，需要配置字段由调用者初始化。
type BaseConfig struct {
	NodeRole string
	// 全局配置
	config1 string
	config2 string
	config3 uint32

	TracerSensitivity uint
	TracerEnabled     bool
	MetricsPort       uint
	DebugLogLimit     uint32
	Level             string
	BindAddr          string
	MetricsEnabled    bool
	AdminMaxMsgSize   uint
	AdminAddr         string
	AdminCert         string
	AdminKey          string
	AdminClientCAs    string

	// 各模块自定义配置
	ProfilerConfig profiler.ProfilerConfig
	Module1Config  module1.Config

	// 通过yaml配置文件的默认配置（基础设施的配置）
	YamlConfig YamlConfig
}

func DefaultBaseConfig() *BaseConfig {
	homedir, _ := os.UserHomeDir()
	datadir := filepath.Join(homedir, ".gosolo", "database")

	return &BaseConfig{
		config1:           NotSet,
		config2:           datadir,
		config3:           0,
		Level:             "info",
		DebugLogLimit:     2000,
		MetricsPort:       8080,
		TracerSensitivity: 4,
		TracerEnabled:     true,
		BindAddr:          NotSet,
		MetricsEnabled:    true,
		AdminMaxMsgSize:   DefaultMaxMsgSize,
		AdminAddr:         NotSet,
		AdminCert:         NotSet,
		AdminKey:          NotSet,
		AdminClientCAs:    NotSet,

		ProfilerConfig: profiler.ProfilerConfig{
			Enabled:         false,
			UploaderEnabled: false,

			Dir:      "profiler",
			Interval: 15 * time.Minute,
			Duration: 10 * time.Second,
		},

		Module1Config: module1.DefaultConfig(),
	}
}
