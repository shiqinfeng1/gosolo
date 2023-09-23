package config

import (
	"gosolo/module/module1"
	"gosolo/module/profiler"
	"os"
	"path/filepath"
	"time"
)

const NotSet = "not set"

// BaseConfig 是节点的公共配置
// 对于作为独立进程运行的节点，配置字段将从命令行参数填充，而对于作为库运行的节点，需要配置字段由调用者初始化。
type BaseConfig struct {
	// 全局配置
	config1         string
	config2         string
	config3         uint32
	MetricsEnabled  bool
	AdminMaxMsgSize uint
	AdminAddr       string
	AdminCert       string
	AdminKey        string
	AdminClientCAs  string

	// 各模块自定义配置
	profilerConfig profiler.ProfilerConfig
	Module1Config  module1.Config

	// 通过yaml配置文件的默认配置（基础设施的配置）
	YamlConfig YamlConfig
}

func DefaultBaseConfig() *BaseConfig {
	homedir, _ := os.UserHomeDir()
	datadir := filepath.Join(homedir, ".flow", "database")

	return &BaseConfig{
		config1: NotSet,
		config2: datadir,
		config3: 0,

		profilerConfig: profiler.ProfilerConfig{
			Enabled:         false,
			UploaderEnabled: false,

			Dir:      "profiler",
			Interval: 15 * time.Minute,
			Duration: 10 * time.Second,
		},

		Module1Config: module1.DefaultConfig(),
	}
}
