package config

import (
	"github.com/spf13/pflag"
)

const (
	configFileFlagName = "config-file"
)
const (
	// All constant strings are used for CLI flag names and corresponding keys for config values.
	// network configuration
	networkingConnectionPruning = "networking-connection-pruning"
	receivedMessageCacheSize    = "received-message-cache-size"
)

func AllFlagNames() []string {
	return []string{
		networkingConnectionPruning,
		receivedMessageCacheSize,
	}
}

// InitializePFlagSet 把yaml配置加载到flagset中。把全部命令行参数都注册到pflagset
// Args:
//
//	*pflag.FlagSet: 命令行参数集合.
//	*YamlConfig: yaml配置，保存在yaml文件中
//
// Note: in subsequent PR's all flag initialization for Flow node should be moved to this func.
func InitializePFlagSet(flags *pflag.FlagSet, baseConfig *BaseConfig, config *YamlConfig) {
	flags.String(configFileFlagName, "", "配置文件的路径")
	flags.Bool(networkingConnectionPruning, config.Infra1Config.NetworkConnectionPruning, "enabling connection trimming")
	flags.Int(receivedMessageCacheSize, config.Infra2Config.ReceivedMessageCacheSize, "enabling connection trimming")

	defaultConfig := DefaultBaseConfig()

	// bind configuration parameters
	flags.StringVar(&baseConfig.config1, "nodeid", defaultConfig.config1, "identity of our node")
	flags.StringVarP(&baseConfig.datadir, "bootstrapdir", "b", defaultConfig.datadir, "path to the bootstrap directory")
	flags.Uint32Var(&baseConfig.config3, "debug-log-limit", defaultConfig.config3, "max number of debug/trace log events per second")
	flags.BoolVar(&baseConfig.ProfilerConfig.Enabled, "profiler-enabled", defaultConfig.ProfilerConfig.Enabled, "whether to enable the auto-profiler")

	flags.StringVar(&baseConfig.AdminAddr, "admin-addr", defaultConfig.AdminAddr, "address to bind on for admin HTTP server")
	flags.StringVar(&baseConfig.AdminCert, "admin-cert", defaultConfig.AdminCert, "admin cert file (for TLS)")
	flags.StringVar(&baseConfig.AdminKey, "admin-key", defaultConfig.AdminKey, "admin key file (for TLS)")
	flags.StringVar(&baseConfig.AdminClientCAs, "admin-client-certs", defaultConfig.AdminClientCAs, "admin client certs (for mutual TLS)")
	flags.UintVar(&baseConfig.AdminMaxMsgSize, "admin-max-response-size", defaultConfig.AdminMaxMsgSize, "admin server max response size in bytes")

}
