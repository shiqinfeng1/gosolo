package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
)

// setAliases 设置配置字段的别名，这是为了把命令行参数直接映射为配置字段
// 因为默认配置default-config.yml中，一般按照各个组件/模块来划分，viper读进来之后，字段名称默认就像 infrastructure1.networking-connection-pruning，我们为了命令行参数简洁，只需要给出--networking-connection-pruning就能直接映射到该配置
// 所以做一个viper字段名称的别名设置，把字段名默认的前缀去除掉
func setAliases() {
	m := make(map[string]string)
	// create map of key -> full pathkey
	// ie: "networking-connection-pruning" -> "network-config.networking-connection-pruning"
	for _, key := range conf.AllKeys() {
		s := strings.Split(key, ".")
		// check len of s, we expect all network keys to have a single prefix "network-config"
		// s should always contain only 2 elements
		if len(s) == 2 {
			m[s[1]] = key
		}
	}
	// each flag name should correspond to exactly one key in our config store after it is loaded with the default config
	for _, flagName := range AllFlagNames() {
		fullKey, ok := m[flagName]
		if !ok {
			panic(fmt.Errorf("failed to set network aliases: invalid network configuration missing configuration key flag name %s check config file and cli flags", flagName))
		}
		conf.RegisterAlias(fullKey, flagName)
	}
}

// overrideConfigFile 从 --config-file参数指定的配置文件路径中读取配置，并覆盖默认配置
// Returns:
//
//	error: 如果读取文件发生错误，俺么返回的错误将被视为不可恢复.
//	bool: true 覆盖成功, false 覆盖失败.
func overrideConfigFile(flags *pflag.FlagSet) (bool, error) {
	configFileFlag := flags.Lookup(configFileFlagName)
	if configFileFlag.Changed {
		p := configFileFlag.Value.String()
		dirPath, fileName := splitConfigPath(p)
		// 把指定的配置加载到viper中
		conf.AddConfigPath(dirPath)
		conf.SetConfigName(fileName)
		err := conf.ReadInConfig()
		if err != nil {
			return false, fmt.Errorf("failed to read config file %s: %w", p, err)
		}
		if len(conf.AllKeys()) == 0 {
			return false, fmt.Errorf("failed to read in config file no config values found")
		}
		return true, nil
	}
	return false, nil
}

// splitConfigPath 返回路径和文件名，如果文件名非法，那么将panic
// 合法的:
//   - /path/to/my_config.yaml
//   - /path/to/my-config123.yaml
//   - my-config.yaml (when in the current directory)
//
// 非法的:
//   - /path/to/my.config.yaml (contains multiple dots)
//   - /path/to/my config.yaml (contains spaces)
//   - /path/to/.config.yaml (does not have a file name before the dot)
//
// Args:
//   - path: The file path string to be split into directory and base name.
//
// Returns:
//   - The directory and base name without extension.
//
// Panics:
//   - If the file name does not match the expected pattern.
func splitConfigPath(path string) (string, string) {
	// Regex to match filenames like 'my_config.yaml' or 'my-config.yaml' but not 'my.config.yaml'
	validFileNamePattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$`)

	dir, name := filepath.Split(path)

	// Panic if the file name does not match the expected pattern
	if !validFileNamePattern.MatchString(name) {
		panic(fmt.Errorf("Invalid config file name '%s'. Expected pattern: alphanumeric, hyphens, or underscores followed by a single dot and extension", name))
	}

	// Extracting the base name without extension
	baseName := strings.Split(name, ".")[0]
	return dir, baseName
}

// LogConfig logs configuration keys and values if they were overridden with a config file.
// It also returns a map of keys for which the values were set by a config file.
//
// Parameters:
//   - logger: *zerolog.Event to which the configuration keys and values will be logged.
//   - flags: *pflag.FlagSet containing the set flags.
//
// Returns:
//   - map[string]struct{}: map of keys for which the values were set by a config file.
func LogConfig(logger *zerolog.Event, flags *pflag.FlagSet) map[string]struct{} {
	keysToAvoid := make(map[string]struct{})

	// 用户指定了自定义config-file
	if flags.Lookup(configFileFlagName).Changed {
		for _, key := range conf.AllKeys() { // 遍历viper中已存在的所有配置字段
			logger.Str(key, fmt.Sprint(conf.Get(key))) // 把所有key-value记录到logger上
			parts := strings.Split(key, ".")
			if len(parts) == 2 { // 带嵌套的配置
				keysToAvoid[parts[1]] = struct{}{}
			} else {
				keysToAvoid[key] = struct{}{}
			}
		}
	}

	return keysToAvoid
}
