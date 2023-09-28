package config

import (
	"bytes"
	"gosolo/infrastructure1"
	"gosolo/infrastructure2"

	_ "embed"
	"errors"
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	conf     = viper.New()
	validate *validator.Validate
	// 嵌入了默认配置文件，configFile的值就是yamlw文件的内容
	//go:embed default-config.yml
	configFile string

	errPflagsNotParsed = errors.New("failed to bind flags to configuration values, pflags must be parsed before binding")
)

func init() {
	initialize()
}

// 和yaml文件对应的结构体
type YamlConfig struct {
	// ConfigFile used to set a path to a config.yml file used to override the default-config.yml file.
	ConfigFile   string                  `validate:"filepath" mapstructure:"config-file"` //mapstructure 指定映射的字段名称
	Infra1Config *infrastructure1.Config `mapstructure:"infrastructure1-config"`
	Infra2Config *infrastructure2.Config `mapstructure:"infrastructure2-config"`
}

// Validate checks validity of the Flow config. Errors indicate that either the configuration is broken,
// incompatible with the node's internal state, or that the node's internal state is corrupted. In all
// cases, continuation is impossible.
func (fc *YamlConfig) Validate() error {
	err := validate.Struct(fc)
	if err != nil {
		if validationErrors, ok := err.(validator.ValidationErrors); ok {
			return fmt.Errorf("failed to validate flow configuration: %w", validationErrors)
		}
		return fmt.Errorf("unexpeceted error encountered while validating flow configuration: %w", err)
	}
	return nil
}

// DefaultYamlConfig initializes the flow configuration. All default values for the Flow
// configuration are stored in the default-config.yml file. These values can be overridden
// by node operators by setting the corresponding cli flag. DefaultYamlConfig should be called
// before any pflags are parsed, this will allow the configuration to initialize with defaults
// from default-config.yml.
// Returns:
//
//	*YamlConfig: an instance of the network configuration fully initialized to the default values set in the config file
//	error: if there is any error encountered while initializing the configuration, all errors are considered irrecoverable.
func DefaultYamlConfig() (*YamlConfig, error) {
	var yamlConfig YamlConfig
	err := Unmarshall(&yamlConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall the Flow config: %w", err)
	}
	return &yamlConfig, nil
}

// BindPFlags 绑定配置文件和命令行参数，该函数在阐述被解析后执行 ，如果指定了--config-file 那么配置文件从指定的文件加载，再和命令行参数合并
func BindPFlags(c *YamlConfig, flags *pflag.FlagSet) (bool, error) {
	if !flags.Parsed() {
		return false, errPflagsNotParsed
	}

	// 如果指定了 --config-file 标志，那么加到配置文建到viper
	overridden, err := overrideConfigFile(flags)
	if err != nil {
		return false, err
	}
	// 没有指定--config-file
	if !overridden {
		// 把flags 加载到viper中
		err = conf.BindPFlags(flags)
		if err != nil {
			return false, fmt.Errorf("failed to bind pflag set: %w", err)
		}
		// 更新参数字段的别名(去掉嵌套参数的前缀)
		setAliases()
	}
	// 把viper重新解析到yamlCOnfig结构体
	err = Unmarshall(c)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshall the Flow config: %w", err)
	}

	return overridden, nil
}

// Unmarshall 把viper中的配置映射到结构体中
func Unmarshall(yamlConfig *YamlConfig) error {
	err := conf.Unmarshal(yamlConfig, func(decoderConfig *mapstructure.DecoderConfig) {
		// enforce all fields are set on the YamlConfig struct
		decoderConfig.ErrorUnset = true
		// currently the entire flow configuration has not been moved to this package
		// for now we allow key's in the config which are unused.
		decoderConfig.ErrorUnused = false
	})
	if err != nil {
		return fmt.Errorf("failed to unmarshal network config: %w", err)
	}
	return nil
}

// 加载默认配置
func initialize() {
	// 读入数据到缓存
	buf := bytes.NewBufferString(configFile)
	conf.SetConfigType("yaml")
	// 从缓存解析数据到conf
	if err := conf.ReadConfig(buf); err != nil {
		panic(fmt.Errorf("failed to initialize flow config failed to read in config file: %w", err))
	}

	// 实例化一个验证器
	validate = validator.New()
}
