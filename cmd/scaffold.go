package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"gosolo/admin"
	"gosolo/admin/commands/common"
	"gosolo/cmd/build"
	"gosolo/config"
	"gosolo/module"
	"gosolo/module/component"
	"gosolo/module/irrecoverable"
	"gosolo/module/metrics"
	"gosolo/module/profiler"
	"gosolo/module/trace"
	"gosolo/module/updatable_configs"
	"gosolo/module/util"
	"gosolo/utils/logging"
	"os"
	"runtime"
	"strings"
	"time"

	gcemd "cloud.google.com/go/compute/metadata"

	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"google.golang.org/api/option"

	"gosolo/admin/commands"
)

const (
	NetworkComponent        = "network"
	ConduitFactoryComponent = "conduit-factory"
	LibP2PNodeComponent     = "libp2p-node"
)

type namedModuleFunc struct {
	fn   BuilderFunc
	name string
}

type namedComponentFunc struct {
	fn   ReadyDoneFactory
	name string

	errorHandler component.OnError
	dependencies *DependencyList
}

// AppBuilder 是默认的接待你构造器
// It runs a node process with following structure, in sequential order
// Base inits (network, storage, state, logger)
// PostInit handlers, if any
// Components handlers, if any, wait sequentially
// Run() <- main loop
// Components destructors, if any
// The initialization can be proceeded and succeeded with  PreInit and PostInit functions that allow customization
// of the process in case of nodes such as the unstaked access node where the NodeInfo is not part of the genesis data
type AppBuilder struct {
	*NodeConfig
	flags                    *pflag.FlagSet                                            // 保存所有命令行参数
	modules                  []namedModuleFunc                                         // 保存所有命名模块
	components               []namedComponentFunc                                      // 保存所有命名组件
	postShutdownFns          []func() error                                            // 退出闭节点之前、关闭组件之后需要执行的函数
	preInitFns               []BuilderFunc                                             // 初始化之前执行的函数
	postInitFns              []BuilderFunc                                             // 初始化之后执行的函数
	adminCommandBootstrapper *admin.CommandRunnerBootstrapper                          // admin命令引导
	adminCommands            map[string]func(config *NodeConfig) commands.AdminCommand //admin命令
	componentBuilder         component.ComponentManagerBuilder                         // 组件管理器构造器
}

var _ NodeBuilder = (*AppBuilder)(nil)

// 读如默认配置和命令行参数，并都映射到FlagSet中
func (ab *AppBuilder) BaseFlags() {
	defaultAppConfig, err := config.DefaultConfig()
	if err != nil {
		ab.Logger.Fatal().Err(err).Msg("failed to initialize flow config")
	}

	// initialize pflag set for Flow node
	config.InitializePFlagSet(ab.flags, &ab.config, defaultAppConfig)

}

func (ab *AppBuilder) EnqueueMetricsServerInit() {
	ab.Component("metrics server", func(node *NodeConfig) (module.ReadyDoneAware, error) {
		server := metrics.NewServer(ab.Logger, ab.config.MetricsPort)
		return server, nil
	})
}

// 注册一个管理员服务组件
func (ab *AppBuilder) EnqueueAdminServerInit() error {
	if ab.config.AdminAddr == config.NotSet {
		return nil
	}

	// 要么都不提供证书，要么全部提供证书
	if (ab.config.AdminCert != config.NotSet || ab.config.AdminKey != config.NotSet || ab.config.AdminClientCAs != config.NotSet) &&
		!(ab.config.AdminCert != config.NotSet && ab.config.AdminKey != config.NotSet && ab.config.AdminClientCAs != config.NotSet) {
		return fmt.Errorf("admin cert / key and client certs must all be provided to enable mutual TLS")
	}

	ab.RegisterDefaultAdminCommands()
	ab.Component("admin server", func(node *NodeConfig) (module.ReadyDoneAware, error) {
		// set up all admin commands
		for commandName, commandFunc := range ab.adminCommands {
			command := commandFunc(ab.NodeConfig)
			ab.adminCommandBootstrapper.RegisterHandler(commandName, command.Handler)
			ab.adminCommandBootstrapper.RegisterValidator(commandName, command.Validator)
		}

		opts := []admin.CommandRunnerOption{
			admin.WithMaxMsgSize(int(ab.config.AdminMaxMsgSize)),
		}

		if node.config.AdminCert != config.NotSet {
			serverCert, err := tls.LoadX509KeyPair(node.config.AdminCert, node.config.AdminKey)
			if err != nil {
				return nil, err
			}
			clientCAs, err := os.ReadFile(node.config.AdminClientCAs)
			if err != nil {
				return nil, err
			}
			certPool := x509.NewCertPool()
			certPool.AppendCertsFromPEM(clientCAs)
			config := &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{serverCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    certPool,
			}

			opts = append(opts, admin.WithTLS(config))
		}

		runner := ab.adminCommandBootstrapper.Bootstrap(ab.Logger, ab.config.AdminAddr, opts...)

		return runner, nil
	})

	return nil
}

func (ab *AppBuilder) EnqueueTracer() {
	ab.Component("tracer", func(node *NodeConfig) (module.ReadyDoneAware, error) {
		return ab.Tracer, nil
	})
}

func (ab *AppBuilder) ParseAndPrintFlags() error {
	// parse configuration parameters
	pflag.Parse()

	configOverride, err := config.BindPFlags(&ab.config.YamlConfig, ab.flags)
	if err != nil {
		return err
	}

	if configOverride {
		ab.Logger.Info().Str("config-file", ab.config.YamlConfig.ConfigFile).Msg("configuration file updated")
	}

	if err = ab.config.YamlConfig.Validate(); err != nil {
		ab.Logger.Fatal().Err(err).Msg("flow configuration validation failed")
	}

	info := ab.Logger.Info()

	noPrint := config.LogConfig(info, ab.flags)
	ab.flags.VisitAll(func(flag *pflag.Flag) {
		if _, ok := noPrint[flag.Name]; !ok {
			info.Str(flag.Name, fmt.Sprintf("%v", flag.Value)) // 打印不在viper中的命令行参数字段，重复的不打印
		}
	})
	info.Msg("configuration loaded")
	return nil
}

func (ab *AppBuilder) PrintBuildVersionDetails() {
	ab.Logger.Info().Str("version", build.Version()).Str("commit", build.Commit()).Msg("build details")
}

func (ab *AppBuilder) initLogger() error {
	// configure logger with standard level, node ID and UTC timestamp
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimestampFunc = func() time.Time { return time.Now().UTC() }

	// Drop all log events that exceed this rate limit
	throttledSampler := logging.BurstSampler(ab.config.DebugLogLimit, time.Second)

	log := ab.Logger.With().
		Timestamp().
		Str("node_role", ab.config.NodeRole).
		Logger().
		Sample(zerolog.LevelSampler{
			TraceSampler: throttledSampler,
			DebugSampler: throttledSampler,
		})

	log.Info().Msgf("flow %s node starting up", ab.config.NodeRole)

	// parse config log level and apply to logger
	lvl, err := zerolog.ParseLevel(strings.ToLower(ab.config.Level))
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	// Minimum log level is set to trace, then overridden by SetGlobalLevel.
	// this allows admin commands to modify the level to any value during runtime
	log = log.Level(zerolog.TraceLevel)
	zerolog.SetGlobalLevel(lvl)

	ab.Logger = log

	return nil
}

func (ab *AppBuilder) createGCEProfileUploader(client *gcemd.Client, opts ...option.ClientOption) (profiler.Uploader, error) {
	projectID, err := client.ProjectID()
	if err != nil {
		return &profiler.NoopUploader{}, fmt.Errorf("failed to get project ID: %w", err)
	}

	instance, err := client.InstanceID()
	if err != nil {
		return &profiler.NoopUploader{}, fmt.Errorf("failed to get instance ID: %w", err)
	}

	params := profiler.Params{
		ProjectID: projectID,
		Role:      ab.config.NodeRole,
		Version:   build.Version(),
		Commit:    build.Commit(),
		Instance:  instance,
	}
	ab.Logger.Info().Msgf("creating pprof profile uploader with params: %+v", params)

	return profiler.NewUploader(ab.Logger, params, opts...)
}

func (ab *AppBuilder) initMetrics() error {

	ab.Tracer = trace.NewNoopTracer()
	if ab.config.TracerEnabled {

		serviceName := ab.config.NodeRole
		tracer, err := trace.NewTracer(
			ab.Logger,
			serviceName,
			"",
			ab.config.TracerSensitivity,
		)
		if err != nil {
			return fmt.Errorf("could not initialize tracer: %w", err)
		}

		ab.Logger.Info().Msg("Tracer Started")
		ab.Tracer = tracer
	}

	ab.Metrics = Metrics{}
	if ab.config.MetricsEnabled {
		ab.MetricsRegisterer = prometheus.DefaultRegisterer

		mempools := metrics.NewMempoolCollector(5 * time.Second)

		ab.Metrics = Metrics{}

		// registers mempools as a Component so that its Ready method is invoked upon startup
		ab.Component("mempools metrics", func(node *NodeConfig) (module.ReadyDoneAware, error) {
			return mempools, nil
		})

		// metrics enabled, report node info metrics as post init event
		ab.PostInit(func(nodeConfig *NodeConfig) error {
			nodeInfoMetrics := metrics.NewNodeInfoCollector()
			nodeInfoMetrics.NodeInfo(build.Version(), build.Commit(), "SporkID", 1)
			return nil
		})
	}
	return nil
}

func (ab *AppBuilder) createProfileUploader() (profiler.Uploader, error) {
	switch {
	case ab.config.ProfilerConfig.UploaderEnabled && gcemd.OnGCE():
		return ab.createGCEProfileUploader(gcemd.NewClient(nil))
	default:
		ab.Logger.Info().Msg("not running on GCE, setting pprof uploader to noop")
		return &profiler.NoopUploader{}, nil
	}
}
func (ab *AppBuilder) initProfiler() error {

	uploader, err := ab.createProfileUploader()
	if err != nil {
		ab.Logger.Warn().Err(err).Msg("failed to create pprof uploader, falling back to noop")
		uploader = &profiler.NoopUploader{}
	}
	profiler, err := profiler.New(ab.Logger, uploader, ab.config.ProfilerConfig)
	if err != nil {
		return fmt.Errorf("could not initialize profiler: %w", err)
	}

	// register the enabled state of the profiler for dynamic configuring
	err = ab.ConfigManager.RegisterBoolConfig("profiler-enabled", profiler.Enabled, profiler.SetEnabled)
	if err != nil {
		return fmt.Errorf("could not register profiler-enabled config: %w", err)
	}

	err = ab.ConfigManager.RegisterDurationConfig(
		"profiler-trigger",
		func() time.Duration { return ab.config.ProfilerConfig.Duration },
		func(d time.Duration) error { return profiler.TriggerRun(d) },
	)
	if err != nil {
		return fmt.Errorf("could not register profiler-trigger config: %w", err)
	}

	err = ab.ConfigManager.RegisterUintConfig(
		"profiler-set-mem-profile-rate",
		func() uint { return uint(runtime.MemProfileRate) },
		func(r uint) error { runtime.MemProfileRate = int(r); return nil },
	)
	if err != nil {
		return fmt.Errorf("could not register profiler-set-mem-profile-rate setting: %w", err)
	}

	// There is no way to get the current block profile rate so we keep track of it ourselves.
	currentRate := new(uint)
	err = ab.ConfigManager.RegisterUintConfig(
		"profiler-set-block-profile-rate",
		func() uint { return *currentRate },
		func(r uint) error { currentRate = &r; runtime.SetBlockProfileRate(int(r)); return nil },
	)
	if err != nil {
		return fmt.Errorf("could not register profiler-set-block-profile-rate setting: %w", err)
	}

	err = ab.ConfigManager.RegisterUintConfig(
		"profiler-set-mutex-profile-fraction",
		func() uint { return uint(runtime.SetMutexProfileFraction(-1)) },
		func(r uint) error { _ = runtime.SetMutexProfileFraction(int(r)); return nil },
	)
	if err != nil {
		return fmt.Errorf("could not register profiler-set-mutex-profile-fraction setting: %w", err)
	}

	// registering as a DependableComponent with no dependencies so that it's started immediately on startup
	// without being blocked by other component's Ready()
	ab.DependableComponent("profiler", func(node *NodeConfig) (module.ReadyDoneAware, error) {
		return profiler, nil
	}, NewDependencyList())

	return nil
}

// handleModules initializes the given module.
func (ab *AppBuilder) handleModule(v namedModuleFunc) error {
	err := v.fn(ab.NodeConfig)
	if err != nil {
		return fmt.Errorf("module %s initialization failed: %w", v.name, err)
	}

	ab.Logger.Info().Str("module", v.name).Msg("module initialization complete")
	return nil
}

// handleModules initializes all modules that have been enqueued on this node builder.
func (ab *AppBuilder) handleModules() error {
	for _, f := range ab.modules {
		if err := ab.handleModule(f); err != nil {
			return err
		}
	}

	return nil
}

// handleComponents registers the component's factory method with the ComponentManager to be run
// when the node starts.
// It uses signal channels to ensure that components are started serially.
func (ab *AppBuilder) handleComponents() error {
	// The parent/started channels are used to enforce serial startup.
	// - parent is the started channel of the previous component.
	// - when a component is ready, it closes its started channel by calling the provided callback.
	// Components wait for their parent channel to close before starting, this ensures they start
	// up serially, even though the ComponentManager will launch the goroutines in parallel.

	// The first component is always started immediately
	parent := make(chan struct{})
	close(parent)

	var err error
	asyncComponents := []namedComponentFunc{}

	// Run all components
	for _, f := range ab.components {
		// Components with explicit dependencies are not started serially
		if f.dependencies != nil {
			asyncComponents = append(asyncComponents, f)
			continue
		}

		started := make(chan struct{})

		if f.errorHandler != nil {
			err = ab.handleRestartableComponent(f, parent, func() { close(started) })
		} else {
			err = ab.handleComponent(f, parent, func() { close(started) })
		}

		if err != nil {
			return fmt.Errorf("could not handle component %s: %w", f.name, err)
		}

		parent = started
	}

	// Components with explicit dependencies are run asynchronously, which means dependencies in
	// the dependency list must be initialized outside of the component factory.
	for _, f := range asyncComponents {
		ab.Logger.Debug().Str("component", f.name).Int("dependencies", len(f.dependencies.components)).Msg("handling component asynchronously")
		err = ab.handleComponent(f, util.AllReady(f.dependencies.components...), func() {})
		if err != nil {
			return fmt.Errorf("could not handle dependable component %s: %w", f.name, err)
		}
	}

	return nil
}

// handleComponent constructs a component using the provided ReadyDoneFactory, and registers a
// worker with the ComponentManager to be run when the node is started.
//
// The ComponentManager starts all workers in parallel. Since some components have non-idempotent
// ReadyDoneAware interfaces, we need to ensure that they are started serially. This is accomplished
// using the parentReady channel and the started closure. Components wait for the parentReady channel
// to close before starting, and then call the started callback after they are ready(). The started
// callback closes the parentReady channel of the next component, and so on.
//
// TODO: Instead of this serial startup, components should wait for their dependencies to be ready
// using their ReadyDoneAware interface. After components are updated to use the idempotent
// ReadyDoneAware interface and explicitly wait for their dependencies to be ready, we can remove
// this channel chaining.
func (ab *AppBuilder) handleComponent(v namedComponentFunc, dependencies <-chan struct{}, started func()) error {
	// Add a closure that starts the component when the node is started, and then waits for it to exit
	// gracefully.
	// Startup for all components will happen in parallel, and components can use their dependencies'
	// ReadyDoneAware interface to wait until they are ready.
	ab.componentBuilder.AddWorker(func(ctx irrecoverable.SignalerContext, ready component.ReadyFunc) {
		// wait for the dependencies to be ready before starting
		if err := util.WaitClosed(ctx, dependencies); err != nil {
			return
		}

		logger := ab.Logger.With().Str("component", v.name).Logger()

		// First, build the component using the factory method.
		readyAware, err := v.fn(ab.NodeConfig)
		if err != nil {
			ctx.Throw(fmt.Errorf("component %s initialization failed: %w", v.name, err))
		}
		logger.Info().Msg("component initialization complete")

		// if this is a Component, use the Startable interface to start the component, otherwise
		// Ready() will launch it.
		cmp, isComponent := readyAware.(component.Component)
		if isComponent {
			cmp.Start(ctx)
		}

		// Wait until the component is ready
		if err := util.WaitClosed(ctx, readyAware.Ready()); err != nil {
			// The context was cancelled. Continue to shutdown logic.
			logger.Warn().Msg("component startup aborted")

			// Non-idempotent ReadyDoneAware components trigger shutdown by calling Done(). Don't
			// do that here since it may not be safe if the component is not Ready().
			if !isComponent {
				return
			}
		} else {
			logger.Info().Msg("component startup complete")
			ready()

			// Signal to the next component that we're ready.
			started()
		}

		// Component shutdown is signaled by cancelling its context.
		<-ctx.Done()
		logger.Info().Msg("component shutdown started")

		// Finally, wait until component has finished shutting down.
		<-readyAware.Done()
		logger.Info().Msg("component shutdown complete")
	})

	return nil
}

// handleRestartableComponent constructs a component using the provided ReadyDoneFactory, and
// registers a worker with the ComponentManager to be run when the node is started.
//
// Restartable Components are components that can be restarted after successfully handling
// an irrecoverable error.
//
// Any irrecoverable errors thrown by the component will be passed to the provided error handler.
func (ab *AppBuilder) handleRestartableComponent(v namedComponentFunc, parentReady <-chan struct{}, started func()) error {
	ab.componentBuilder.AddWorker(func(ctx irrecoverable.SignalerContext, ready component.ReadyFunc) {
		// wait for the previous component to be ready before starting
		if err := util.WaitClosed(ctx, parentReady); err != nil {
			return
		}

		// Note: we're marking the worker routine ready before we even attempt to start the
		// component. the idea behind a restartable component is that the node should not depend
		// on it for safe operation, so the node does not need to wait for it to be ready.
		ready()

		// do not block serial startup. started can only be called once, so it cannot be called
		// from within the componentFactory
		started()

		log := ab.Logger.With().Str("component", v.name).Logger()

		// This may be called multiple times if the component is restarted
		componentFactory := func() (component.Component, error) {
			c, err := v.fn(ab.NodeConfig)
			if err != nil {
				return nil, err
			}
			log.Info().Msg("component initialization complete")

			go func() {
				if err := util.WaitClosed(ctx, c.Ready()); err != nil {
					log.Info().Msg("component startup aborted")
				} else {
					log.Info().Msg("component startup complete")
				}

				<-ctx.Done()
				log.Info().Msg("component shutdown started")
			}()
			return c.(component.Component), nil
		}

		err := component.RunComponent(ctx, componentFactory, v.errorHandler)
		if err != nil && !errors.Is(err, ctx.Err()) {
			ctx.Throw(fmt.Errorf("component %s encountered an unhandled irrecoverable error: %w", v.name, err))
		}

		log.Info().Msg("component shutdown complete")
	})

	return nil
}

// ExtraFlags enables binding additional flags beyond those defined in config.BaseConfig.
func (ab *AppBuilder) ExtraFlags(f func(*pflag.FlagSet)) NodeBuilder {
	f(ab.flags)
	return ab
}

// Module enables setting up dependencies of the engine with the builder context.
func (ab *AppBuilder) Module(name string, f BuilderFunc) NodeBuilder {
	ab.modules = append(ab.modules, namedModuleFunc{
		fn:   f,
		name: name,
	})
	return ab
}

// ShutdownFunc adds a callback function that is called after all components have exited.
func (ab *AppBuilder) ShutdownFunc(fn func() error) NodeBuilder {
	ab.postShutdownFns = append(ab.postShutdownFns, fn)
	return ab
}

func (ab *AppBuilder) AdminCommand(command string, f func(config *NodeConfig) commands.AdminCommand) NodeBuilder {
	ab.adminCommands[command] = f
	return ab
}

// Component adds a new component to the node that conforms to the ReadyDoneAware
// interface.
//
// The ReadyDoneFactory may return either a `Component` or `ReadyDoneAware` instance.
// In both cases, the object is started when the node is run, and the node will wait for the
// component to exit gracefully.
func (ab *AppBuilder) Component(name string, f ReadyDoneFactory) NodeBuilder {
	ab.components = append(ab.components, namedComponentFunc{
		fn:   f,
		name: name,
	})
	return ab
}

// DependableComponent adds a new component to the node that conforms to the ReadyDoneAware
// interface. The builder will wait until all of the components in the dependencies list are ready
// before constructing the component.
//
// The ReadyDoneFactory may return either a `Component` or `ReadyDoneAware` instance.
// In both cases, the object is started when the node is run, and the node will wait for the
// component to exit gracefully.
//
// IMPORTANT: Dependable components are started in parallel with no guaranteed run order, so all
// dependencies must be initialized outside of the ReadyDoneFactory, and their `Ready()` method
// MUST be idempotent.
func (ab *AppBuilder) DependableComponent(name string, f ReadyDoneFactory, dependencies *DependencyList) NodeBuilder {
	// Note: dependencies are passed as a struct to allow updating the list after calling this method.
	// Passing a slice instead would result in out of sync metadata since slices are passed by reference
	ab.components = append(ab.components, namedComponentFunc{
		fn:           f,
		name:         name,
		dependencies: dependencies,
	})
	return ab
}

// OverrideComponent adds given builder function to the components set of the node builder. If a builder function with that name
// already exists, it will be overridden.
func (ab *AppBuilder) OverrideComponent(name string, f ReadyDoneFactory) NodeBuilder {
	for i := 0; i < len(ab.components); i++ {
		if ab.components[i].name == name {
			// found component with the name, override it.
			ab.components[i] = namedComponentFunc{
				fn:   f,
				name: name,
			}

			return ab
		}
	}

	// no component found with the same name, hence just adding it.
	return ab.Component(name, f)
}

// RestartableComponent adds a new component to the node that conforms to the ReadyDoneAware
// interface, and calls the provided error handler when an irrecoverable error is encountered.
// Use RestartableComponent if the component is not critical to the node's safe operation and
// can/should be independently restarted when an irrecoverable error is encountered.
//
// IMPORTANT: Since a RestartableComponent can be restarted independently of the node, the node and
// other components must not rely on it for safe operation, and failures must be handled gracefully.
// As such, RestartableComponents do not block the node from becoming ready, and do not block
// subsequent components from starting serially. They do start in serial order.
//
// Note: The ReadyDoneFactory method may be called multiple times if the component is restarted.
//
// Any irrecoverable errors thrown by the component will be passed to the provided error handler.
func (ab *AppBuilder) RestartableComponent(name string, f ReadyDoneFactory, errorHandler component.OnError) NodeBuilder {
	ab.components = append(ab.components, namedComponentFunc{
		fn:           f,
		name:         name,
		errorHandler: errorHandler,
	})
	return ab
}

// OverrideModule adds given builder function to the modules set of the node builder. If a builder function with that name
// already exists, it will be overridden.
func (ab *AppBuilder) OverrideModule(name string, f BuilderFunc) NodeBuilder {
	for i := 0; i < len(ab.modules); i++ {
		if ab.modules[i].name == name {
			// found module with the name, override it.
			ab.modules[i] = namedModuleFunc{
				fn:   f,
				name: name,
			}

			return ab
		}
	}

	// no module found with the same name, hence just adding it.
	return ab.Module(name, f)
}

func (ab *AppBuilder) PreInit(f BuilderFunc) NodeBuilder {
	ab.preInitFns = append(ab.preInitFns, f)
	return ab
}

func (ab *AppBuilder) PostInit(f BuilderFunc) NodeBuilder {
	ab.postInitFns = append(ab.postInitFns, f)
	return ab
}

type Option func(*config.BaseConfig)

func WithBindAddress(bindAddress string) Option {
	return func(config *config.BaseConfig) {
		config.BindAddr = bindAddress
	}
}

func WithMetricsEnabled(enabled bool) Option {
	return func(config *config.BaseConfig) {
		config.MetricsEnabled = enabled
	}
}

func WithLogLevel(level string) Option {
	return func(config *config.BaseConfig) {
		config.Level = level
	}
}

// App creates a new Flow node builder with the given name.
func App(role string, opts ...Option) *AppBuilder {
	config := config.DefaultBaseConfig()
	config.NodeRole = role
	for _, opt := range opts {
		opt(config)
	}

	builder := &AppBuilder{
		NodeConfig: &NodeConfig{
			config:                  *config,
			Logger:                  zerolog.New(os.Stderr),
			PeerManagerDependencies: NewDependencyList(),
			ConfigManager:           updatable_configs.NewManager(),
		},
		flags:                    pflag.CommandLine,
		adminCommandBootstrapper: admin.NewCommandRunnerBootstrapper(),
		adminCommands:            make(map[string]func(*NodeConfig) commands.AdminCommand),
		componentBuilder:         component.NewComponentManagerBuilder(),
	}
	return builder
}

// 初始化节点
func (ab *AppBuilder) Initialize() error {

	// 打印版本信息到日志
	ab.PrintBuildVersionDetails()

	// 定义和加载并合并默认配置和命令行参数
	ab.BaseFlags()

	//  解析命令行参数的具体的值，并打印配置文件和命令行参数
	if err := ab.ParseAndPrintFlags(); err != nil {
		return err
	}

	if ab.config.MetricsEnabled {
		ab.EnqueueMetricsServerInit()
		// if err := ab.RegisterBadgerMetrics(); err != nil {
		// 	return err
		// }
	}

	ab.EnqueueTracer()

	return nil
}

func (ab *AppBuilder) RegisterDefaultAdminCommands() {
	ab.AdminCommand("set-log-level", func(config *NodeConfig) commands.AdminCommand {
		return &common.SetLogLevelCommand{}
	}).AdminCommand("set-golog-level", func(config *NodeConfig) commands.AdminCommand {
		return &common.SetGologLevelCommand{}
	}).AdminCommand("get-config", func(config *NodeConfig) commands.AdminCommand {
		return common.NewGetConfigCommand(config.ConfigManager)
	}).AdminCommand("set-config", func(config *NodeConfig) commands.AdminCommand {
		return common.NewSetConfigCommand(config.ConfigManager)
	}).AdminCommand("list-configs", func(config *NodeConfig) commands.AdminCommand {
		return common.NewListConfigCommand(config.ConfigManager)
	})
}

func (ab *AppBuilder) Build() (Node, error) {
	// Run the prestart initialization. This includes anything that should be done before
	// starting the components.
	if err := ab.onStart(); err != nil {
		return nil, err
	}

	return NewNode(
		ab.componentBuilder.Build(),
		ab.NodeConfig,
		ab.Logger,
		ab.postShutdown,
		ab.handleFatal,
	), nil
}

func (ab *AppBuilder) onStart() error {

	if err := ab.initLogger(); err != nil {
		return err
	}

	if err := ab.initMetrics(); err != nil {
		return err
	}

	for _, f := range ab.preInitFns {
		if err := ab.handlePreInit(f); err != nil {
			return err
		}
	}

	if err := ab.initProfiler(); err != nil {
		return err
	}

	for _, f := range ab.postInitFns {
		if err := ab.handlePostInit(f); err != nil {
			return err
		}
	}

	if err := ab.EnqueueAdminServerInit(); err != nil {
		return err
	}

	// run all modules
	if err := ab.handleModules(); err != nil {
		return fmt.Errorf("could not handle modules: %w", err)
	}

	// run all components
	return ab.handleComponents()
}

// postShutdown 执行节点退出前的清理代码， 需要在所有组件退出后
// put any cleanup code here that should be run after all components have stopped
func (ab *AppBuilder) postShutdown() error {
	var errs *multierror.Error

	for _, fn := range ab.postShutdownFns {
		err := fn()
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	ab.Logger.Info().Msg("database has been closed")
	return errs.ErrorOrNil()
}

// handleFatal 处理不可恢复错误的函数
func (ab *AppBuilder) handleFatal(err error) {
	ab.Logger.Fatal().Err(err).Msg("unhandled irrecoverable error")
}

// 执行pre初始化的函数的封装
func (ab *AppBuilder) handlePreInit(f BuilderFunc) error {
	return f(ab.NodeConfig)
}

// 执行post初始化的函数的封装
func (ab *AppBuilder) handlePostInit(f BuilderFunc) error {
	return f(ab.NodeConfig)
}
