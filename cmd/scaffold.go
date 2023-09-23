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
	"gosolo/module/irrecoverable"
	"os"
	"runtime"
	"strings"
	"time"

	gcemd "cloud.google.com/go/compute/metadata"
	"github.com/dgraph-io/badger/v2"
	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"google.golang.org/api/option"

	"github.com/onflow/flow-go/admin/commands"
	"github.com/onflow/flow-go/fvm"
	"github.com/onflow/flow-go/fvm/environment"
	"github.com/onflow/flow-go/model/flow"
	"github.com/onflow/flow-go/module"
	"github.com/onflow/flow-go/module/chainsync"
	"github.com/onflow/flow-go/module/compliance"
	"github.com/onflow/flow-go/module/component"
	"github.com/onflow/flow-go/module/local"
	"github.com/onflow/flow-go/module/metrics"
	"github.com/onflow/flow-go/module/profiler"
	"github.com/onflow/flow-go/module/trace"
	"github.com/onflow/flow-go/module/updatable_configs"
	"github.com/onflow/flow-go/module/util"
	"github.com/onflow/flow-go/state/protocol"
	badgerState "github.com/onflow/flow-go/state/protocol/badger"
	"github.com/onflow/flow-go/state/protocol/events"
	"github.com/onflow/flow-go/storage"
	bstorage "github.com/onflow/flow-go/storage/badger"
	"github.com/onflow/flow-go/storage/badger/operation"
	sutil "github.com/onflow/flow-go/storage/util"
	"github.com/onflow/flow-go/utils/logging"
)

const (
	NetworkComponent        = "network"
	ConduitFactoryComponent = "conduit-factory"
	LibP2PNodeComponent     = "libp2p-node"
)

type Metrics struct {
	Network        module.NetworkMetrics
	Engine         module.EngineMetrics
	Compliance     module.ComplianceMetrics
	Cache          module.CacheMetrics
	Mempool        module.MempoolMetrics
	CleanCollector module.CleanerMetrics
	Bitswap        module.BitswapMetrics
}

type Storage = storage.All

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

var _ NodeBuilder = (*App)(nil)

// 读如默认配置和命令行参数，并都映射到FlagSet中
func (ab *AppBuilder) BaseFlags() {
	defaultAppConfig, err := config.DefaultConfig()
	if err != nil {
		ab.Logger.Fatal().Err(err).Msg("failed to initialize flow config")
	}

	// initialize pflag set for Flow node
	config.InitializePFlagSet(ab.flags, &ab.BaseConfig, defaultAppConfig)

}

// HeroCacheMetricsFactory returns a HeroCacheMetricsFactory based on the MetricsEnabled flag.
// If MetricsEnabled is true, it returns a HeroCacheMetricsFactory that will register metrics with the provided MetricsRegisterer.
// If MetricsEnabled is false, it returns a no-op HeroCacheMetricsFactory that will not register any metrics.
func (ab *AppBuilder) HeroCacheMetricsFactory() metrics.HeroCacheMetricsFactory {
	if ab.MetricsEnabled {
		return metrics.NewHeroCacheMetricsFactory(ab.MetricsRegisterer)
	}
	return metrics.NewNoopHeroCacheMetricsFactory()
}

func (ab *AppBuilder) EnqueueMetricsServerInit() {
	ab.Component("metrics server", func(node *NodeConfig) (module.ReadyDoneAware, error) {
		server := metrics.NewServer(ab.Logger, ab.BaseConfig.metricsPort)
		return server, nil
	})
}

// 注册一个管理员服务组件
func (ab *AppBuilder) EnqueueAdminServerInit() error {
	if ab.AdminAddr == config.NotSet {
		return nil
	}

	// 要么都不提供证书，要么全部提供证书
	if (ab.AdminCert != config.NotSet || ab.AdminKey != config.NotSet || ab.AdminClientCAs != config.NotSet) &&
		!(ab.AdminCert != config.NotSet && ab.AdminKey != config.NotSet && ab.AdminClientCAs != config.NotSet) {
		return fmt.Errorf("admin cert / key and client certs must all be provided to enable mutual TLS")
	}

	// create the updatable config manager
	ab.RegisterDefaultAdminCommands()
	ab.Component("admin server", func(node *NodeConfig) (module.ReadyDoneAware, error) {
		// set up all admin commands
		for commandName, commandFunc := range ab.adminCommands {
			command := commandFunc(ab.NodeConfig)
			ab.adminCommandBootstrapper.RegisterHandler(commandName, command.Handler)
			ab.adminCommandBootstrapper.RegisterValidator(commandName, command.Validator)
		}

		opts := []admin.CommandRunnerOption{
			admin.WithMaxMsgSize(int(ab.AdminMaxMsgSize)),
		}

		if node.AdminCert != config.NotSet {
			serverCert, err := tls.LoadX509KeyPair(node.AdminCert, node.AdminKey)
			if err != nil {
				return nil, err
			}
			clientCAs, err := os.ReadFile(node.AdminClientCAs)
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

		runner := ab.adminCommandBootstrapper.Bootstrap(ab.Logger, ab.AdminAddr, opts...)

		return runner, nil
	})

	return nil
}

func (ab *AppBuilder) RegisterBadgerMetrics() error {
	return metrics.RegisterBadgerMetrics()
}

func (ab *AppBuilder) EnqueueTracer() {
	ab.Component("tracer", func(node *NodeConfig) (module.ReadyDoneAware, error) {
		return ab.Tracer, nil
	})
}

func (ab *AppBuilder) ParseAndPrintFlags() error {
	// parse configuration parameters
	pflag.Parse()

	configOverride, err := config.BindPFlags(&ab.BaseConfig.YamlConfig, ab.flags)
	if err != nil {
		return err
	}

	if configOverride {
		ab.Logger.Info().Str("config-file", ab.YamlConfig.ConfigFile).Msg("configuration file updated")
	}

	if err = ab.BaseConfig.YamlConfig.Validate(); err != nil {
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
	throttledSampler := logging.BurstSampler(ab.BaseConfig.debugLogLimit, time.Second)

	log := ab.Logger.With().
		Timestamp().
		Str("node_role", ab.BaseConfig.NodeRole).
		Str("node_id", ab.NodeID.String()).
		Logger().
		Sample(zerolog.LevelSampler{
			TraceSampler: throttledSampler,
			DebugSampler: throttledSampler,
		})

	log.Info().Msgf("flow %s node starting up", ab.BaseConfig.NodeRole)

	// parse config log level and apply to logger
	lvl, err := zerolog.ParseLevel(strings.ToLower(ab.BaseConfig.level))
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

func (ab *AppBuilder) initMetrics() error {

	ab.Tracer = trace.NewNoopTracer()
	if ab.BaseConfig.tracerEnabled {
		nodeIdHex := ab.NodeID.String()
		if len(nodeIdHex) > 8 {
			nodeIdHex = nodeIdHex[:8]
		}

		serviceName := ab.BaseConfig.NodeRole + "-" + nodeIdHex
		tracer, err := trace.NewTracer(
			ab.Logger,
			serviceName,
			ab.RootChainID.String(),
			ab.tracerSensitivity,
		)
		if err != nil {
			return fmt.Errorf("could not initialize tracer: %w", err)
		}

		ab.Logger.Info().Msg("Tracer Started")
		ab.Tracer = tracer
	}

	ab.Metrics = Metrics{
		Network:        metrics.NewNoopCollector(),
		Engine:         metrics.NewNoopCollector(),
		Compliance:     metrics.NewNoopCollector(),
		Cache:          metrics.NewNoopCollector(),
		Mempool:        metrics.NewNoopCollector(),
		CleanCollector: metrics.NewNoopCollector(),
		Bitswap:        metrics.NewNoopCollector(),
	}
	if ab.BaseConfig.MetricsEnabled {
		ab.MetricsRegisterer = prometheus.DefaultRegisterer

		mempools := metrics.NewMempoolCollector(5 * time.Second)

		ab.Metrics = Metrics{
			Network:    metrics.NewNetworkCollector(ab.Logger),
			Engine:     metrics.NewEngineCollector(),
			Compliance: metrics.NewComplianceCollector(),
			// CacheControl metrics has been causing memory abuse, disable for now
			// Cache:          metrics.NewCacheCollector(ab.RootChainID),
			Cache:          metrics.NewNoopCollector(),
			CleanCollector: metrics.NewCleanerCollector(),
			Mempool:        mempools,
			Bitswap:        metrics.NewBitswapCollector(),
		}

		// registers mempools as a Component so that its Ready method is invoked upon startup
		ab.Component("mempools metrics", func(node *NodeConfig) (module.ReadyDoneAware, error) {
			return mempools, nil
		})

		// metrics enabled, report node info metrics as post init event
		ab.PostInit(func(nodeConfig *NodeConfig) error {
			nodeInfoMetrics := metrics.NewNodeInfoCollector()
			protocolVersion, err := ab.RootSnapshot.Params().ProtocolVersion()
			if err != nil {
				return fmt.Errorf("could not query root snapshoot protocol version: %w", err)
			}
			nodeInfoMetrics.NodeInfo(build.Version(), build.Commit(), nodeConfig.SporkID.String(), protocolVersion)
			return nil
		})
	}
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
		ChainID:   chainID,
		Role:      ab.NodeConfig.NodeRole,
		Version:   build.Version(),
		Commit:    build.Commit(),
		Instance:  instance,
	}
	ab.Logger.Info().Msgf("creating pprof profile uploader with params: %+v", params)

	return profiler.NewUploader(ab.Logger, params, opts...)
}

func (ab *AppBuilder) createProfileUploader() (profiler.Uploader, error) {
	switch {
	case ab.BaseConfig.profilerConfig.UploaderEnabled && gcemd.OnGCE():
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

	profiler, err := profiler.New(ab.Logger, uploader, ab.BaseConfig.profilerConfig)
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
		func() time.Duration { return ab.BaseConfig.profilerConfig.Duration },
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

func (ab *AppBuilder) initDB() error {

	// if a db has been passed in, use that instead of creating one
	if ab.BaseConfig.db != nil {
		ab.DB = ab.BaseConfig.db
		return nil
	}

	// Pre-create DB path (Badger creates only one-level dirs)
	err := os.MkdirAll(ab.BaseConfig.datadir, 0700)
	if err != nil {
		return fmt.Errorf("could not create datadir (path: %s): %w", ab.BaseConfig.datadir, err)
	}

	log := sutil.NewLogger(ab.Logger)

	// we initialize the database with options that allow us to keep the maximum
	// item size in the trie itself (up to 1MB) and where we keep all level zero
	// tables in-memory as well; this slows down compaction and increases memory
	// usage, but it improves overall performance and disk i/o
	opts := badger.
		DefaultOptions(ab.BaseConfig.datadir).
		WithKeepL0InMemory(true).
		WithLogger(log).

		// the ValueLogFileSize option specifies how big the value of a
		// key-value pair is allowed to be saved into badger.
		// exceeding this limit, will fail with an error like this:
		// could not store data: Value with size <xxxx> exceeded 1073741824 limit
		// Maximum value size is 10G, needed by execution node
		// TODO: finding a better max value for each node type
		WithValueLogFileSize(128 << 23).
		WithValueLogMaxEntries(100000) // Default is 1000000

	publicDB, err := bstorage.InitPublic(opts)
	if err != nil {
		return fmt.Errorf("could not open public db: %w", err)
	}
	ab.DB = publicDB

	ab.ShutdownFunc(func() error {
		if err := ab.DB.Close(); err != nil {
			return fmt.Errorf("error closing protocol database: %w", err)
		}
		return nil
	})

	ab.Component("badger log cleaner", func(node *NodeConfig) (module.ReadyDoneAware, error) {
		return bstorage.NewCleaner(node.Logger, node.DB, node.Metrics.CleanCollector, flow.DefaultValueLogGCWaitDuration), nil
	})

	return nil
}

func (ab *AppBuilder) initSecretsDB() error {

	// if the secrets DB is disabled (only applicable for Consensus Follower,
	// which makes use of this same logic), skip this initialization
	if !ab.BaseConfig.secretsDBEnabled {
		return nil
	}

	if ab.BaseConfig.secretsdir == NotSet {
		return fmt.Errorf("missing required flag '--secretsdir'")
	}

	err := os.MkdirAll(ab.BaseConfig.secretsdir, 0700)
	if err != nil {
		return fmt.Errorf("could not create secrets db dir (path: %s): %w", ab.BaseConfig.secretsdir, err)
	}

	log := sutil.NewLogger(ab.Logger)

	opts := badger.DefaultOptions(ab.BaseConfig.secretsdir).WithLogger(log)

	// NOTE: SN nodes need to explicitly set --insecure-secrets-db to true in order to
	// disable secrets database encryption
	if ab.NodeRole == flow.RoleConsensus.String() && ab.InsecureSecretsDB {
		ab.Logger.Warn().Msg("starting with secrets database encryption disabled")
	} else {
		encryptionKey, err := loadSecretsEncryptionKey(ab.BootstrapDir, ab.NodeID)
		if errors.Is(err, os.ErrNotExist) {
			if ab.NodeRole == flow.RoleConsensus.String() {
				// missing key is a fatal error for SN nodes
				return fmt.Errorf("secrets db encryption key not found: %w", err)
			}
			ab.Logger.Warn().Msg("starting with secrets database encryption disabled")
		} else if err != nil {
			return fmt.Errorf("failed to read secrets db encryption key: %w", err)
		} else {
			opts = opts.WithEncryptionKey(encryptionKey)
		}
	}

	secretsDB, err := bstorage.InitSecret(opts)
	if err != nil {
		return fmt.Errorf("could not open secrets db: %w", err)
	}
	ab.SecretsDB = secretsDB

	ab.ShutdownFunc(func() error {
		if err := ab.SecretsDB.Close(); err != nil {
			return fmt.Errorf("error closing secrets database: %w", err)
		}
		return nil
	})

	return nil
}

func (ab *AppBuilder) initStorage() error {

	// in order to void long iterations with big keys when initializing with an
	// already populated database, we bootstrap the initial maximum key size
	// upon starting
	err := operation.RetryOnConflict(ab.DB.Update, func(tx *badger.Txn) error {
		return operation.InitMax(tx)
	})
	if err != nil {
		return fmt.Errorf("could not initialize max tracker: %w", err)
	}

	headers := bstorage.NewHeaders(ab.Metrics.Cache, ab.DB)
	guarantees := bstorage.NewGuarantees(ab.Metrics.Cache, ab.DB, ab.BaseConfig.guaranteesCacheSize)
	seals := bstorage.NewSeals(ab.Metrics.Cache, ab.DB)
	results := bstorage.NewExecutionResults(ab.Metrics.Cache, ab.DB)
	receipts := bstorage.NewExecutionReceipts(ab.Metrics.Cache, ab.DB, results, ab.BaseConfig.receiptsCacheSize)
	index := bstorage.NewIndex(ab.Metrics.Cache, ab.DB)
	payloads := bstorage.NewPayloads(ab.DB, index, guarantees, seals, receipts, results)
	blocks := bstorage.NewBlocks(ab.DB, headers, payloads)
	qcs := bstorage.NewQuorumCertificates(ab.Metrics.Cache, ab.DB, bstorage.DefaultCacheSize)
	transactions := bstorage.NewTransactions(ab.Metrics.Cache, ab.DB)
	collections := bstorage.NewCollections(ab.DB, transactions)
	setups := bstorage.NewEpochSetups(ab.Metrics.Cache, ab.DB)
	epochCommits := bstorage.NewEpochCommits(ab.Metrics.Cache, ab.DB)
	statuses := bstorage.NewEpochStatuses(ab.Metrics.Cache, ab.DB)
	commits := bstorage.NewCommits(ab.Metrics.Cache, ab.DB)
	versionBeacons := bstorage.NewVersionBeacons(ab.DB)

	ab.Storage = Storage{
		Headers:            headers,
		Guarantees:         guarantees,
		Receipts:           receipts,
		Results:            results,
		Seals:              seals,
		Index:              index,
		Payloads:           payloads,
		Blocks:             blocks,
		QuorumCertificates: qcs,
		Transactions:       transactions,
		Collections:        collections,
		Setups:             setups,
		EpochCommits:       epochCommits,
		VersionBeacons:     versionBeacons,
		Statuses:           statuses,
		Commits:            commits,
	}

	return nil
}

func (ab *AppBuilder) initState() error {
	ab.ProtocolEvents = events.NewDistributor()

	isBootStrapped, err := badgerState.IsBootstrapped(ab.DB)
	if err != nil {
		return fmt.Errorf("failed to determine whether database contains bootstrapped state: %w", err)
	}

	if isBootStrapped {
		ab.Logger.Info().Msg("opening already bootstrapped protocol state")
		state, err := badgerState.OpenState(
			ab.Metrics.Compliance,
			ab.DB,
			ab.Storage.Headers,
			ab.Storage.Seals,
			ab.Storage.Results,
			ab.Storage.Blocks,
			ab.Storage.QuorumCertificates,
			ab.Storage.Setups,
			ab.Storage.EpochCommits,
			ab.Storage.Statuses,
			ab.Storage.VersionBeacons,
		)
		if err != nil {
			return fmt.Errorf("could not open protocol state: %w", err)
		}
		ab.State = state

		// set root snapshot field
		rootBlock, err := state.Params().FinalizedRoot()
		if err != nil {
			return fmt.Errorf("could not get root block from protocol state: %w", err)
		}

		rootSnapshot := state.AtBlockID(rootBlock.ID())
		if err := ab.setRootSnapshot(rootSnapshot); err != nil {
			return err
		}
	} else {
		// Bootstrap!
		ab.Logger.Info().Msg("bootstrapping empty protocol state")

		// if no root snapshot is configured, attempt to load the file from disk
		var rootSnapshot = ab.RootSnapshot
		if rootSnapshot == nil {
			ab.Logger.Info().Msgf("loading root protocol state snapshot from disk")
			rootSnapshot, err = loadRootProtocolSnapshot(ab.BaseConfig.BootstrapDir)
			if err != nil {
				return fmt.Errorf("failed to read protocol snapshot from disk: %w", err)
			}
		}
		// set root snapshot fields
		if err := ab.setRootSnapshot(rootSnapshot); err != nil {
			return err
		}

		// generate bootstrap config options as per NodeConfig
		var options []badgerState.BootstrapConfigOptions
		if ab.SkipNwAddressBasedValidations {
			options = append(options, badgerState.SkipNetworkAddressValidation)
		}

		ab.State, err = badgerState.Bootstrap(
			ab.Metrics.Compliance,
			ab.DB,
			ab.Storage.Headers,
			ab.Storage.Seals,
			ab.Storage.Results,
			ab.Storage.Blocks,
			ab.Storage.QuorumCertificates,
			ab.Storage.Setups,
			ab.Storage.EpochCommits,
			ab.Storage.Statuses,
			ab.Storage.VersionBeacons,
			ab.RootSnapshot,
			options...,
		)
		if err != nil {
			return fmt.Errorf("could not bootstrap protocol state: %w", err)
		}

		ab.Logger.Info().
			Hex("root_result_id", logging.Entity(ab.RootResult)).
			Hex("root_state_commitment", ab.RootSeal.FinalState[:]).
			Hex("finalized_root_block_id", logging.Entity(ab.FinalizedRootBlock)).
			Uint64("finalized_root_block_height", ab.FinalizedRootBlock.Header.Height).
			Hex("sealed_root_block_id", logging.Entity(ab.SealedRootBlock)).
			Uint64("sealed_root_block_height", ab.SealedRootBlock.Header.Height).
			Msg("protocol state bootstrapped")
	}

	// initialize local if it hasn't been initialized yet
	if ab.Me == nil {
		if err := ab.initLocal(); err != nil {
			return err
		}
	}

	lastFinalized, err := ab.State.Final().Head()
	if err != nil {
		return fmt.Errorf("could not get last finalized block header: %w", err)
	}
	ab.NodeConfig.LastFinalizedHeader = lastFinalized

	lastSealed, err := ab.State.Sealed().Head()
	if err != nil {
		return fmt.Errorf("could not get last sealed block header: %w", err)
	}

	ab.Logger.Info().
		Hex("last_finalized_block_id", logging.Entity(lastFinalized)).
		Uint64("last_finalized_block_height", lastFinalized.Height).
		Hex("last_sealed_block_id", logging.Entity(lastSealed)).
		Uint64("last_sealed_block_height", lastSealed.Height).
		Hex("finalized_root_block_id", logging.Entity(ab.FinalizedRootBlock)).
		Uint64("finalized_root_block_height", ab.FinalizedRootBlock.Header.Height).
		Hex("sealed_root_block_id", logging.Entity(ab.SealedRootBlock)).
		Uint64("sealed_root_block_height", ab.SealedRootBlock.Header.Height).
		Msg("successfully opened protocol state")

	return nil
}

// setRootSnapshot sets the root snapshot field and all related fields in the NodeConfig.
func (ab *AppBuilder) setRootSnapshot(rootSnapshot protocol.Snapshot) error {
	var err error

	// validate the root snapshot QCs
	err = badgerState.IsValidRootSnapshotQCs(rootSnapshot)
	if err != nil {
		return fmt.Errorf("failed to validate root snapshot QCs: %w", err)
	}

	// perform extra checks requested by specific node types
	if ab.extraRootSnapshotCheck != nil {
		err = ab.extraRootSnapshotCheck(rootSnapshot)
		if err != nil {
			return fmt.Errorf("failed to perform extra checks on root snapshot: %w", err)
		}
	}

	ab.RootSnapshot = rootSnapshot
	// cache properties of the root snapshot, for convenience
	ab.RootResult, ab.RootSeal, err = ab.RootSnapshot.SealedResult()
	if err != nil {
		return fmt.Errorf("failed to read root sealed result: %w", err)
	}

	sealingSegment, err := ab.RootSnapshot.SealingSegment()
	if err != nil {
		return fmt.Errorf("failed to read root sealing segment: %w", err)
	}

	ab.FinalizedRootBlock = sealingSegment.Highest()
	ab.SealedRootBlock = sealingSegment.Sealed()
	ab.RootQC, err = ab.RootSnapshot.QuorumCertificate()
	if err != nil {
		return fmt.Errorf("failed to read root QC: %w", err)
	}

	ab.RootChainID = ab.FinalizedRootBlock.Header.ChainID
	ab.SporkID, err = ab.RootSnapshot.Params().SporkID()
	if err != nil {
		return fmt.Errorf("failed to read spork ID: %w", err)
	}

	return nil
}

func (ab *AppBuilder) initLocal() error {
	// Verify that my ID (as given in the configuration) is known to the network
	// (i.e. protocol state). There are two cases that will cause the following error:
	// 1) used the wrong node id, which is not part of the identity list of the finalized state
	// 2) the node id is a new one for a new spork, but the bootstrap data has not been updated.
	myID, err := flow.HexStringToIdentifier(ab.BaseConfig.nodeIDHex)
	if err != nil {
		return fmt.Errorf("could not parse node identifier: %w", err)
	}

	self, err := ab.State.Final().Identity(myID)
	if err != nil {
		return fmt.Errorf("node identity not found in the identity list of the finalized state (id: %v): %w", myID, err)
	}

	// Verify that my role (as given in the configuration) is consistent with the protocol state.
	// We enforce this strictly for MainNet. For other networks (e.g. TestNet or BenchNet), we
	// are lenient, to allow ghost node to run as any role.
	if self.Role.String() != ab.BaseConfig.NodeRole {
		rootBlockHeader, err := ab.State.Params().FinalizedRoot()
		if err != nil {
			return fmt.Errorf("could not get root block from protocol state: %w", err)
		}

		if rootBlockHeader.ChainID == flow.Mainnet {
			return fmt.Errorf("running as incorrect role, expected: %v, actual: %v, exiting",
				self.Role.String(),
				ab.BaseConfig.NodeRole,
			)
		}

		ab.Logger.Warn().Msgf("running as incorrect role, expected: %v, actual: %v, continuing",
			self.Role.String(),
			ab.BaseConfig.NodeRole)
	}

	// ensure that the configured staking/network keys are consistent with the protocol state
	if !self.NetworkPubKey.Equals(ab.NetworkKey.PublicKey()) {
		return fmt.Errorf("configured networking key does not match protocol state")
	}
	if !self.StakingPubKey.Equals(ab.StakingKey.PublicKey()) {
		return fmt.Errorf("configured staking key does not match protocol state")
	}

	ab.Me, err = local.New(self, ab.StakingKey)
	if err != nil {
		return fmt.Errorf("could not initialize local: %w", err)
	}

	return nil
}

func (ab *AppBuilder) initFvmOptions() {
	blockFinder := environment.NewBlockFinder(ab.Storage.Headers)
	vmOpts := []fvm.Option{
		fvm.WithChain(ab.RootChainID.Chain()),
		fvm.WithBlocks(blockFinder),
		fvm.WithAccountStorageLimit(true),
	}
	if ab.RootChainID == flow.Testnet || ab.RootChainID == flow.Sandboxnet || ab.RootChainID == flow.Mainnet {
		vmOpts = append(vmOpts,
			fvm.WithTransactionFeesEnabled(true),
		)
	}
	if ab.RootChainID == flow.Testnet || ab.RootChainID == flow.Sandboxnet || ab.RootChainID == flow.Localnet || ab.RootChainID == flow.Benchnet {
		vmOpts = append(vmOpts,
			fvm.WithContractDeploymentRestricted(false),
		)
	}
	ab.FvmOptions = vmOpts
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

// ExtraFlags enables binding additional flags beyond those defined in BaseConfig.
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

type Option func(*BaseConfig)

func WithBootstrapDir(bootstrapDir string) Option {
	return func(config *BaseConfig) {
		config.BootstrapDir = bootstrapDir
	}
}

func WithBindAddress(bindAddress string) Option {
	return func(config *BaseConfig) {
		config.BindAddr = bindAddress
	}
}

func WithDataDir(dataDir string) Option {
	return func(config *BaseConfig) {
		if config.db == nil {
			config.datadir = dataDir
		}
	}
}

func WithSecretsDBEnabled(enabled bool) Option {
	return func(config *BaseConfig) {
		config.secretsDBEnabled = enabled
	}
}

func WithMetricsEnabled(enabled bool) Option {
	return func(config *BaseConfig) {
		config.MetricsEnabled = enabled
	}
}

func WithSyncCoreConfig(syncConfig chainsync.Config) Option {
	return func(config *BaseConfig) {
		config.SyncCoreConfig = syncConfig
	}
}

func WithComplianceConfig(complianceConfig compliance.Config) Option {
	return func(config *BaseConfig) {
		config.ComplianceConfig = complianceConfig
	}
}

func WithLogLevel(level string) Option {
	return func(config *BaseConfig) {
		config.level = level
	}
}

// WithDB takes precedence over WithDataDir and datadir will be set to empty if DB is set using this option
func WithDB(db *badger.DB) Option {
	return func(config *BaseConfig) {
		config.db = db
		config.datadir = ""
	}
}

// App creates a new Flow node builder with the given name.
func App(role string, opts ...Option) *AppBuilder {
	config := DefaultBaseConfig()
	config.NodeRole = role
	for _, opt := range opts {
		opt(config)
	}

	builder := &AppBuilder{
		NodeConfig: &NodeConfig{
			BaseConfig:              *config,
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

	ab.EnqueuePingService()

	if ab.MetricsEnabled {
		ab.EnqueueMetricsServerInit()
		if err := ab.RegisterBadgerMetrics(); err != nil {
			return err
		}
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

	if err := ab.initDB(); err != nil {
		return err
	}

	if err := ab.initSecretsDB(); err != nil {
		return err
	}

	if err := ab.initMetrics(); err != nil {
		return err
	}

	if err := ab.initStorage(); err != nil {
		return err
	}

	for _, f := range ab.preInitFns {
		if err := ab.handlePreInit(f); err != nil {
			return err
		}
	}

	if err := ab.initState(); err != nil {
		return err
	}

	if err := ab.initProfiler(); err != nil {
		return err
	}

	ab.initFvmOptions()

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
