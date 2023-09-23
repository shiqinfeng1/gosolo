package cmd

import (
	"gosolo/module"
	"gosolo/module/component"

	"github.com/spf13/pflag"

	"github.com/onflow/flow-go/admin/commands"
)

type BuilderFunc func(nodeConfig *NodeConfig) error
type ReadyDoneFactory func(node *NodeConfig) (module.ReadyDoneAware, error)

// NodeBuilder 引导构造一个节点的初始化方法
type NodeBuilder interface {
	// BaseFlags 设置命令行参数
	BaseFlags()

	// ExtraFlags 设置额外的命令行参数配置
	ExtraFlags(f func(*pflag.FlagSet)) NodeBuilder

	// ParseAndPrintFlags 解析和验证所有命令行参数
	ParseAndPrintFlags() error

	// Initialize 启动节点之前的初始化
	Initialize() error

	// PrintBuildVersionDetails 打印版本信息
	PrintBuildVersionDetails()

	// EnqueueMetricsServerInit enqueues the metrics component.
	EnqueueMetricsServerInit()

	// EnqueueTracer enqueues the Tracer component.
	EnqueueTracer()

	// Module enables setting up dependencies of the engine with the builder context
	Module(name string, f BuilderFunc) NodeBuilder

	// Component adds a new component to the node that conforms to the ReadyDoneAware
	// interface, and throws a Fatal() when an irrecoverable error is encountered.
	//
	// The ReadyDoneFactory may return either a `Component` or `ReadyDoneAware` instance.
	// In both cases, the object is started according to its interface when the node is run,
	// and the node will wait for the component to exit gracefully.
	Component(name string, f ReadyDoneFactory) NodeBuilder

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
	DependableComponent(name string, f ReadyDoneFactory, dependencies *DependencyList) NodeBuilder

	// RestartableComponent adds a new component to the node that conforms to the ReadyDoneAware
	// interface, and calls the provided error handler when an irrecoverable error is encountered.
	// Use RestartableComponent if the component is not critical to the node's safe operation and
	// can/should be independently restarted when an irrecoverable error is encountered.
	//
	// Any irrecoverable errors thrown by the component will be passed to the provided error handler.
	RestartableComponent(name string, f ReadyDoneFactory, errorHandler component.OnError) NodeBuilder

	// ShutdownFunc adds a callback function that is called after all components have exited.
	// All shutdown functions are called regardless of errors returned by previous callbacks. Any
	// errors returned are captured and passed to the caller.
	ShutdownFunc(fn func() error) NodeBuilder

	// AdminCommand registers a new admin command with the admin server
	AdminCommand(command string, f func(config *NodeConfig) commands.AdminCommand) NodeBuilder

	// Build finalizes the node configuration in preparation for start and returns a Node
	// object that can be run
	Build() (Node, error)

	// PreInit registers a new PreInit function.
	// PreInit functions run before the protocol state is initialized or any other modules or components are initialized
	PreInit(f BuilderFunc) NodeBuilder

	// PostInit registers a new PreInit function.
	// PostInit functions run after the protocol state has been initialized but before any other modules or components
	// are initialized
	PostInit(f BuilderFunc) NodeBuilder

	// RegisterBadgerMetrics registers all badger related metrics
	RegisterBadgerMetrics() error

	// ValidateFlags sets any custom validation rules for the command line flags,
	// for example where certain combinations aren't allowed
	ValidateFlags(func() error) NodeBuilder
}

// DependencyList is a slice of ReadyDoneAware implementations that are used by DependableComponent
// to define the list of dependencies that must be ready before starting the component.
type DependencyList struct {
	components []module.ReadyDoneAware
}

func NewDependencyList(components ...module.ReadyDoneAware) *DependencyList {
	return &DependencyList{
		components: components,
	}
}

// Add adds a new ReadyDoneAware implementation to the list of dependencies.
func (d *DependencyList) Add(component module.ReadyDoneAware) {
	d.components = append(d.components, component)
}
