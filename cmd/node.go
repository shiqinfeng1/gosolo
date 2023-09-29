package cmd

import (
	"context"
	"gosolo/module/component"
	"gosolo/module/irrecoverable"
	"gosolo/module/util"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
)

// 节点也作为一个组件实现
var _ component.Component = (*FlowNodeImp)(nil)

// node也作为一个组件
type Node interface {
	component.Component

	// Run initiates all common components (logger, database etc.)
	// then starts each component. It also sets up a channel to gracefully shut
	// down each component if a SIGINT is received.
	// Run负责初始化所有一般的组件(日志，数据库等)，然后启动各个组件，同时需要捕获中断信号，并优雅地关闭各个组件
	Run()
}

// FlowNodeImp is created by the FlowNodeBuilder with all components ready to be started.
// The Run function starts all the components, and is blocked until either a termination
// signal is received or a irrecoverable error is encountered.
type FlowNodeImp struct {
	component.Component
	*NodeConfig
	logger       zerolog.Logger
	postShutdown func() error
	fatalHandler func(error)
}

// NewNode returns a new node instance
// 逐渐管理器作为组件component传入，
func NewNode(component component.Component, cfg *NodeConfig, logger zerolog.Logger, cleanup func() error, handleFatal func(error)) Node {
	return &FlowNodeImp{
		Component:    component,
		NodeConfig:   cfg,
		logger:       logger,
		postShutdown: cleanup,
		fatalHandler: handleFatal,
	}
}

// Run starts all the node's components, then blocks until a SIGINT or SIGTERM is received, at
// which point it gracefully shuts down.
// Any unhandled irrecoverable errors thrown in child components will propagate up to here and
// result in a fatal error.
// 运行节点，即运行节点的所有组件
func (node *FlowNodeImp) Run() {
	// Cancelling this context notifies all child components that it's time to shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Block until node is shutting down
	err := node.run(ctx, cancel)

	// Any error received is considered fatal.
	if err != nil {
		node.fatalHandler(err)
		return
	}

	// Run post shutdown cleanup logic
	err = node.postShutdown()

	// Since this occurs after all components have stopped, it is not considered fatal
	if err != nil {
		node.logger.Error().Err(err).Msg("error encountered during cleanup")
	}

	node.logger.Info().Msgf("%s node shutdown complete", node.config.NodeRole)
}

// run starts the node and blocks until a SIGINT/SIGTERM is received or an error is encountered.
// It returns:
//   - nil if a termination signal is received, and all components have been gracefully stopped.
//   - error if a irrecoverable error is received
func (node *FlowNodeImp) run(ctx context.Context, shutdown context.CancelFunc) error {
	// Components will pass unhandled irrecoverable errors to this channel via signalerCtx (or a
	// child context). Any errors received on this channel should halt the node.
	signalerCtx, errChan := irrecoverable.WithSignaler(ctx)

	// This context will be marked done when SIGINT/SIGTERM is received.
	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)

	// 1: Start up
	// Start all the components
	node.Start(signalerCtx)

	// Log when all components have been started
	// 在routine中等待节点启动完成，完成后无往外处理，只输出打印
	go func() {
		select {
		case <-node.Ready():
			node.logger.Info().
				Msgf("%s node startup complete", node.config.NodeRole)
		case <-ctx.Done():
		}
	}()

	// 2: Run the node
	// Block here until either a signal or irrecoverable error is received.
	err := util.WaitError(errChan, sigCtx.Done())

	// Stop relaying signals. Subsequent signals will be handled by the OS and will abort the
	// process.
	stop()

	// If an irrecoverable error was received, abort
	if err != nil {
		return err
	}

	// 3: Shut down
	// Send shutdown signal to components
	node.logger.Info().Msgf("%s node shutting down", node.config.NodeRole)
	shutdown()

	// Block here until all components have stopped or an irrecoverable error is received.
	return util.WaitError(errChan, node.Done())
}
