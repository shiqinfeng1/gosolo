package main

import (
	"gosolo/cmd"
	"gosolo/module"

	"github.com/spf13/pflag"
)

func main() {
	// 生产一个节点构造器的实例
	nodeBuilder := cmd.App("app1")
	nodeBuilder.ExtraFlags(func(flags *pflag.FlagSet) {

	})

	// 初始化
	if err := nodeBuilder.Initialize(); err != nil {
		nodeBuilder.Logger.Fatal().Err(err).Send()
	}

	nodeBuilder.
		Module("message validators", func(node *cmd.NodeConfig) error {
			return nil
		}).
		Component("RPC engine", func(node *cmd.NodeConfig) (module.ReadyDoneAware, error) {
			// rpcEng, err := engine.New(node.EngineRegistry, node.Logger, node.Me, node.State, rpcConf)
			return nil, nil
		})

	node, err := nodeBuilder.Build()
	if err != nil {
		nodeBuilder.Logger.Fatal().Err(err).Send()
	}
	node.Run()
}
