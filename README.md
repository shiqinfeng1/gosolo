
# gosolo

一个单体程序的文件和代码框架

# 主流程

1. 生成一个app的脚手架
   1. ` App(role string, opts ...Option) *AppBuilder `  返回app构造器
      1. 通过`DefaultBaseConfig()`生成一个基础配置的实例：`BaseConfig`。包括了全局配置，各模块自定义配置
      2. 生成一个节点配置实例：`NodeConfig`，其中包含了`BaseConfig`
      3. 生成app构造器实例：`AppBuilder`
   2. (可选)添加额外的命令行参数配置
2. 初始化
   1. 通过构造器AppBuilder的Logger打印版本信息：`PrintBuildVersionDetails(...)`
   2. 导出viper中的配置到 `YamlConfig`  (在init时已经加载了默认配置)
   3. 映射和解析命令行参数： `InitializePFlagSet(...)`
3. 添加组件和模块
4. 启动允许

## 配置

- 配置数据保存在`appBuilder`的`NodeConfig.BaseConfig`中
- `appBuilder`中的flags字段解析和保存命令行参数
配置初始化的过程:
1. 项目自带一个默认配置文件 `default-config.yml` ，该文件以静态资源嵌入的方式存储在全局变量中，在`init`时读取默认配置文件 `default-config.yml` 的数据到viper
2. 代码中自带一个`DefaultBaseConfig`，设置了`BaseConfig`的默认值
3. 构造appBuilder时，读取`DefaultBaseConfig`, 然后通过opts选项模式修改默认值， 更新后保存默认配置到`appBuilder.NodeConfig.BaseConfig`
4. 设置应用需要的额外参数， 这些参数是各个应用特有的，不是通用的
5. 把yaml中的默认配置读取到flags中
6. 把`appBuilder.NodeConfig.BaseConfig`中的字段和命令行参数关联起来
7. 解析命令行参数
8. 检查命令行参数是否带有`--config-file`，如果有，那么把`--config-file`指定的配置读入到viper，覆盖默认的yaml配置，并更新`BaseConfig.YamlConfig`；如果没有，也把命令行参数绑定到viper的字段中，并设置去掉前缀的参数名称


## 生产环境性能剖析器 pprof


## 运行指标观测 prometheus

## 链路跟踪 otel

# 文件目录说明

1. cmd是app的入口汇总
   1. cmd下的目录是app入口，有几个app就建几个目录，例如app1，app2
   2. cmd下的go文件是脚手架代码



## infrastructure

一些和业务逻辑无关的基础设施，可以独立出来的，包括网络通信、数据存储等独立的基础设施