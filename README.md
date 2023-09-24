
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


### 默认配置

`congfig` 包负责处理默认配置和命令行参数的解析。
项目自带一个默认配置文件 `default-config.yml` ，该文件以静态资源嵌入的方式存储在全局变量中。
在`init`时读取默认配置文件 `default-config.yml` 的数据到viper

### 通用配置

- `BaseConfig` 保存公共通用配置和通用的基础功能
  - 配置字段可以全局定义， 也可以各个模块自定义
  - 配置来源：
   1. 命令行参数；
   2. yaml文件；
  - 
## app构造器 `AppBuilder`

- app构造器实现了 `NodeBuilder` 接口，该接口在`node_builder.go`中定义
- 

# 文件目录说明

1. cmd是app的入口汇总
   1. cmd下的目录是app入口，有几个app就建几个目录，例如app1，app2
   2. cmd下的go文件是脚手架代码



## infrastructure

一些和业务逻辑无关的基础设施，可以独立出来的，包括网络通信、数据存储等独立的基础设施