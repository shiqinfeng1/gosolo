# 管理员工具介绍

## Intro

Admin tool 动态修改配置，无需重启节点，比如修改log等级

## 用法

### 列出所有命令

```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "list-commands"}'
```

### 修改日志级别

Flow, and other zerolog-based libraries:

```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "set-log-level", "data": "debug"}'
```

libp2p, badger, and other golog-based libraries:

```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "set-golog-level", "data": "debug"}'
```

#### To get a list of all updatable configs

```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "list-configs"}'
```

### To get a config value

```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "get-config", "data": "consensus-required-approvals-for-sealing"}'
```

### To set a config value

#### Example: enable the auto-profiler

```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "set-config", "data": {"profiler-enabled": true}}'
```

#### Example: manually trigger the auto-profiler for 1 minute

```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "set-config", "data": {"profiler-trigger": "1m"}}'
```
