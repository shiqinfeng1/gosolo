# proto管理工具介绍

buf 是一个管理protobuf文件的工具，使用步骤如下：
操作之前需要安装一些工具： 
    ```
    go install \
    go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway \
    github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2 \
    google.golang.org/protobuf/cmd/protoc-gen-go \
    google.golang.org/grpc/cmd/protoc-gen-go-grpc
    ```

1. 安装buf： 
    ```
    GO111MODULE=on GOBIN=/usr/local/bin go install github.com/bufbuild/buf/cmd/buf@v1.18.0
    ```

2. 在需要proto管理的目录中。例如本admin， 执行 `buf mod init` ， 会生成bug.yaml文件
3. 执行 `buf mod update`， 生成 buf.lock 文件
4. 执行 `buf generate --template ./buf.gen.yaml . -v`

执行成功后，在admin.proto所在的目录下生成pb.go文件，以及swagger文件

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
