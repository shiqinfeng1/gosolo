# syntax = docker/dockerfile:experimental
# NOTE: 必须在仓库的根目录下运行。上面语句是为了使用buildkit的功能

####################################
## (1) Setup the build environment
## (1) 设置编译环境。
FROM dockerproxy.com/library/golang:1.20-bullseye AS build-setup

RUN apt-get update 
# cmake 用于下面加密库的编译，如果不许哟啊编译，则不用安装cmake， zip用于在镜像中打包文件
RUN apt-get install cmake zip -y   

## (2) Setup crypto dependencies
FROM build-setup AS build-env

# 在 /app 中编译程序
RUN mkdir /app
WORKDIR /app

# 下面定义的ARG是docker命令可以传入的参数变量，例如 docker --build-arg VERSION=$(IMAGE_TAG) --build-arg GOPRIVATE=$(GOPRIVATE)
ARG TARGET
ARG COMMIT
ARG VERSION
# ENV 和 ARG 的区别是，ARG只能在编译镜像时生效，ENV变量只能在容器运行时生效
ENV GOPRIVATE=

# 把当前目录(根目录)下的所有文件和目录复制到/app下
COPY . .

# 在容器中编译加密库，编译出来的是静态库，在编译go的app时静态链接到app中： #cgo LDFLAGS: -L${SRCDIR}/relic/build/lib -l relic_s
# --mount=type=cache,sharing=locked,target=/go/pkg/mod 表示挂载一个缓存到容器目录/go/pkg/mod，locked表示串行访问，不能并发访问
RUN --mount=type=cache,sharing=locked,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=secret,id=git_creds,dst=/root/.netrc \
    make crypto_setup

####################################
## (3) Build the production app binary
FROM build-env as build-production
WORKDIR /app

ARG GOARCH=amd64

# TAGS can be overriden to modify the go build tags (e.g. build without netgo)
ARG TAGS="relic,netgo"

# Keep Go's build cache between builds.
# https://github.com/golang/go/issues/27719#issuecomment-514747274
# -X：设定包中string类型变量的值，一般是设置版本信息
# -tags： 编译控制，带有对应的tag的文件才会会被编译, 例如 // +build relic
# 以静态链接的方式，使用c密码库: 
# 1. 在代码中注释：// #cgo LDFLAGS: -L${SRCDIR}/relic/build/lib -l relic_s  
# 2. 在编译选项中添加： -extldflags -static
RUN --mount=type=cache,sharing=locked,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=secret,id=git_creds,dst=/root/.netrc \
    GOPROXY='https://goproxy.cn,direct' CGO_ENABLED=1 GOOS=linux go build --tags "${TAGS}" -ldflags "-extldflags -static \
    -X 'gosolo/cmd/build.commit=${COMMIT}' -X  'gosolo/cmd/build.semver=${VERSION}'" \
    -o ./app ${TARGET}

RUN chmod a+x /app/app

## (4) Add the statically linked production binary to a distroless image
# distroless是使用libc的最小镜像
FROM gcr.dockerproxy.com/distroless/base-debian11 as production

COPY --from=build-production /app/app /bin/app
# 指定容器运行后的执行命令
ENTRYPOINT ["/bin/app"]

####################################
## (3) Build the debug app binary
# -gcflags "all=-N -l" ： 禁止编译优化
FROM build-env as build-debug
WORKDIR /app
ARG GOARCH=amd64
RUN --mount=type=ssh \
    --mount=type=cache,sharing=locked,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux go build --tags "relic,netgo" -ldflags "-extldflags -static \
    -X 'gosolo/cmd/build.commit=${COMMIT}' -X  'gosolo/cmd/build.semver=${VERSION}'" \
    -gcflags="all=-N -l" -o ./app ${TARGET}

RUN chmod a+x /app/app

## (4) Add the statically linked debug binary to a distroless image configured for debugging
FROM golang:1.20-bullseye as debug

RUN go install github.com/go-delve/delve/cmd/dlv@latest

COPY --from=build-debug /app/app /bin/app

# --后面可以个app传递参数
# 前面的参数用于启动远程调试
# exec命令将使Delve执行二进制文件，并立即附加到它，开始一个新的调试会话。
# 通过vscode或goland的远程调试的功能连接到该dlv会话，进行调试
ENTRYPOINT ["dlv", "--listen=:2345", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/bin/app", "--"]


FROM build-setup as environment-clean
