# The short Git commit hash
SHORT_COMMIT := $(shell git rev-parse --short HEAD)
BRANCH_NAME:=$(shell git rev-parse --abbrev-ref HEAD | tr '/' '-')
# The Git commit hash
COMMIT := $(shell git rev-parse HEAD)
# The tag of the current commit, otherwise empty
VERSION := $(shell git describe --tags --abbrev=2 --match "v*" --match "secure-cadence*" 2>/dev/null)

# By default, this will run all tests in all packages, but we have a way to override this in CI so that we can
# dynamically split up CI jobs into smaller jobs that can be run in parallel
GO_TEST_PACKAGES := ./...

# Image tag: if image tag is not set, set it with version (or short commit if empty)
ifeq (${IMAGE_TAG},)
IMAGE_TAG := ${VERSION}
endif

ifeq (${IMAGE_TAG},)
IMAGE_TAG := ${SHORT_COMMIT}
endif


# Name of the cover profile
COVER_PROFILE := coverage.txt
# Disable go sum database lookup for private repos
GOPRIVATE=github.com/dapperlabs/*
# OS
UNAME := $(shell uname)

# Used when building within docker
GOARCH := $(shell go env GOARCH)

# The location of the k8s YAML files
K8S_YAMLS_LOCATION_STAGING=./k8s/staging


# docker container registry
export CONTAINER_REGISTRY := gcr.io/flow-container-registry
export DOCKER_BUILDKIT := 1

.PHONY: check-go-version
check-go-version:
	@bash -c '\
		MINGOVERSION=1.18; \
		function ver { printf "%d%03d%03d%03d" $$(echo "$$1" | tr . " "); }; \
		GOVER=$$(go version | sed -rne "s/.* go([0-9.]+).*/\1/p" ); \
		if [ "$$(ver $$GOVER)" -lt "$$(ver $$MINGOVERSION)" ]; then \
			echo "go $$GOVER is too old. flow-go only supports go $$MINGOVERSION and up."; \
			exit 1; \
		else \
			echo "go $$GOVER is matched for build ."; \
		fi; \
		'

# setup the crypto package under the GOPATH: needed to test packages importing flow-go/crypto
.PHONY: crypto_setup
crypto_setup:
	bash crypto_setup.sh

.PHONY: cmd/app1
cmd/app1:
	go build -o cmd/app1/app cmd/app1/main.go

############################################################################################
# CAUTION: DO NOT MODIFY THESE TARGETS! DOING SO WILL BREAK THE FLAKY TEST MONITOR

.PHONY: unittest-main
unittest-main:
	# test all packages with Relic library enabled
	go test $(if $(VERBOSE),-v,) -coverprofile=$(COVER_PROFILE) -covermode=atomic $(if $(RACE_DETECTOR),-race,) $(if $(JSON_OUTPUT),-json,) $(if $(NUM_RUNS),-count $(NUM_RUNS),) --tags relic $(GO_TEST_PACKAGES)

.PHONY: install-mock-generators
install-mock-generators:
	cd ${GOPATH}; \
    go install github.com/vektra/mockery/v2@latest; \
    go install github.com/golang/mock/mockgen@latest;

.PHONY: install-tools
install-tools: crypto_setup check-go-version install-mock-generators
	cd ${GOPATH}; \
	go install github.com/golang/protobuf/protoc-gen-go@latest; \
	go install github.com/uber/prototool/cmd/prototool@latest; \
	go install github.com/gogo/protobuf/protoc-gen-gofast@latest; \
	go install golang.org/x/tools/cmd/stringer@master;

.PHONY: verify-mocks
verify-mocks: tidy generate-mocks
	git diff --exit-code

############################################################################################

.SILENT: go-math-rand-check
go-math-rand-check:
	# check that the insecure math/rand Go package isn't used by production code.
	# `exclude` should only specify non production code (test, bench..).
	# If this check fails, try updating your code by using:
	#   - "crypto/rand" or "flow-go/utils/rand" for non-deterministic randomness
	#   - "flow-go/crypto/random" for deterministic randomness
	grep --include=\*.go \
	--exclude=*test* --exclude=*helper* --exclude=*example* --exclude=*fixture* --exclude=*benchmark* --exclude=*profiler* \
    --exclude-dir=*test* --exclude-dir=*helper* --exclude-dir=*example* --exclude-dir=*fixture* --exclude-dir=*benchmark* --exclude-dir=*profiler* -rnw '"math/rand"'; \
    if [ $$? -ne 1 ]; then \
       echo "[Error] Go production code should not use math/rand package"; exit 1; \
    fi

.PHONY: code-sanity-check
code-sanity-check: go-math-rand-check 

.PHONY: test
test: verify-mocks unittest-main

.PHONY: integration-test
integration-test: docker-build-flow
	$(MAKE) -C integration integration-test

.PHONY: benchmark
benchmark: docker-build-flow
	$(MAKE) -C integration benchmark

.PHONY: coverage
coverage:
ifeq ($(COVER), true)
	# Cover summary has to produce cover.json
	COVER_PROFILE=$(COVER_PROFILE) ./cover-summary.sh
	# file has to be called index.html
	gocov-html cover.json > index.html
	# coverage.zip will automatically be picked up by teamcity
	zip coverage.zip index.html
endif

.PHONY: generate-openapi
generate-openapi:
	swagger-codegen generate -l go -i https://raw.githubusercontent.com/onflow/flow/master/openapi/access.yaml -D packageName=models,modelDocs=false,models -o engine/access/rest/models;
	go fmt ./engine/access/rest/models

.PHONY: generate
generate: generate-proto generate-mocks 

.PHONY: generate-proto
generate-proto:
	prototool generate protobuf

.PHONY: generate-mocks
generate-mocks: install-mock-generators
	mockery --name '(Connector|PingInfoProvider)' --dir=network/p2p --case=underscore --output="./network/mocknetwork" --outpkg="mocknetwork"
	mockgen -destination=storage/mocks/storage.go -package=mocks github.com/onflow/flow-go/storage Blocks,Headers,Payloads,Collections,Commits,Events,ServiceEvents,TransactionResults
	mockgen -destination=module/mocks/network.go -package=mocks github.com/onflow/flow-go/module Local,Requester
	mockgen -destination=network/mocknetwork/mock_network.go -package=mocknetwork github.com/onflow/flow-go/network EngineRegistry
	mockery --name='.*' --dir=integration/benchmark/mocksiface --case=underscore --output="integration/benchmark/mock" --outpkg="mock"
	
	#temporarily make insecure/ a non-module to allow mockery to create mocks
	mv insecure/go.mod insecure/go2.mod
	mockery --name '.*' --dir=insecure/ --case=underscore --output="./insecure/mock"  --outpkg="mockinsecure"
	mv insecure/go2.mod insecure/go.mod

# this ensures there is no unused dependency being added by accident
.PHONY: tidy
tidy:
	go mod tidy -v
	cd integration; go mod tidy -v
	cd crypto; go mod tidy -v
	git diff --exit-code

.PHONY: lint
lint: tidy
	# revive -config revive.toml -exclude storage/ledger/trie ./...
	golangci-lint run -v --build-tags relic ./...

.PHONY: fix-lint
fix-lint:
	# revive -config revive.toml -exclude storage/ledger/trie ./...
	golangci-lint run -v --build-tags relic --fix ./...

# Runs unit tests with different list of packages as passed by CI so they run in parallel
.PHONY: ci
ci: install-tools test

# Runs integration tests
.PHONY: ci-integration
ci-integration: crypto_setup
	$(MAKE) -C integration ci-integration-test

# Runs benchmark tests
# NOTE: we do not need `docker-build-flow` as this is run as a separate step
# on Teamcity
.PHONY: ci-benchmark
ci-benchmark: install-tools
	$(MAKE) -C integration ci-benchmark

# Runs unit tests, test coverage, lint in Docker (for mac)
.PHONY: docker-ci
docker-ci:
	docker run --env RACE_DETECTOR=$(RACE_DETECTOR) --env COVER=$(COVER) --env JSON_OUTPUT=$(JSON_OUTPUT) \
		-v /run/host-services/ssh-auth.sock:/run/host-services/ssh-auth.sock -e SSH_AUTH_SOCK="/run/host-services/ssh-auth.sock" \
		-v "$(CURDIR)":/go/flow -v "/tmp/.cache":"/root/.cache" -v "/tmp/pkg":"/go/pkg" \
		-w "/go/flow" "$(CONTAINER_REGISTRY)/golang-cmake:v0.0.7" \
		make ci

# Runs integration tests in Docker  (for mac)
.PHONY: docker-ci-integration
docker-ci-integration:
	rm -rf crypto/relic
	docker run \
		--env DOCKER_API_VERSION='1.39' \
		--network host \
		-v "$(CURDIR)":/go/flow -v "/tmp/.cache":"/root/.cache" -v "/tmp/pkg":"/go/pkg" \
		-v /tmp:/tmp \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v /run/host-services/ssh-auth.sock:/run/host-services/ssh-auth.sock -e SSH_AUTH_SOCK="/run/host-services/ssh-auth.sock" \
		-w "/go/flow" "$(CONTAINER_REGISTRY)/golang-cmake:v0.0.7" \
		make ci-integration

.PHONY: docker-build-app1
docker-build-app1:
	docker build -f cmd/Dockerfile  --build-arg TARGET=./cmd/app1 --build-arg COMMIT=$(COMMIT)  --build-arg VERSION=$(IMAGE_TAG) --build-arg GOARCH=$(GOARCH) --target production \
		--secret id=git_creds,env=GITHUB_CREDS --build-arg GOPRIVATE=$(GOPRIVATE) \
		--label "git_commit=${COMMIT}" --label "git_tag=${IMAGE_TAG}" \
		-t "$(CONTAINER_REGISTRY)/app1:latest" -t "$(CONTAINER_REGISTRY)/app1:$(SHORT_COMMIT)" -t "$(CONTAINER_REGISTRY)/app1:$(IMAGE_TAG)"  .

.PHONY: docker-build-app1-debug
docker-build-app1-debug:
	docker build -f cmd/Dockerfile  --build-arg TARGET=./cmd/app1 --build-arg COMMIT=$(COMMIT)  --build-arg VERSION=$(IMAGE_TAG) --build-arg GOARCH=$(GOARCH) --target debug \
		-t "$(CONTAINER_REGISTRY)/app1-debug:latest" -t "$(CONTAINER_REGISTRY)/app1-debug:$(SHORT_COMMIT)" -t "$(CONTAINER_REGISTRY)/app1-debug:$(IMAGE_TAG)" .


PHONY: tool-bootstrap
tool-bootstrap: docker-build-bootstrap
	docker container create --name bootstrap $(CONTAINER_REGISTRY)/bootstrap:latest;docker container cp bootstrap:/bin/app ./bootstrap;docker container rm bootstrap

PHONY: tool-transit
tool-transit: docker-build-bootstrap-transit
	docker container create --name transit $(CONTAINER_REGISTRY)/bootstrap-transit:latest;docker container cp transit:/bin/app ./transit;docker container rm transit

.PHONY: docker-build-app
docker-build-app: docker-build-app1 

.PHONY: docker-push-app1
docker-push-app1:
	docker push "$(CONTAINER_REGISTRY)/app1:$(SHORT_COMMIT)"
	docker push "$(CONTAINER_REGISTRY)/app1:$(IMAGE_TAG)"

.PHONY: docker-push-app
docker-push-app: docker-push-app1 

.PHONY: docker-run-app1
docker-run-app1:
	docker run -p 8080:8080 -p 3569:3569 "$(CONTAINER_REGISTRY)/app1:latest" --nodeid 1234567890123456789012345678901234567890123456789012345678901234 --entries app1-1234567890123456789012345678901234567890123456789012345678901234@localhost:3569=1000


PHONY: docker-all-tools
docker-all-tools: tool-util tool-remove-execution-fork

PHONY: docker-build-util
docker-build-util:
	docker build -f cmd/Dockerfile --build-arg TARGET=./cmd/util --build-arg GOARCH=$(GOARCH) --target production \
		-t "$(CONTAINER_REGISTRY)/util:latest" -t "$(CONTAINER_REGISTRY)/util:$(SHORT_COMMIT)" -t "$(CONTAINER_REGISTRY)/util:$(IMAGE_TAG)" .

PHONY: tool-util
tool-util: docker-build-util
	docker container create --name util $(CONTAINER_REGISTRY)/util:latest;docker container cp util:/bin/app ./util;docker container rm util

#----------------------------------------------------------------------
# CD COMMANDS
#----------------------------------------------------------------------

.PHONY: deploy-staging
deploy-staging: update-deployment-image-name-staging apply-staging-files monitor-rollout

# Staging YAMLs must have 'staging' in their name.
.PHONY: apply-staging-files
apply-staging-files:
	kconfig=$$(uuidgen); \
	echo "$$KUBECONFIG_STAGING" > $$kconfig; \
	files=$$(find ${K8S_YAMLS_LOCATION_STAGING} -type f \( --name "*.yml" -or --name "*.yaml" \)); \
	echo "$$files" | xargs -I {} kubectl --kubeconfig=$$kconfig apply -f {}

# Deployment YAMLs must have 'deployment' in their name.
.PHONY: update-deployment-image-name-staging
update-deployment-image-name-staging: CONTAINER=flow-test-net
update-deployment-image-name-staging:
	@files=$$(find ${K8S_YAMLS_LOCATION_STAGING} -type f \( --name "*.yml" -or --name "*.yaml" \) | grep deployment); \
	for file in $$files; do \
		patched=`openssl rand -hex 8`; \
		node=`echo "$$file" | grep -oP 'flow-\K\w+(?=-node-deployment.yml)'`; \
		kubectl patch -f $$file -p '{"spec":{"template":{"spec":{"containers":[{"name":"${CONTAINER}","image":"$(CONTAINER_REGISTRY)/'"$$node"':${IMAGE_TAG}"}]}}}}`' --local -o yaml > $$patched; \
		mv -f $$patched $$file; \
	done

.PHONY: monitor-rollout
monitor-rollout:
	kconfig=$$(uuidgen); \
	echo "$$KUBECONFIG_STAGING" > $$kconfig; \
	kubectl --kubeconfig=$$kconfig rollout status statefulsets.apps flow-collection-node-v1; \
	kubectl --kubeconfig=$$kconfig rollout status statefulsets.apps flow-app1-node-v1; \
	kubectl --kubeconfig=$$kconfig rollout status statefulsets.apps flow-execution-node-v1; \
	kubectl --kubeconfig=$$kconfig rollout status statefulsets.apps flow-verification-node-v1
