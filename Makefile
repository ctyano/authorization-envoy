ifeq ($(APP_NAME),)
APP_NAME := $(shell basename $(shell pwd))
endif

ifeq ($(DOCKER_TAG),)
DOCKER_TAG := :latest
endif
ifneq ($(VERSION),)
DOCKER_TAG := :v$(VERSION)
endif
ifeq ($(ENVOY_VERSION),)
ENVOY_VERSION := $(shell curl -s https://api.github.com/repos/envoyproxy/envoy/releases | jq -r .[].tag_name | sort -rV | head -n1)
ifeq ($(ENVOY_VERSION),)
$(error Failed to determine ENVOY_VERSION from GitHub API. Please set it manually.)
endif
endif

ifeq ($(PATCH),)
PATCH := true
endif

ifeq ($(PUSH),)
PUSH := true
endif
ifeq ($(PUSH),true)
PUSH_OPTION := --push
endif

BUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
VCS_REF=$(shell cd $(SUBMODULE_NAME) && git rev-parse --short HEAD)

ifeq ($(XPLATFORMS),)
XPLATFORMS := linux/amd64,linux/arm64
endif
XPLATFORM_ARGS := --platform=$(XPLATFORMS)

BUILD_ARG := --build-arg 'BUILD_DATE=$(BUILD_DATE)' --build-arg 'VCS_REF=$(VCS_REF)' --build-arg 'VERSION=$(VERSION)' --build-arg 'ENVOY_VERSION=$(ENVOY_VERSION)'

ifeq ($(DOCKER_REGISTRY_OWNER),)
DOCKER_REGISTRY_OWNER=ctyano
endif

ifeq ($(DOCKER_REGISTRY),)
DOCKER_REGISTRY=ghcr.io/$(DOCKER_REGISTRY_OWNER)/
endif

ifeq ($(DOCKER_CACHE),)
DOCKER_CACHE=false
endif

.PHONY: buildx

.SILENT: version

build:
	IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME)$(DOCKER_TAG); \
	LATEST_IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME):latest; \
	DOCKERFILE_PATH=./Dockerfile; \
	test $(DOCKER_CACHE) && DOCKER_CACHE_OPTION="--cache-from $$IMAGE_NAME"; \
	docker build $(BUILD_ARG) $$DOCKER_CACHE_OPTION -t $$IMAGE_NAME -t $$LATEST_IMAGE_NAME -f $$DOCKERFILE_PATH .

buildx:
	IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME)$(DOCKER_TAG); \
	LATEST_IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME):latest; \
	DOCKERFILE_PATH=./Dockerfile; \
	DOCKER_BUILDKIT=1 docker buildx build $(BUILD_ARG) $(XPLATFORM_ARGS) $(PUSH_OPTION) --cache-from $$IMAGE_NAME -t $$IMAGE_NAME -t $$LATEST_IMAGE_NAME -f $$DOCKERFILE_PATH .

mirror-amd64-images:
	IMAGE=$(APP_NAME); docker pull --platform linux/amd64 ghcr.io/ctyano/$$IMAGE:latest && docker tag ghcr.io/ctyano/$$IMAGE:latest docker.io/tatyano/$$IMAGE:latest && docker push docker.io/tatyano/$$IMAGE:latest

install-golang:
	which go \
|| (curl -sf https://webi.sh/golang | sh \
&& ~/.local/bin/pathman add ~/.local/bin)

patch:
	$(PATCH) && rsync -av --exclude=".gitkeep" patchfiles/* $(SUBMODULE_NAME)

clean: #checkout

diff:
	@diff $(SUBMODULE_NAME) patchfiles

checkout:
	@cd $(SUBMODULE_NAME)/ && git checkout .

submodule-update: checkout
	@git submodule update --init --remote

checkout-version: submodule-update
	@cd $(SUBMODULE_NAME)/ && git fetch --refetch --tags origin && git checkout v$(VERSION)

version:
	@echo "Version: $(VERSION)"
	@echo "Tag Version: v$(VERSION)"

install-pathman:
	test -e ~/.local/bin/pathman \
|| curl -sf https://webi.sh/pathman | sh

install-jq: install-pathman
	which jq \
|| (curl -sf https://webi.sh/jq | sh \
&& ~/.local/bin/pathman add ~/.local/bin)

install-yq: install-pathman
	which yq \
|| (curl -sf https://webi.sh/yq | sh \
&& ~/.local/bin/pathman add ~/.local/bin)

install-step: install-pathman
	which step \
|| (STEP_VERSION=$$(curl -sf https://api.github.com/repos/smallstep/cli/releases | jq -r .[].tag_name | grep -E '^v[0-9]*.[0-9]*.[0-9]*$$' | head -n1 | sed -e 's/.*v\([0-9]*.[0-9]*.[0-9]*\).*/\1/g') \
; curl -fL "https://github.com/smallstep/cli/releases/download/v$${STEP_VERSION}/step_$(GOOS)_$${STEP_VERSION}_$(GOARCH).tar.gz" | tar -xz -C ~/.local/bin/ \
&& ln -sf ~/.local/bin/step_$${STEP_VERSION}/bin/step ~/.local/bin/step \
&& ~/.local/bin/pathman add ~/.local/bin)

install-kustomize: install-pathman
	which kustomize \
|| (cd ~/.local/bin \
&& curl "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash \
&& ~/.local/bin/pathman add ~/.local/bin)

install-parsers: install-jq install-yq install-step

