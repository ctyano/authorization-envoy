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
	test -x "$$HOME/.local/bin/pathman" \
|| curl -fsSL https://webi.sh/pathman | sh ; \
printf '%s\n' ":$$PATH:" | grep -q "$$HOME/.local/bin" \
|| export PATH="$$PATH:$$HOME/.local/bin"

install-jq: install-pathman
	which jq \
|| (curl -sf https://webi.sh/jq | sh \
&& ~/.local/bin/pathman add ~/.local/bin \
|| export PATH="$$PATH:$$HOME/.local/bin")

install-yq: install-pathman
	which yq \
|| (curl -sf https://webi.sh/yq | sh \
&& ~/.local/bin/pathman add ~/.local/bin \
|| export PATH="$$PATH:$$HOME/.local/bin")

install-step: install-pathman
	which step \
|| (STEP_VERSION=$$(curl -sf https://api.github.com/repos/smallstep/cli/releases | jq -r .[].tag_name | grep -E '^v[0-9]*.[0-9]*.[0-9]*$$' | head -n1 | sed -e 's/.*v\([0-9]*.[0-9]*.[0-9]*\).*/\1/g') \
; curl -fL "https://github.com/smallstep/cli/releases/download/v$${STEP_VERSION}/step_$(GOOS)_$${STEP_VERSION}_$(GOARCH).tar.gz" | tar -xz -C ~/.local/bin/ \
&& ln -sf ~/.local/bin/step_$${STEP_VERSION}/bin/step ~/.local/bin/step \
&& ~/.local/bin/pathman add ~/.local/bin \
|| export PATH="$$PATH:$$HOME/.local/bin")

install-kustomize: install-pathman
	which kustomize \
|| (cd ~/.local/bin \
&& curl "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash \
&& ~/.local/bin/pathman add ~/.local/bin \
|| export PATH="$$PATH:$$HOME/.local/bin")

install-parsers: install-jq install-yq install-step


kind-setup:
	kind create cluster

kind-load-images:
	kubectl config get-contexts kind-kind --no-headers=true | grep -E "^\* +kind-kind"
	kind load docker-image \
		docker.io/ghostunnel/ghostunnel:latest \
		$(DOCKER_REGISTRY)crypki-softhsm:latest \
		$(DOCKER_REGISTRY)certsigner-envoy:latest \
		$(DOCKER_REGISTRY)athenz_user_cert:latest \
		$(DOCKER_REGISTRY)athenz-plugins:latest
	kind load docker-image \
		$(DOCKER_REGISTRY)athenz-db:latest \
		$(DOCKER_REGISTRY)athenz-zms-server:latest \
		$(DOCKER_REGISTRY)athenz-zts-server:latest \
		$(DOCKER_REGISTRY)athenz-cli:latest \
		$(DOCKER_REGISTRY)athenz-ui:latest
	kind load docker-image \
		docker.io/ealen/echo-server:latest \
		docker.io/dexidp/dex:latest \
		docker.io/envoyproxy/envoy:v1.34-latest \
		docker.io/openpolicyagent/kube-mgmt:latest \
		docker.io/openpolicyagent/opa:latest-static \
		docker.io/portainer/kubectl-shell:latest \
		$(DOCKER_REGISTRY)k8s-athenz-sia:latest \
		$(DOCKER_REGISTRY)docker-vegeta:latest \
		docker.io/tatyano/authorization-proxy:latest

kind-shutdown:
	kind delete cluster

load-docker-images:
	docker pull docker.io/ghostunnel/ghostunnel:latest
	docker pull $(DOCKER_REGISTRY)crypki-softhsm:latest
	docker pull $(DOCKER_REGISTRY)athenz_user_cert:latest
	docker pull docker.io/ealen/echo-server:latest
	docker pull docker.io/dexidp/dex:latest

load-kubernetes-images:
	kubectl config get-contexts kind-kind --no-headers=true | grep -E "^\* +kind-kind"
	kind load docker-image \
		docker.io/ghostunnel/ghostunnel:latest \
		$(DOCKER_REGISTRY)crypki-softhsm:latest \
		$(DOCKER_REGISTRY)$(APP_NAME):latest \
		$(DOCKER_REGISTRY)athenz_user_cert:latest \
		docker.io/ealen/echo-server:latest \
		docker.io/dexidp/dex:latest

deploy-kubernetes-manifests: generate-certificates copy-certificates-to-kustomization
	kubectl apply -k kustomize

test-kubernetes-authorization-envoy:
	SLEEP_SECONDS=5; \
WAITING_THRESHOLD=60; \
i=0; \
while true; do \
	printf "\n***** Waiting for crypki($$(( $$i * $${SLEEP_SECONDS} ))s/$${WAITING_THRESHOLD}s) *****\n"; \
	( \
	test $$(( $$(kubectl -n athenz get all | grep authorization-envoy | grep -E "0/1" | wc -l) )) -eq 0 \
	&& \
	kubectl -n athenz exec deployment/authorization-envoy -it -c athenz-cli -- \
		curl \
			-s \
			--fail \
			--cert \
			/opt/crypki/tls-crt/client.crt \
			--key \
			/opt/crypki/tls-crt/client.key \
			--cacert \
			/opt/crypki/tls-crt/ca.crt \
			--resolve \
			localhost:4443:127.0.0.1 \
			https://localhost:4443/ruok \
	) \
	&& break \
	|| echo "Waiting for Crypki SoftHSM Server..."; \
	sleep $${SLEEP_SECONDS}; \
	i=$$(( i + 1 )); \
	if [ $$i -eq $$(( $${WAITING_THRESHOLD} / $${SLEEP_SECONDS} )) ]; then \
		printf "\n\n** Waiting ($$(( $$i * $${SLEEP_SECONDS} ))s) reached to threshold($${WAITING_THRESHOLD}s) **\n\n"; \
		kubectl -n athenz get all | grep -E "pod/authorization-envoy-" | sed -e 's/^\(pod\/[^ ]*\) *[0-9]\/[0-9].*/\1/g' | xargs -I%% kubectl -n athenz logs %% --all-containers=true ||:; \
		kubectl -n athenz get all | grep -E "pod/authorization-envoy-" | sed -e 's/^\(pod\/[^ ]*\) *[0-9]\/[0-9].*/\1/g' | xargs -I%% kubectl -n athenz describe %% ||:; \
		kubectl -n athenz get all; \
		exit 1; \
	fi; \
done
	kubectl -n athenz get all
	@echo ""
	@echo "**************************************"
	@echo "***  Crypki provisioning successful **"
	@echo "**************************************"
	@echo ""

clean-certificates:
	rm -rf keys certs

generate-ca:
	mkdir keys certs ||:
	openssl genrsa -out keys/ca.private.pem 4096
	openssl rsa -pubout -in keys/ca.private.pem -out keys/ca.public.pem
	openssl req -new -x509 -days 99999 -config openssl/ca.openssl.config -extensions ext_req -key keys/ca.private.pem -out certs/ca.cert.pem

generate-zms: generate-ca
	mkdir keys certs ||:
	openssl genrsa -out keys/zms.private.pem 4096
	openssl rsa -pubout -in keys/zms.private.pem -out keys/zms.public.pem
	openssl req -config openssl/zms.openssl.config -new -key keys/zms.private.pem -out certs/zms.csr.pem -extensions ext_req
	openssl x509 -req -in certs/zms.csr.pem -CA certs/ca.cert.pem -CAkey keys/ca.private.pem -CAcreateserial -out certs/zms.cert.pem -days 99999 -extfile openssl/zms.openssl.config -extensions ext_req
	openssl verify -CAfile certs/ca.cert.pem certs/zms.cert.pem

generate-zts: generate-zms
	mkdir keys certs ||:
	openssl genrsa -out keys/zts.private.pem 4096
	openssl rsa -pubout -in keys/zts.private.pem -out keys/zts.public.pem
	openssl req -config openssl/zts.openssl.config -new -key keys/zts.private.pem -out certs/zts.csr.pem -extensions ext_req
	openssl x509 -req -in certs/zts.csr.pem -CA certs/ca.cert.pem -CAkey keys/ca.private.pem -CAcreateserial -out certs/zts.cert.pem -days 99999 -extfile openssl/zts.openssl.config -extensions ext_req
	openssl verify -CAfile certs/ca.cert.pem certs/zts.cert.pem

generate-admin: generate-ca
	mkdir keys certs ||:
	openssl genrsa -out keys/athenz_admin.private.pem 4096
	openssl rsa -pubout -in keys/athenz_admin.private.pem -out keys/athenz_admin.public.pem
	openssl req -config openssl/athenz_admin.openssl.config -new -key keys/athenz_admin.private.pem -out certs/athenz_admin.csr.pem -extensions ext_req
	openssl x509 -req -in certs/athenz_admin.csr.pem -CA certs/ca.cert.pem -CAkey keys/ca.private.pem -CAcreateserial -out certs/athenz_admin.cert.pem -days 99999 -extfile openssl/athenz_admin.openssl.config -extensions ext_req
	openssl verify -CAfile certs/ca.cert.pem certs/athenz_admin.cert.pem

generate-crypki: generate-ca
	mkdir keys certs ||:
	openssl genrsa -out - 4096 | openssl pkey -out keys/crypki.private.pem
	openssl req -config openssl/crypki.openssl.config -new -key keys/crypki.private.pem -out certs/crypki.csr.pem -extensions ext_req
	openssl x509 -req -in certs/crypki.csr.pem -CA certs/ca.cert.pem -CAkey keys/ca.private.pem -CAcreateserial -out certs/crypki.cert.pem -days 99999 -extfile openssl/crypki.openssl.config -extensions ext_req
	openssl verify -CAfile certs/ca.cert.pem certs/crypki.cert.pem

generate-certificates: generate-ca generate-zms generate-zts generate-admin generate-ui generate-identityprovider generate-crypki

copy-certificates-to-kustomization:
	( \
	cp -r ../keys ../certs kustomize/ && \
	echo "APPLIED copy-certificates-to-kustomization" \
	)

clean-kubernetes-athenz: clean-certificates

load-docker-images: load-docker-images-internal load-docker-images-external

load-docker-images-internal:
	docker pull $(DOCKER_REGISTRY)athenz-db:latest
	docker pull $(DOCKER_REGISTRY)athenz-zms-server:latest
	docker pull $(DOCKER_REGISTRY)athenz-zts-server:latest
	docker pull $(DOCKER_REGISTRY)athenz-cli:latest
	docker pull $(DOCKER_REGISTRY)athenz-ui:latest

load-docker-images-external:
	docker pull $(DOCKER_REGISTRY)athenz-plugins:latest
	docker pull $(DOCKER_REGISTRY)athenz_user_cert:latest
	docker pull $(DOCKER_REGISTRY)certsigner-envoy:latest
	docker pull $(DOCKER_REGISTRY)crypki-softhsm:latest
	docker pull $(DOCKER_REGISTRY)docker-vegeta:latest
	docker pull $(DOCKER_REGISTRY)k8s-athenz-sia:latest
	docker pull docker.io/dexidp/dex:latest
	docker pull docker.io/ealen/echo-server:latest
	docker pull docker.io/envoyproxy/envoy:v1.34-latest
	docker pull docker.io/ghostunnel/ghostunnel:latest
	docker pull docker.io/openpolicyagent/kube-mgmt:latest
	docker pull docker.io/openpolicyagent/opa:latest-static
	docker pull docker.io/portainer/kubectl-shell:latest
	docker pull docker.io/tatyano/authorization-proxy:latest

load-kubernetes-images: version install-kustomize load-docker-images load-kubernetes-images

deploy-kubernetes-athenz: generate-certificates deploy-kubernetes-manifests

check-kubernetes-athenz: install-parsers
	@DOCKER_REGISTRY=$(DOCKER_REGISTRY) $(MAKE) -C kubernetes check-athenz

clean-docker-athenz: clean-certificates
	@VERSION=$(VERSION) $(MAKE) -C docker clean-athenz


