# Image URL to use for building and pushing.
IMG ?= ghcr.io/vileend/keyvault-certoperator:latest
# Platforms for the multi-arch build.
PLATFORMS ?= linux/amd64,linux/arm64

# Tool versions, pinned so CI and a developer machine agree.
CONTROLLER_TOOLS_VERSION ?= v0.21.0
ENVTEST_VERSION ?= v0.24.1
ENVTEST_K8S_VERSION ?= 1.36
GOLANGCI_LINT_VERSION ?= v2.13.1
KUSTOMIZE_VERSION ?= v5.8.1
HELM_VERSION ?= v3.19.0

# A placeholder client ID, so linting does not need a real Azure identity.
CHART_LINT_CLIENT_ID ?= 00000000-0000-0000-0000-000000000000
# Terraform is no longer present on the GitHub runner image, so CI installs it
# the same way a developer machine does.
TERRAFORM_VERSION ?= 1.14.3
GOVULNCHECK_VERSION ?= v1.7.0
# Pinned so CI and a developer machine run the same Kubernetes, and so the
# download is reproducible rather than whatever get.k3s.io serves today.
K3S_VERSION ?= v1.36.3+k3s1
# Pinned here rather than in each caller, so the e2e suite and the chart-install
# job cannot end up testing against different Gateway API versions.
GATEWAY_API_VERSION ?= v1.6.1

LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
HELM ?= $(LOCALBIN)/helm
TERRAFORM ?= $(LOCALBIN)/terraform
GOVULNCHECK ?= $(LOCALBIN)/govulncheck

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
	/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } \
	/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate CRDs and RBAC from code markers.
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=config/crd/bases
	$(CONTROLLER_GEN) rbac:roleName=manager-role paths=./internal/controller/... output:rbac:artifacts:config=config/rbac

.PHONY: generate
generate: controller-gen ## Generate DeepCopy implementations.
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./api/...

.PHONY: fmt
fmt: ## Run go fmt.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint.
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint with --fix.
	$(GOLANGCI_LINT) run --fix

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run all tests, including envtest.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" \
		go test $$(go list ./... | grep -v /test/e2e) -coverprofile cover.out

.PHONY: test-unit
test-unit: ## Run only the tests that need neither a cluster nor Azure.
	go test ./internal/domain/... ./internal/app/... ./internal/infra/...

.PHONY: check-manifests
check-manifests: manifests generate ## Fail if generated files are out of date.
	@if [ -n "$$(git status --porcelain config/ api/)" ]; then \
		echo "generated files are out of date; run 'make manifests generate' and commit the result"; \
		git --no-pager diff -- config/ api/; \
		exit 1; \
	fi

.PHONY: refresh-testdata
refresh-testdata: ## Re-vendor the cert-manager CRD used by envtest.
	@cmdir=$$(go list -m -f '{{.Dir}}' github.com/cert-manager/cert-manager) && \
		cp "$$cmdir/deploy/crds/cert-manager.io_certificates.yaml" test/testdata/crds/ && \
		chmod 644 test/testdata/crds/cert-manager.io_certificates.yaml

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build the manager binary.
	go build -o bin/manager ./cmd/manager

.PHONY: run
run: manifests generate fmt vet ## Run the manager against the current kubecontext.
	go run ./cmd/manager --azure-credential=default

.PHONY: docker-build
docker-build: ## Build the container image.
	docker build -t $(IMG) .

.PHONY: docker-buildx
docker-buildx: ## Build and push a multi-arch image.
	docker buildx build --push --platform=$(PLATFORMS) --tag $(IMG) -f Dockerfile .

.PHONY: build-installer
build-installer: manifests generate kustomize ## Render a single-file install manifest.
	mkdir -p dist
	cd config/manager && $(LOCALBIN)/kustomize edit set image controller=$(IMG)
	$(LOCALBIN)/kustomize build config/default > dist/install.yaml

##@ Deployment

.PHONY: install
install: manifests kustomize ## Install the CRDs.
	$(LOCALBIN)/kustomize build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall the CRDs.
	$(LOCALBIN)/kustomize build config/crd | kubectl delete --ignore-not-found -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy the operator.
	cd config/manager && $(LOCALBIN)/kustomize edit set image controller=$(IMG)
	$(LOCALBIN)/kustomize build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: kustomize ## Remove the operator.
	$(LOCALBIN)/kustomize build config/default | kubectl delete --ignore-not-found -f -

##@ Tooling

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(LOCALBIN)
	@test -x $(CONTROLLER_GEN) || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: setup-envtest
setup-envtest: $(LOCALBIN)
	@test -x $(ENVTEST) || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path >/dev/null

.PHONY: golangci-lint
golangci-lint: $(LOCALBIN)
	@test -x $(GOLANGCI_LINT) || GOBIN=$(LOCALBIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: kustomize
kustomize: $(LOCALBIN)
	@test -x $(LOCALBIN)/kustomize || GOBIN=$(LOCALBIN) go install sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION)

.PHONY: govulncheck
govulncheck: $(LOCALBIN)
	@test -x $(GOVULNCHECK) || GOBIN=$(LOCALBIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: vulncheck
vulncheck: govulncheck ## Report known vulnerabilities reachable from this code.
	$(GOVULNCHECK) ./...

.PHONY: terraform
terraform: $(LOCALBIN)
	@test -x $(TERRAFORM) || { \
		tmp=$$(mktemp -d); \
		base="https://releases.hashicorp.com/terraform/$(TERRAFORM_VERSION)"; \
		zip="terraform_$(TERRAFORM_VERSION)_linux_amd64.zip"; \
		curl -sSLf -o "$$tmp/$$zip" "$$base/$$zip"; \
		curl -sSLf -o "$$tmp/sums" "$$base/terraform_$(TERRAFORM_VERSION)_SHA256SUMS"; \
		(cd "$$tmp" && grep " $$zip$$" sums | sha256sum -c -); \
		unzip -oq "$$tmp/$$zip" -d $(LOCALBIN); \
		rm -rf "$$tmp"; \
	}

.PHONY: tf-fmt
tf-fmt: terraform ## Fail if the Terraform sources are not formatted.
	$(TERRAFORM) fmt -check -recursive terraform/

.PHONY: tf-validate
tf-validate: terraform ## Validate the Terraform module and example against the real provider schema.
	$(TERRAFORM) -chdir=terraform init -backend=false -input=false
	$(TERRAFORM) -chdir=terraform validate
	$(TERRAFORM) -chdir=terraform/examples/aks init -backend=false -input=false
	$(TERRAFORM) -chdir=terraform/examples/aks validate

.PHONY: print-k3s-version
print-k3s-version: ## Print the pinned k3s version, so CI installs what the Makefile says.
	@echo $(K3S_VERSION)

.PHONY: print-gateway-api-version
print-gateway-api-version: ## Print the pinned Gateway API version.
	@echo $(GATEWAY_API_VERSION)

.PHONY: helm
helm: $(LOCALBIN)
	@test -x $(HELM) || GOBIN=$(LOCALBIN) go install helm.sh/helm/v3/cmd/helm@$(HELM_VERSION)

##@ Helm

.PHONY: helm-manifests
helm-manifests: helm-crds helm-rbac ## Sync everything generated into the chart.

.PHONY: helm-crds
helm-crds: manifests ## Sync the generated CRDs into the chart.
	cp config/crd/bases/*.yaml charts/keyvault-certoperator/crds/

.PHONY: helm-rbac
helm-rbac: manifests ## Sync the generated RBAC rules into the chart.
	go run ./hack/helmrbac -o charts/keyvault-certoperator/templates/_rbac-rules.tpl

.PHONY: check-helm-manifests
check-helm-manifests: helm-manifests ## Fail if anything generated in the chart is stale.
	@if [ -n "$$(git status --porcelain charts/)" ]; then \
		echo "the chart is out of date; run 'make helm-manifests' and commit the result"; \
		git --no-pager diff -- charts/; \
		exit 1; \
	fi

.PHONY: helm-lint
helm-lint: helm ## Lint the chart, render it, and check what it actually grants.
	$(HELM) lint charts/keyvault-certoperator --set azure.clientId=$(CHART_LINT_CLIENT_ID)
	$(HELM) template ci charts/keyvault-certoperator --set azure.clientId=$(CHART_LINT_CLIENT_ID) \
		> $(LOCALBIN)/chart-rendered.yaml
	# The staleness gate cannot see a deleted include, so what the chart really
	# grants is compared against config/rbac rather than against the template.
	go run ./hack/helmrbac -verify $(LOCALBIN)/chart-rendered.yaml

##@ End-to-end

.PHONY: e2e
e2e: manifests generate ## Run the end-to-end suite against the current kubectl context.
	test/e2e/run.sh

.PHONY: e2e-cleanup
e2e-cleanup: ## Remove what the end-to-end suite created.
	-kubectl delete namespace keyvault-certoperator-e2e e2e-certs e2e-apps --ignore-not-found
	-kubectl delete clusterrolebinding keyvault-certoperator-e2e --ignore-not-found
	-kubectl delete wildcardcertificatepolicy e2e-discovery --ignore-not-found

.PHONY: e2e-fullstack
e2e-fullstack: manifests generate ## Run the end-to-end suite with cert-manager actually issuing certificates.
	E2E_CERT_MANAGER=1 test/e2e/run.sh
