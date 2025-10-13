.PHONY: help build test crdgen install clean

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the operator
	cargo build --release -p patronus-operator

test: ## Run tests
	cargo test -p patronus-operator

crdgen: ## Generate CRD YAML files from Rust types
	@echo "Generating CRDs..."
	@mkdir -p crds
	@cargo run -q --bin crdgen > crds/crds.yaml
	@echo "CRDs generated in crds/crds.yaml"

docker-build: ## Build Docker image
	docker build -t patronus/operator:latest -f Dockerfile ..

helm-lint: ## Lint Helm chart
	helm lint helm/patronus-operator

helm-package: ## Package Helm chart
	helm package helm/patronus-operator

install: crdgen ## Install CRDs to Kubernetes cluster
	kubectl apply -f crds/crds.yaml

uninstall: ## Uninstall CRDs from Kubernetes cluster
	kubectl delete -f crds/crds.yaml

clean: ## Clean build artifacts
	cargo clean
	rm -f helm/patronus-operator/*.tgz
