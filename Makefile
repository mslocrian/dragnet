SHELL=/bin/bash

GO := go
pkgs=$(shell $(GO) list ./... | egrep -v ("vendor)")

export DOCKERHUB_REPO=dragnet
export DOCKERHUB_USER=mslocrian
export SAUSAGE_VERSION=0.0.8
export VERSION=v$(SAUSAGE_VERSION)

build:
	@docker build -f Dockerfile -t $(DOCKERHUB_REPO):$(SAUSAGE_VERSION) .

build-local: format
	@echo ">> removing old dragnet"
	@rm -f dragnet
	@echo ">> building dragnet"
	@go build -o dragnet ./cmd/dragnet/main.go

format:
	@echo ">> formatting go files"
	@find . -path ./vendor -prune -o -name '*.go' -print | xargs gofmt -s -w

push: DOCKER_IMAGE_ID = $(shell docker images -q $(DOCKERHUB_REPO):$(SAUSAGE_VERSION))
push:
	docker tag $(DOCKER_IMAGE_ID) $(DOCKERHUB_USER)/$(DOCKERHUB_REPO):latest
	docker push $(DOCKERHUB_USER)/$(DOCKERHUB_REPO):latest
	docker tag $(DOCKER_IMAGE_ID) $(DOCKERHUB_USER)/$(DOCKERHUB_REPO):$(SAUSAGE_VERSION)
	docker push $(DOCKERHUB_USER)/$(DOCKERHUB_REPO):$(SAUSAGE_VERSION)

run:
	$(GO) run -ldflags "-X main.version=$(VERSION)" cmd/dragnet/main.go -log.level debug -config.file ./dragnet.yml
