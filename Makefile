SHELL := /bin/bash
SAFE_AUTH_CLI_VERSION := $(shell grep "^version" < Cargo.toml | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
UNAME_S := $(shell uname -s)
PWD := $(shell echo $$PWD)
UUID := $(shell uuidgen | sed 's/-//g')
S3_BUCKET := safe-jenkins-build-artifacts
GITHUB_REPO_OWNER := maidsafe
GITHUB_REPO_NAME := safe-cli

build-container:
	rm -rf target/
	docker rmi -f maidsafe/safe-authenticator-cli-build:build
	docker build -f Dockerfile.build -t maidsafe/safe-authenticator-cli-build:build .

push-container:
	docker push maidsafe/safe-authenticator-cli-build:build

test:
	rm -rf artifacts
	mkdir artifacts
ifeq ($(UNAME_S),Linux)
	docker run --name "safe-auth-cli-build-${UUID}" \
		-v "${PWD}":/usr/src/safe-authenticator-cli:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-authenticator-cli-build:build \
		cargo test --release --features mock-network
	docker cp "safe-auth-cli-build-${UUID}":/target .
	docker rm "safe-auth-cli-build-${UUID}"
else
	cargo test --release --features mock-network
endif
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;
