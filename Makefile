SHELL := /bin/bash
SAFE_AUTH_CLI_VERSION := $(shell grep "^version" < Cargo.toml | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
UNAME_S := $(shell uname -s)
PWD := $(shell echo $$PWD)
UUID := $(shell uuidgen | sed 's/-//g')
S3_BUCKET := safe-jenkins-build-artifacts
S3_LINUX_DEPLOY_URL := https://safe-authenticator-cli.s3.amazonaws.com/safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu-dev.tar
S3_WIN_DEPLOY_URL := https://safe-authenticator-cli.s3.amazonaws.com/safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu-dev.tar
S3_MACOS_DEPLOY_URL := https://safe-authenticator-cli.s3.amazonaws.com/safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin-dev.tar
GITHUB_REPO_OWNER := jacderida
GITHUB_REPO_NAME := safe-authenticator-cli
define GITHUB_RELEASE_DESCRIPTION
Command line interface for authenticating with the SAFE Network.

With the SAFE authenticator, users can create SAFE Network accounts, log in using existing credentials (secret and password), authorise applications which need to store data on the network on behalf of the user, and manage permissions granted to applications.

There are also development versions of this release:
[Linux](${S3_LINUX_DEPLOY_URL})
[macOS](${S3_MACOS_DEPLOY_URL})
[Windows](${S3_WIN_DEPLOY_URL})

The development version uses a mocked SAFE network, which allows you to work against a file that mimics the network, where SafeCoins are created for local use.
endef
export GITHUB_RELEASE_DESCRIPTION

build-container:
	rm -rf target/
	docker rmi -f maidsafe/safe-authenticator-cli-build:build
	docker build -f Dockerfile.build -t maidsafe/safe-authenticator-cli-build:build \
		--build-arg build_type="non-dev" .

build-dev-container:
	rm -rf target/
	docker rmi -f maidsafe/safe-cli-build:build-dev
	docker build -f Dockerfile.build -t maidsafe/safe-authenticator-cli-build:build-dev \
		--build-arg build_type="dev" .

push-container:
	docker push maidsafe/safe-authenticator-cli-build:build

push-dev-container:
	docker push maidsafe/safe-authenticator-cli-build:build-dev

build:
	rm -rf artifacts
	mkdir artifacts
ifeq ($(UNAME_S),Linux)
	docker run --name "safe-authenticator-cli-build-${UUID}" \
		-v "${PWD}":/usr/src/safe-cli:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-authenticator-cli-build:build \
		cargo build --release
	docker cp "safe-authenticator-cli-build-${UUID}":/target .
	docker rm "safe-authenticator-cli-build-${UUID}"
else
	cargo build --release
endif
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

build-dev:
	rm -rf artifacts
	mkdir artifacts
ifeq ($(UNAME_S),Linux)
	docker run --name "safe-authenticator-cli-build-${UUID}" -v "${PWD}":/usr/src/safe-cli:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-authenticator-cli-build:build-dev \
		cargo build --release --features=mock-network
	docker cp "safe-authenticator-cli-build-${UUID}":/target .
	docker rm "safe-authenticator-cli-build-${UUID}"
else
	cargo build --release --features=mock-network
endif
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

test:
	rm -rf artifacts
	mkdir artifacts
ifeq ($(UNAME_S),Linux)
	docker run --name "safe-auth-cli-build-${UUID}" \
		-v "${PWD}":/usr/src/safe-authenticator-cli:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-authenticator-cli-build:build-dev \
		cargo test --release --features mock-network --lib --test cli_integration -- --test-threads=1
	docker cp "safe-auth-cli-build-${UUID}":/target .
	docker rm "safe-auth-cli-build-${UUID}"
else
	cargo test --release --features mock-network --lib --test cli_integration -- --test-threads=1
endif
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

retrieve-cache:
ifndef SAFE_AUTH_BRANCH
	@echo "A branch reference must be provided."
	@echo "Please set SAFE_AUTH_BRANCH to a valid branch reference."
	@exit 1
endif
ifeq ($(OS),Windows_NT)
	aws s3 cp \
		--no-sign-request \
		--region eu-west-2 \
		s3://${S3_BUCKET}/safe_auth_cli-${SAFE_AUTH_BRANCH}-windows-cache.tar.gz .
	mkdir target
	tar -C target -xvf safe_auth_cli-${SAFE_AUTH_BRANCH}-windows-cache.tar.gz
	rm safe_auth_cli-${SAFE_AUTH_BRANCH}-windows-cache.tar.gz
endif

package-build-artifacts:
ifndef SAFE_AUTH_BRANCH
	@echo "A branch or PR reference must be provided."
	@echo "Please set SAFE_AUTH_BRANCH to a valid branch or PR reference."
	@exit 1
endif
ifndef SAFE_AUTH_BUILD_NUMBER
	@echo "A build number must be supplied for build artifact packaging."
	@echo "Please set SAFE_AUTH_BUILD_NUMBER to a valid build number."
	@exit 1
endif
ifndef SAFE_AUTH_BUILD_OS
	@echo "A value must be supplied for SAFE_AUTH_BUILD_OS."
	@echo "Valid values are 'linux' or 'windows' or 'macos'."
	@exit 1
endif
ifndef SAFE_AUTH_BUILD_TYPE
	@echo "A value must be supplied for SAFE_AUTH_BUILD_OS."
	@echo "Valid values are 'linux' or 'windows' or 'macos'."
	@exit 1
endif
ifeq ($(SAFE_AUTH_BUILD_TYPE),dev)
	$(eval ARCHIVE_NAME := ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-${SAFE_AUTH_BUILD_OS}-x86_64-${SAFE_AUTH_BUILD_TYPE}.tar.gz)
else
	$(eval ARCHIVE_NAME := ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-${SAFE_AUTH_BUILD_OS}-x86_64.tar.gz)
endif
	tar -C artifacts -zcvf ${ARCHIVE_NAME} .
	rm artifacts/**
	mv ${ARCHIVE_NAME} artifacts

retrieve-all-build-artifacts:
ifndef SAFE_AUTH_BRANCH
	@echo "A branch or PR reference must be provided."
	@echo "Please set SAFE_AUTH_BRANCH to a valid branch or PR reference."
	@exit 1
endif
ifndef SAFE_AUTH_BUILD_NUMBER
	@echo "A build number must be supplied for build artifact packaging."
	@echo "Please set SAFE_AUTH_BUILD_NUMBER to a valid build number."
	@exit 1
endif
	rm -rf artifacts
	mkdir -p artifacts/linux/release
	mkdir -p artifacts/win/release
	mkdir -p artifacts/macos/release
	mkdir -p artifacts/linux/dev
	mkdir -p artifacts/win/dev
	mkdir -p artifacts/macos/dev
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-linux-x86_64.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-windows-x86_64.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-macos-x86_64.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-linux-x86_64-dev.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-windows-x86_64-dev.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-macos-x86_64-dev.tar.gz .
	tar -C artifacts/linux/release -xvf ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-linux-x86_64.tar.gz
	tar -C artifacts/win/release -xvf ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-windows-x86_64.tar.gz
	tar -C artifacts/macos/release -xvf ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-macos-x86_64.tar.gz
	tar -C artifacts/linux/dev -xvf ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-linux-x86_64-dev.tar.gz
	tar -C artifacts/win/dev -xvf ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-windows-x86_64-dev.tar.gz
	tar -C artifacts/macos/dev -xvf ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-macos-x86_64-dev.tar.gz
	rm ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-linux-x86_64.tar.gz
	rm ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-windows-x86_64.tar.gz
	rm ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-macos-x86_64.tar.gz
	rm ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-linux-x86_64-dev.tar.gz
	rm ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-windows-x86_64-dev.tar.gz
	rm ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-macos-x86_64-dev.tar.gz

package-commit_hash-artifacts-for-deploy:
	rm -f *.tar
	rm -rf deploy
	mkdir -p deploy/dev
	mkdir -p deploy/release
	tar -C artifacts/linux/release -cvf safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-unknown-linux-gnu.tar safe_auth
	tar -C artifacts/win/release -cvf safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-pc-windows-gnu.tar safe_auth.exe
	tar -C artifacts/macos/release -cvf safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-apple-darwin.tar safe_auth
	tar -C artifacts/linux/dev -cvf safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-unknown-linux-gnu-dev.tar safe_auth
	tar -C artifacts/win/dev -cvf safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-pc-windows-gnu-dev.tar safe_auth.exe
	tar -C artifacts/macos/dev -cvf safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-apple-darwin.tar safe_auth
	mv safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-unknown-linux-gnu.tar deploy/release
	mv safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-pc-windows-gnu.tar deploy/release
	mv safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-apple-darwin.tar deploy/release
	mv safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-unknown-linux-gnu-dev.tar deploy/dev
	mv safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-pc-windows-gnu-dev.tar deploy/dev
	mv safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-apple-darwin-dev.tar deploy/dev

package-version-artifacts-for-deploy:
	rm -f *.tar
	rm -rf deploy
	mkdir -p deploy/dev
	mkdir -p deploy/release
	tar -C artifacts/linux/release -cvf safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu.tar safe_auth
	tar -C artifacts/win/release -cvf safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu.tar safe_auth.exe
	tar -C artifacts/macos/release -cvf safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin.tar safe_auth
	tar -C artifacts/linux/dev -cvf safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu-dev.tar safe_auth
	tar -C artifacts/win/dev -cvf safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu-dev.tar safe_auth.exe
	tar -C artifacts/macos/dev -cvf safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin-dev.tar safe_auth
	mv safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu.tar deploy/release
	mv safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu.tar deploy/release
	mv safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin.tar deploy/release
	mv safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu-dev.tar deploy/dev
	mv safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu-dev.tar deploy/dev
	mv safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin-dev.tar deploy/dev

package-nightly-artifacts-for-deploy:
	rm -f *.tar
	rm -rf deploy
	mkdir -p deploy/dev
	mkdir -p deploy/release
	tar -C artifacts/linux/release -cvf safe_authenticator_cli-nightly-x86_64-unknown-linux-gnu.tar safe_auth
	tar -C artifacts/win/release -cvf safe_authenticator_cli-nightly-x86_64-pc-windows-gnu.tar safe_auth.exe
	tar -C artifacts/macos/release -cvf safe_authenticator_cli-nightly-x86_64-apple-darwin.tar safe_auth
	tar -C artifacts/linux/dev -cvf safe_authenticator_cli-nightly-x86_64-unknown-linux-gnu-dev.tar safe_auth
	tar -C artifacts/win/dev -cvf safe_authenticator_cli-nightly-x86_64-pc-windows-gnu-dev.tar safe_auth.exe
	tar -C artifacts/macos/dev -cvf safe_authenticator_cli-nightly-x86_64-apple-darwin-dev.tar safe_auth
	mv safe_authenticator_cli-nightly-x86_64-unknown-linux-gnu.tar deploy/release
	mv safe_authenticator_cli-nightly-x86_64-pc-windows-gnu.tar deploy/release
	mv safe_authenticator_cli-nightly-x86_64-apple-darwin.tar deploy/release
	mv safe_authenticator_cli-nightly-x86_64-unknown-linux-gnu-dev.tar deploy/dev
	mv safe_authenticator_cli-nightly-x86_64-pc-windows-gnu-dev.tar deploy/dev
	mv safe_authenticator_cli-nightly-x86_64-apple-darwin-dev.tar deploy/dev

deploy-github-release:
ifndef GITHUB_TOKEN
	@echo "Please set GITHUB_TOKEN to the API token for a user who can create releases."
	@exit 1
endif
	github-release release \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_CLI_VERSION} \
		--name "safe-authenticator-cli" \
		--description "$$GITHUB_RELEASE_DESCRIPTION";
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_CLI_VERSION} \
		--name "safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu.tar" \
		--file deploy/release/safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu.tar;
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_CLI_VERSION} \
		--name "safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu.tar" \
		--file deploy/release/safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu.tar;
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_CLI_VERSION} \
		--name "safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin.tar" \
		--file deploy/release/safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin.tar;
