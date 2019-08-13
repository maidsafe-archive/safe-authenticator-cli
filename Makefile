SHELL := /bin/bash
SAFE_AUTH_CLI_VERSION := $(shell grep "^version" < Cargo.toml | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
UNAME_S := $(shell uname -s)
PWD := $(shell echo $$PWD)
UUID := $(shell uuidgen | sed 's/-//g')
S3_BUCKET := safe-jenkins-build-artifacts
GITHUB_REPO_OWNER := maidsafe
GITHUB_REPO_NAME := safe-authenticator-cli

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
	$(eval ARCHIVE_NAME := ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-${SAFE_AUTH_BUILD_OS}-x86_64.tar.gz)
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
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-linux-x86_64.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-windows-x86_64.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-macos-x86_64.tar.gz .
	tar -C artifacts/linux/release -xvf ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-linux-x86_64.tar.gz
	tar -C artifacts/win/release -xvf ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-windows-x86_64.tar.gz
	tar -C artifacts/macos/release -xvf ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-macos-x86_64.tar.gz
	rm ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-linux-x86_64.tar.gz
	rm ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-windows-x86_64.tar.gz
	rm ${SAFE_AUTH_BRANCH}-${SAFE_AUTH_BUILD_NUMBER}-safe_auth_cli-macos-x86_64.tar.gz

package-commit_hash-artifacts-for-deploy:
	rm -f *.tar
	rm -rf deploy
	mkdir deploy
	tar -C artifacts/linux/release -cvf safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-unknown-linux-gnu.tar safe_auth
	tar -C artifacts/win/release -cvf safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-pc-windows-gnu.tar safe_auth.exe
	tar -C artifacts/macos/release -cvf safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-apple-darwin.tar safe_auth
	mv safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-unknown-linux-gnu.tar deploy
	mv safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-pc-windows-gnu.tar deploy
	mv safe_authenticator_cli-$$(git rev-parse --short HEAD)-x86_64-apple-darwin.tar deploy

package-version-artifacts-for-deploy:
	rm -f *.tar
	rm -rf deploy
	mkdir deploy
	tar -C artifacts/linux/release -cvf safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu.tar safe_auth
	tar -C artifacts/win/release -cvf safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu.tar safe_auth.exe
	tar -C artifacts/macos/release -cvf safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin.tar safe_auth
	mv safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu.tar deploy
	mv safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu.tar deploy
	mv safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin.tar deploy

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
		--description "Command line interface for the authenticating with the SAFE Network";
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_CLI_VERSION} \
		--name "safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu.tar" \
		--file deploy/safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-unknown-linux-gnu.tar;
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_CLI_VERSION} \
		--name "safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu.tar" \
		--file deploy/safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-pc-windows-gnu.tar;
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_AUTH_CLI_VERSION} \
		--name "safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin.tar" \
		--file deploy/safe_authenticator_cli-${SAFE_AUTH_CLI_VERSION}-x86_64-apple-darwin.tar;
