#!/usr/bin/env bash

if [[ -z "$build_type" ]]; then
    echo "build_type must be set to dev or non-dev"
    exit 1
fi

if [[ "$build_type" == "dev" ]]; then
    cargo test --release --features mock-network --lib --test cli_integration -- --test-threads=1
else
    cargo build --release --lib
fi
