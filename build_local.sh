#!/bin/bash

# If the DB schema has changed, run `cargo sqlx prepare` beforehand and build a new builder

IMAGE_NAME=nioca
TAG=$(cat Cargo.toml | grep '^version =' | cut -d " " -f3 | xargs)

cargo build --target x86_64-unknown-linux-musl --release
cp target/x86_64-unknown-linux-musl/release/nioca out/nioca

docker build -t registry.netitservices.com/meteo/$IMAGE_NAME:$TAG .
docker push registry.netitservices.com/meteo/$IMAGE_NAME:$TAG
