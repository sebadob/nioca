#!/bin/bash

## This file builds the builder image for the compilation.
## It should be re-created after any updates in the Cargo.toml or after a rustc update to speed up the gitlab pipelines
# and reduced unnecessary crates downloads and re-compilations all the time
#
# Important: If anything in the `meteo-crates` repo was updated, this needs to be rebuilt too, since the whole
# repo will be cached inside the container

IMAGE_NAME=builder-nioca
TAG=20230323

## Important: If you have changed the DB schema and query! validations fails inside the docker image, delete
# `./sqlx-data.json` and run: `cargo sqlx prepare`
# while you are connected to your existing test database.

docker build -t registry.netitservices.com/meteo/$IMAGE_NAME:$TAG -f Dockerfile.builder --no-cache .
docker push registry.netitservices.com/meteo/$IMAGE_NAME:$TAG
