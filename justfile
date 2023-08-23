set shell := ["bash", "-uc"]

export TAG := `cat Cargo.toml | grep '^version =' | cut -d " " -f3 | xargs`
db_url := "postgresql://nioca:123SuperSafe@localhost:5432/nioca"


# sets access rights using `sudo` on linux to grant permission for the nioca binary to bind to port 443
set-cap:
    #!/usr/bin/env bash
    set -euxo pipefail
    sudo setcap CAP_NET_BIND_SERVICE=+eip $(pwd)/target/debug/nioca
    sudo setcap CAP_NET_BIND_SERVICE=+eip $(pwd)/target/release/nioca


# migrates the database
migrate:
    DATABASE_URL={{db_url}} sqlx migrate run


# run `cargo clippy` with correct env vars
clippy:
    #!/usr/bin/env bash
    set -euxo pipefail
    clear
    DATABASE_URL={{db_url}} cargo clippy


# runs the application
run:
    #!/usr/bin/env bash
    clear
    #cargo run --target x86_64-unknown-linux-musl
    DATABASE_URL={{db_url}} cargo build
    sudo setcap CAP_NET_BIND_SERVICE=+eip $(pwd)/target/debug/nioca
    ./target/debug/nioca server
    #DATABASE_URL={{db_url}} cargo run -- server


# runs the UI in development mode
run-ui:
    #!/usr/bin/env bash
    cd frontend
    npm run dev -- --host


# runs the pre-built docker container image for testing
run-docker:
    #!/usr/bin/env bash
    set -euxo pipefail

    docker run --rm \
        -v ./.env.deploy:/.env \
        --network="host" \
        sdobedev/nioca:{{TAG}}


# prints out the currently set version
version:
    echo $TAG


# runs the full set of tests
test:
    #!/usr/bin/env bash
    set -euxo pipefail
    clear

    DATABASE_URL={{db_url}} cargo build
    DATABASE_URL={{db_url}} cargo run test &
    sleep 1
    PID=$(echo "$!")
    echo "PID: $PID"

    DATABASE_URL={{db_url}} cargo test
    kill "$PID"
    echo All tests successful


# builds the builder file for the musl target image container
builder-musl:
    docker build -t rust-builder-musl -f Dockerfile-builder-musl --network="host" .


# builds the frontend and exports to static html
build-ui:
    #!/usr/bin/env bash
    set -euxo pipefail
    clear

    # cleanup old files
    rm -rf static/*

    # build the frontend
    cd frontend
    npm run build


## builds the rauthy book
#build-docs:
#    #!/usr/bin/env bash
#    set -euxo pipefail
#    cd rauthy-book
#    mdbook build -d ../docs


# builds the whole application in release mode
#build: build-docs build-ui
#    cargo clippy -- -D warnings
#    cargo build --release --target x86_64-unknown-linux-musl
#    cp target/x86_64-unknown-linux-musl/release/nioca out/
build: build-ui
    #!/usr/bin/env bash
    set -euxo pipefail

    cargo clippy -- -D warnings

    # manually update the cross image: docker pull ghcr.io/cross-rs/x86_64-unknown-linux-musl:main
    which cross || echo "'cross' needs to be installed: cargo install cross --git https://github.com/cross-rs/cross"

    cross build --release --target x86_64-unknown-linux-musl || echo 'if the sqlx query! macro fails: cargo sqlx prepare'
    cp target/x86_64-unknown-linux-musl/release/nioca out/


build-image: build
    #!/usr/bin/env bash
    set -euxo pipefail
    docker build --no-cache -t sdobedev/nioca:$TAG .


# makes sure everything is fine
is-clean: test build
    #!/usr/bin/env bash
    set -euxo pipefail
    clear

    # exit early if clippy emits warnings
    DATABASE_URL={{db_url}} cargo clippy -- -D warnings

    # make sure everything has been committed
    git diff --exit-code

    echo all good


## sets a new git tag and pushes it
#release:
#    #!/usr/bin/env bash
#    set -euxo pipefail
#
#    git tag "v$TAG"
#    git push origin "v$TAG"


## publishes the application images
#publish:
#    docker build --no-cache -t sdobedev/rauthy:$TAG .
#    docker push sdobedev/rauthy:$TAG
#    docker build --no-cache -f Dockerfile.debug -t sdobedev/rauthy:$TAG-debug .
#    docker push sdobedev/rauthy:$TAG-debug
#
#    docker tag sdobedev/rauthy:$TAG sdobedev/rauthy:latest
#    docker push sdobedev/rauthy:latest
