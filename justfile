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


# runs `cargo sqlx prepare` against the correct database
prepare: migrate
    DATABASE_URL={{db_url}} cargo sqlx prepare


# run `cargo clippy` with correct env vars
clippy:
    #!/usr/bin/env bash
    set -euxo pipefail
    clear
    DATABASE_URL={{db_url}} cargo clippy


# runs the application
run:
    #!/usr/bin/env bash
    set -euxo pipefail
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

    #DATABASE_URL={{db_url}} cargo build
    #DATABASE_URL={{db_url}} cargo run &
    #sleep 1
    #PID=$(echo "$!")
    #echo "PID: $PID"

    DATABASE_URL={{db_url}} cargo test
    #kill "$PID"
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


build: build-ui
    #!/usr/bin/env bash
    set -euxo pipefail

    DATABASE_URL={{db_url}} cargo clippy -- -D warnings

    # manually update the cross image: docker pull ghcr.io/cross-rs/x86_64-unknown-linux-musl:main
    which cross || echo "'cross' needs to be installed: cargo install cross --git https://github.com/cross-rs/cross"

    cargo clean
    cross build --release --target x86_64-unknown-linux-musl
    cp target/x86_64-unknown-linux-musl/release/nioca out/nioca-amd64

    cargo clean
    cross build --release --target aarch64-unknown-linux-musl
    cp target/aarch64-unknown-linux-musl/release/nioca out/nioca-arm64


# makes sure everything is fine
is-clean:
    #!/usr/bin/env bash
    set -euxo pipefail
    clear

    # exit early if clippy emits warnings
    DATABASE_URL={{db_url}} cargo clippy -- -D warnings

    # make sure everything has been committed
    git diff --exit-code

    echo all good


# sets a new git tag and pushes it
release: is-clean
    #!/usr/bin/env bash
    set -euxo pipefail

    git tag "v$TAG"
    git push origin "v$TAG"


# publishes the application images
publish: test build
     #!/usr/bin/env bash
     set -euxo pipefail

     docker buildx build \
       -t ghcr.io/sebadob/nioca:$TAG \
        --platform linux/amd64,linux/arm64 \
        --no-cache \
        --push \
        .


# publishes the application images
publish-latest:
    docker pull ghcr.io/sebadob/nioca:$TAG
    docker tag ghcr.io/sebadob/nioca:$TAG ghcr.io/sebadob/nioca:latest
    docker push ghcr.io/sebadob/nioca:latest
