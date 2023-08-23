#FROM rust-builder-musl as builder
#
#WORKDIR /work
#
#COPY Cargo.toml .
#COPY Cargo.lock .
#COPY src ./src/
#COPY build.rs .
#COPY static ./static/
#COPY migrations ./migrations/
#COPY sqlx-data.json ./sqlx-data.json
#
##RUN cargo build --target x86_64-unknown-linux-musl --release
#RUN cargo build --release

#FROM scratch as app
FROM alpine:3.13.3 as app

#RUN apk update && apk add --no-cache ca-certificates tzdata && update-ca-certificates
#RUN apk update && apk add --no-cache tzdata

#USER 10001

#COPY --chown=10001:10001 build/tls/ ./tls/
COPY --chown=10001:10001 static ./static/
#COPY --chown=10001:10001 --from=builder /work/target/x86_64-unknown-linux-musl/release/nioca ./nioca
COPY --chown=10001:10001 out/nioca ./nioca

#RUN chown -R 10001:10001 tls static nioca

EXPOSE 8080 8443

ENTRYPOINT ["/nioca"]
CMD ["server"]
