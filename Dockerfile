FROM --platform=$BUILDPLATFORM alpine:3.18.4 AS builderBackend

# docker buildx args automatically available
ARG BUILDPLATFORM
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

# This step is only for debugging / logging the arch we are building for
RUN echo "I'm building on $BUILDPLATFORM for $TARGETOS/$TARGETARCH"

FROM --platform=$TARGETPLATFORM scratch

# docker buildx args automatically available
ARG BUILDPLATFORM
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

USER 10001:10001

COPY --chown=10001:10001 static ./static/
COPY --chown=10001:10001 out/nioca-"$TARGETARCH" ./nioca

EXPOSE 8080 8443

CMD ["/nioca"]
