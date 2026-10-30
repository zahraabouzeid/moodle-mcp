FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY migrations migrations
COPY templates templates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/moodle-mcp /usr/local/bin/moodle-mcp \
    && mkdir /data

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/zahraabouzeid/moodle-mcp"
COPY --from=build /usr/local/bin/moodle-mcp /usr/local/bin/moodle-mcp
COPY --from=build --chown=nonroot:nonroot /data /data
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/local/bin/moodle-mcp", "health"]
ENTRYPOINT ["/usr/local/bin/moodle-mcp"]
