FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://example.invalid/install.sh \
    | sh -s -- --yes
