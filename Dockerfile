FROM rust:1.84 as builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src
RUN echo "fn main() {}" > src/main.rs
RUN cargo build --release
COPY . .
RUN cargo build --release

FROM ubuntu:22.04
WORKDIR /app
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/yaraxserver .
RUN chmod +x /app/yaraxserver
