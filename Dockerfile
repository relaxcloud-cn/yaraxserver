FROM rust:1.85.0 as builder

WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

COPY --from=builder /usr/src/app/target/release/yaraxserver /usr/local/bin/

CMD ["yaraxserver"]