# Stage 1: Build the binary using Rust 1.70
FROM rust:1.85 AS builder
WORKDIR /app
# Copy your source code into the container
COPY . .
# Build the release version of your binary
RUN cargo build --release

# Stage 2: Use a runtime image with GLIBC 2.33+ (Ubuntu 22.04 has GLIBC 2.35)
FROM ubuntu:22.04 AS runtime
# Install any runtime dependencies (adjust as needed)
RUN apt-get update && \
    apt-get install -y libssl-dev ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Copy the built binary from the builder stage
COPY --from=builder /app/target/release/fast_socks /usr/local/bin/socks5-server
# Expose the port if your application listens on one (adjust port as necessary)
# EXPOSE 1337
EXPOSE 1332
# Set the entrypoint to your binary
CMD ["socks5-server", "--listen-addr", "0.0.0.0:1332", "no-auth"]