FROM rust:1.86-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p cogwheel-server

FROM node:22-bookworm AS web-builder
WORKDIR /app/apps/cogwheel-web
COPY apps/cogwheel-web/package*.json ./
RUN npm ci
COPY apps/cogwheel-web/ ./
RUN npm run build

FROM debian:bookworm-slim
RUN useradd --system --create-home --uid 10001 cogwheel
WORKDIR /app
COPY --from=builder /app/target/release/cogwheel-server /usr/local/bin/cogwheel-server
COPY --from=web-builder /app/apps/cogwheel-web/dist /app/web
ENV COGWHEEL_WEB_DIST_DIR=/app/web
RUN mkdir -p /app/data && chown -R 10001:10001 /app
USER cogwheel
EXPOSE 8080 53/udp 53/tcp
CMD ["cogwheel-server"]
