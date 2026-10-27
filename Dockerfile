# Development image: Rust and the Tailwind standalone CLI.
FROM rust:1-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /usr/local/bin/tailwindcss \
       https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.3/tailwindcss-linux-x64 \
    && chmod +x /usr/local/bin/tailwindcss
RUN rustup component add rustfmt clippy
ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} app && useradd -m -u ${UID} -g ${GID} app \
    && mkdir -p /home/app/cargo /home/app/target && chown -R app:app /home/app
USER app
ENV CARGO_HOME=/home/app/cargo CARGO_TARGET_DIR=/home/app/target
WORKDIR /app
EXPOSE 8000
CMD ["bin/dev"]
