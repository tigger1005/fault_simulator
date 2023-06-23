# from base rust image
# FROM mcr.microsoft.com/devcontainers/rust:0-1-bullseye
ARG VARIANT="1-bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/rust:0-${VARIANT}

RUN apt-get update && apt-get install -y --no-install-recommends \
  && apt-get install -y cmake \
  && apt-get install -y gcc-arm-none-eabi

