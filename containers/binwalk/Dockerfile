FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

ARG TARGETARCH
ARG BINWALK_REF=4fdab3d464d97b68e0af9088df3f9e2e1545b21c
ARG RUST_TOOLCHAIN=1.82.0

LABEL org.opencontainers.image.title="FirmAtlas Binwalk extraction worker" \
      org.opencontainers.image.source="https://github.com/FitzBC/FirmAtlas" \
      org.opencontainers.image.version="binwalk-3.1.0" \
      org.opencontainers.image.revision="${BINWALK_REF}"

ENV DEBIAN_FRONTEND=noninteractive \
    BINWALK_RM_EXTRACTION_SYMLINK=1 \
    CARGO_HOME=/root/.cargo \
    RUSTUP_HOME=/root/.rustup \
    PATH=/root/.cargo/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential cabextract ca-certificates clang curl device-tree-compiler \
        git libbz2-dev libfontconfig1-dev liblz4-dev liblzo2-dev liblzma-dev \
        libssl-dev libucl-dev lz4 lzop p7zip-full python3-pip sleuthkit tar \
        unzip unyaffs wget zlib1g-dev zstd \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
        arm64) SASQUATCH_SHA256=fb281906a25667414e8b6aff96b49ceb227519122a7844bbc8166f2b6a59554a ;; \
        amd64) SASQUATCH_SHA256=bb211daf90069a43b7d5e76f136766a8542a5328015773e9b8be87541b307b60 ;; \
        *) exit 64 ;; \
    esac \
    && curl -fL -o /tmp/sasquatch.deb \
        "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-4/sasquatch_1.0_${TARGETARCH}.deb" \
    && echo "${SASQUATCH_SHA256}  /tmp/sasquatch.deb" | sha256sum --check --strict \
    && dpkg -i /tmp/sasquatch.deb \
    && rm /tmp/sasquatch.deb

RUN pip3 install --break-system-packages --no-cache-dir \
        uefi_firmware==1.16 jefferson==0.4.7 ubi-reader==0.8.14 \
        lz4==4.4.5 zstandard==0.25.0 \
        'git+https://github.com/clubby789/python-lzo@b4e39df' \
        'git+https://github.com/marin-m/vmlinux-to-elf@19683fb95b29cd31362d49e6f48ab8368f96cbdf'

RUN git clone --filter=blob:none https://github.com/ReFirmLabs/binwalk.git /tmp/binwalk \
    && git -C /tmp/binwalk checkout --detach "${BINWALK_REF}" \
    && test "$(git -C /tmp/binwalk rev-parse HEAD)" = "${BINWALK_REF}" \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
    && cargo +"${RUST_TOOLCHAIN}" build \
        --manifest-path /tmp/binwalk/Cargo.toml --release --locked \
    && install -m 0755 /tmp/binwalk/target/release/binwalk /usr/local/bin/binwalk \
    && rm -rf /tmp/binwalk /root/.cargo/registry /root/.cargo/git /root/.rustup/downloads

RUN mkdir /analysis && chmod 0777 /analysis
ENV HOME=/tmp
WORKDIR /analysis

ENTRYPOINT ["binwalk"]
