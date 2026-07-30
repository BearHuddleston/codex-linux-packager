# syntax=docker/dockerfile:1
FROM docker.io/library/node@sha256:20a424ecd1d2064a44e12fe287bf3dae443aab31dc5e0c0cb6c74bef9c78911c

LABEL io.github.bearhuddleston.codex-linux-packager.baseline="bookworm-glibc-2.36-x11-v1" \
      io.github.bearhuddleston.codex-linux-packager.debian-snapshots="debian:20260730T082136Z,debian-security:20260730T083809Z" \
      org.opencontainers.image.base.name="docker.io/library/node@sha256:20a424ecd1d2064a44e12fe287bf3dae443aab31dc5e0c0cb6c74bef9c78911c"

COPY containers/debian-snapshot.sources /etc/apt/sources.list.d/debian.sources

RUN apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install --yes --no-install-recommends \
        dbus-x11=1.14.10-1~deb12u1 \
        libasound2=1.2.8-1+b1 \
        libatk-bridge2.0-0=2.46.0-5 \
        libatk1.0-0=2.46.0-5 \
        libatspi2.0-0=2.46.0-5 \
        libcairo2=1.16.0-7 \
        libcups2=2.4.2-3+deb12u9 \
        libdbus-1-3=1.14.10-1~deb12u1 \
        libdrm2=2.4.114-1+b1 \
        libexpat1=2.5.0-1+deb12u2 \
        libgbm1=22.3.6-1+deb12u2 \
        libglib2.0-0=2.74.6-2+deb12u9 \
        libgtk-3-0=3.24.38-2~deb12u3 \
        libnspr4=2:4.35-1 \
        libnss3=2:3.87.1-1+deb12u3 \
        libpango-1.0-0=1.50.12+ds-1 \
        libudev1=252.39-1~deb12u2 \
        libx11-6=2:1.8.4-2+deb12u2 \
        xauth=1:1.1.2-1 \
        xdg-utils=1.1.3-4.1 \
        libxcb1=1.15-1 \
        libxcomposite1=1:0.4.5-1 \
        libxdamage1=1:1.1.6-1 \
        libxext6=2:1.3.4-1+b1 \
        libxfixes3=1:6.0.0-2 \
        libxkbcommon0=1.5.0-1 \
        libxrandr2=2:1.5.2-2+b1 \
        xvfb=2:21.1.7-3+deb12u12 \
    && rm -rf /var/lib/apt/lists/*

USER node
ENV HOME=/tmp/home
ENTRYPOINT []
