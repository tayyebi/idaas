# syntax=docker/dockerfile:1
#
# Multi-stage build. Compilers and headers never leave the build stage, and
# the runtime stage contains no toolchain. The container never mounts
# anything from the host except bind mounts under ./data (see compose file).

ARG DEBIAN_IMAGE=debian:trixie-slim

# ---------------------------------------------------------------- build
FROM ${DEBIAN_IMAGE} AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential make \
        libssl-dev libpam0g-dev libmicrohttpd-dev libcrypt-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY scripts/embed.sh scripts/
COPY src/ src/
COPY web/ web/
COPY tests/ tests/
RUN make -j4 build/idaas

# Collect the full shared-library closure of the binary (same base image,
# so the ABI matches). -L dereferences SONAME symlinks so every entry is a
# real file — some Debian libs (microhttpd, gnutls) are soname symlinks.
RUN mkdir -p /out/libs \
    && ldd build/idaas | awk '/=> \// {print $3} /^\// {print $1}' \
        | sort -u | xargs -I{} cp -L "{}" /out/libs/

# ---------------------------------------------------------------- test
# Fixture users are created here, inside the image only — never on the host.
#   alice     uid >= 1000, sha512crypt password
#   bob       uid >= 1000, yescrypt password (distro default)
#   svcdaemon uid  490,    used to verify the uid-range login gate
FROM build AS test
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpam-modules \
    && rm -rf /var/lib/apt/lists/*
COPY pam/idaas /etc/pam.d/idaas
RUN useradd -m -s /bin/bash alice \
    && echo 'alice:alice-pass-1' | chpasswd -c SHA512 \
    && useradd -m -s /bin/bash bob \
    && echo 'bob:bob-pass-2' | chpasswd \
    && useradd -r -u 490 -s /usr/sbin/nologin svcdaemon \
    && echo 'svcdaemon:svc-pass-3' | chpasswd
RUN make unit && make pamtest

# ---------------------------------------------------------------- runtime
FROM ${DEBIAN_IMAGE} AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpam-modules \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/libs/ /usr/lib/incoming-libs/
RUN mv /usr/lib/incoming-libs/* /usr/lib/*-linux-gnu/ \
    && ldconfig \
    && rmdir /usr/lib/incoming-libs
COPY --from=build /src/build/idaas /usr/local/bin/idaas
COPY pam/idaas /etc/pam.d/idaas
VOLUME /data
ENV IDAAS_LISTEN=:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/idaas"]
