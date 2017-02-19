#!/usr/bin/env sh

set -e -x

#=== Install Packages ===

apt-get update

# Arch-independent pacakges required for building toxcore's dependencies and toxcore itself
apt-get install -y \
    autoconf \
    automake \
    ca-certificates \
    cmake \
    git \
    libtool \
    libc-dev \
    make \
    pkg-config \
    tree \
    yasm

# Arch-dependent pacakges required for building toxcore's dependencies and toxcore itself
if [ "${SUPPORT_ARCH_i686}" = "true" ]; then
    # g++ is unnecessary, but CMake requires it when doing its check
    apt-get install -y \
        g++-mingw-w64-i686 \
        gcc-mingw-w64-i686
fi

if [ "${SUPPORT_ARCH_x86_64}" = "true" ]; then
    # g++ is unnecessary, but CMake requires it when doing its check
    apt-get install -y \
        g++-mingw-w64-x86-64 \
        gcc-mingw-w64-x86-64
fi

# Pacakges needed for running toxcore tests
if [ "${SUPPORT_TEST}" = "true" ]; then
    apt-get install -y \
        curl

    # Arch-independent pacakges for running toxcore tests
    if [ "${SUPPORT_ARCH_i686}" = "true" ]; then
        dpkg --add-architecture i386
        apt-get update
        apt-get install -y \
            wine \
            wine32
    fi
    if [ "${SUPPORT_ARCH_x86_64}" = "true" ]; then
        dpkg --add-architecture amd64
        apt-get install -y \
            wine \
            wine64
    fi
fi

# Clean up to reduce image size
apt-get clean
rm -rf \
    /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/*
