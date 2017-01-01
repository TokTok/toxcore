#!/bin/sh

CMAKE=cmake
CMAKE_EXTRA_FLAGS="$CMAKE_EXTRA_FLAGS"
NPROC=`nproc`
CURDIR=$PWD

RUN() {
  "$@"
}

TESTS() {
  "$@"
}
