#!/bin/sh

CMAKE=cmake
NPROC=`sysctl -n hw.ncpu`
CURDIR=$PWD
TESTS=true

RUN() {
  "$@"
}
