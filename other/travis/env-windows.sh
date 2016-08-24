#!/bin/sh

CMAKE=i686-w64-mingw32.static-cmake
NPROC=`nproc`
CURDIR=/work
TESTS=false

RUN() {
  ./dockcross "$@"
}
