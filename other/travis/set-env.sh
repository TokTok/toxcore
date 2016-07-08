#!/bin/sh

set -e -x

export CACHE_DIR=$HOME/cache
export OPAMROOT=$CACHE_DIR/.opam
export PKG_CONFIG_PATH=$CACHE_DIR/lib/pkgconfig
export ASTYLE=$CACHE_DIR/astyle/build/gcc/bin/astyle
