#!/bin/sh

# Globally used environment variables.
export CACHE_DIR=$HOME/cache
export OPAMROOT=$CACHE_DIR/.opam
export LD_LIBRARY_PATH=$CACHE_DIR/lib
export PKG_CONFIG_PATH=$CACHE_DIR/lib/pkgconfig
export ASTYLE=$CACHE_DIR/astyle/build/gcc/bin/astyle

BUILD_DIR=_build
