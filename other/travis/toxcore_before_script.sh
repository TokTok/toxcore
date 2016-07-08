#!/bin/sh

. other/travis/set-env.sh

cd ..

# Set up opam.
opam init -y
eval `opam config env`

# Install required opam packages.
opam install -y ocamlfind ppx_deriving menhir

# Build apidsl.
git clone --depth=1 https://github.com/iphydf/apidsl
make -C apidsl

# Install cpp-coveralls to upload test coverage results.
pip install --user cpp-coveralls
