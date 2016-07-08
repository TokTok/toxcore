#!/bin/sh

. other/travis/set-env.sh

pushd ..

# Install cpp-coveralls to upload test coverage results.
pip install --user cpp-coveralls

popd
