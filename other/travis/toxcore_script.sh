#!/bin/sh

. other/travis/set-env.sh

# Check if toxcore.h and toxav.h match apidsl tox.in.h and toxav.in.h.
../apidsl/_build/apigen.native ./other/apidsl/tox.in.h   | astyle --options=./other/astyle/astylerc > toxcore/tox.h
../apidsl/_build/apigen.native ./other/apidsl/toxav.in.h | astyle --options=./other/astyle/astylerc > toxav/toxav.h
git diff --exit-code

# Build toxcore and run tests.
./autogen.sh
./configure \
  --enable-daemon \
  --enable-logging \
  --enable-ntox \
  CFLAGS="-O0 -Wall -Wextra -fprofile-arcs -ftest-coverage"

make
make check || true
cat build/test-suite.log
make dist
