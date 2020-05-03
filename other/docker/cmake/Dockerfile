################################################
# cmake-linux
FROM localbuild/travis

# Copy minimal files to run "cmake-linux install", so we can avoid rebuilding
# astyle and other things when only source files change.
RUN mkdir -p /home/travis/build/c-toxcore /home/travis/cache
WORKDIR /home/travis/build/c-toxcore
COPY --chown=travis:travis c-toxcore/.travis/ /home/travis/build/c-toxcore/.travis/
RUN .travis/cmake-linux install

# Now copy the rest of the sources and run the build.
COPY --chown=travis:travis . /home/travis/build/
RUN .travis/cmake-linux script

################################################
# autotools-linux
FROM travis AS autotools

USER root
RUN apt-get update && apt-get install --no-install-recommends -y \
 autoconf \
 automake \
 libtool \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
USER travis

# Copy minimal files to run "cmake-linux install", so we can avoid rebuilding
# astyle and other things when only source files change.
RUN mkdir -p /home/travis/build/c-toxcore /home/travis/cache
WORKDIR /home/travis/build/c-toxcore
COPY --chown=travis:travis c-toxcore/.travis/ /home/travis/build/c-toxcore/.travis/
RUN .travis/autotools-linux install

# Now copy the rest of the sources and run the build.
COPY --chown=travis:travis . /home/travis/build/
RUN .travis/autotools-linux script
