# Installation instructions

These instructions will guide you through the process of building and installing toxcore library and its components, as well as getting already pre-built binaries.

## Table of contents

- [Overview](#overview)
  - [Components](#components)
    - [Main](#main)
    - [Secondary](#secondary)
- [Building](#building)
  - [Requirements](#requirements)
    - [Library dependencies](#library-dependencies)
    - [Compiler requirements](#compiler-requirements)
    - [Build system requirements](#build-system-requirements)
  - [CMake options](#cmake-options)
  - [Build process](#build-process)
    - [Unix-like](#unix-like)
    - [Windows](#windows)
      - [Building on Windows host](#building-on-windows-host)
        - [cmd.exe](#cmdexe)
        - [msys/cygwin](#msyscygwin)
      - [Cross-compiling from Linux](#cross-compiling-from-linux)
- [Pre-build binaries](#pre-build-binaries)
  - [Linux](#linux)
    - [Debian](#debian)
    - [Ubuntu](#ubuntu)
    - [Arch Linux](#arch-linux)
  - [Windows](#windows-1)

## Overview

### Components

#### Main

This repository contains several libraries besides `toxcore` which complement it, as well as several executables. Here is the full list of the main components that can be built using the CMake, their dependencies and descriptions.

| Name           | Type       | Dependencies                                  | Platform       | Description                                                                |
|----------------|------------|-----------------------------------------------|----------------|----------------------------------------------------------------------------|
| toxcore        | Library    | libnacl or libsodium, libm, libpthread, librt | Cross-platform | The main Tox library that provides the messenger functionality.            |
| toxav          | Library    | libtoxcore, libopus, libvpx                   | Cross-platform | Provides audio/video functionality.                                        |
| toxencryptsave | Library    | libtoxcore, libnacl or libsodium              | Cross-platform | Provides encryption of Tox profiles (savedata), as well as arbitrary data. |
| toxdns         | Library    | libtoxcore                                    | Cross-platform | Deprecated. Provides functionality for resolving Tox IDs from DNS records. |
| DHT_bootstrap  | Executable | libtoxcore                                    | Cross-platform | A simple DHT bootstrap node.                                               |
| tox-bootstrapd | Executable | libtoxcore, libconfig                         | Unix-like      | Highly configurable DHT bootstrap node daemon (systemd, SysVinit, Docker). |

#### Secondary

There are some testing programs that you might find interesting. Note that they are not intended for the real-world use and are not coded to the high security standards, so use them on your own risk.

| Name        | Type       | Dependencies           | Platform  | Description                                                                                                                             |
|-------------|------------|------------------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| irc_syncbot | Executable | libtoxcore             | Unix-like | Bot that synchronizes IRC channel and Tox group chat (conference).                                                                      |
| nTox        | Executable | libtoxcore, libncurses | Unix-like | Simple text-based Tox client with support of file transfers and group chat (conference). Testing program, not intended for actual use.  |
| tox_shell   | Executable | libtoxcore, libutil    | Unix-like | Proof of concept SSH-like server software using Tox. Testing program, not intended for actual use.                                      |
| tox_sync    | Executable | libtoxcore             | Unix-like | Bittorrent-sync-like software using Tox. Syncs two directories together.                                                                |

There are also some programs that are not plugged into the CMake build system which you might want to find interesting. You would need to build those programs yourself. These programs reside in [`other/fun`](other/fun) directory.

| Name                | Type       | Dependencies         | Platform       | Description                                                                                                                                               |
|---------------------|------------|----------------------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| bootstrap_node_info | Script     | python3              | Cross-platform | Script for getting version and Message Of The Day (MOTD) information from a DHT bootstrap node.                                                           |
| cracker             | Executable | libnacl or libsodium | Cross-platform | Tries to generate a curve25519 key pair that would have a public key that starts with specified byte sequence.                                            |
| strkey              | Executable | libsodium            | Cross-platform | Tries to generate a curve25519 key pair that would have a public key that contains a specified byte pattern at the specified position or at any position. |
| make-funny-savefile | Script     | python               | Cross-platform | Generates Tox profile file (savedata file) with provided key pair. Useful for generating Tox profiles from the output of cracker or strkey programs.      |
| sign                | Executable | libsodium            | Cross-platform | Program for ed25519 file signing.                                                                                                                         |
## Building

### Requirements

#### Library dependencies

Librariy dependencies are listed in the [components](#components) table. The dependencies need to be satisfied for the components to be built. Note that if you don't have a dependency for some component, e.g. you don't have `libopus` installed required for building `toxav` component, building of that component is silently disabled.

#### Compiler requirements

The supported compilers are GCC and Clang.

In theory, any compiler that fully supports C99 and accepts GCC flags should work.

Microsoft Visual C++ compiler is not supported, as it doesn't fully support C99 and it doesn't support GCC compiler flags. However, it's possible to cross-compile Tox libraries to Windows using GCC or Clang and use them in a MSVC project.

You should have a C99 compatible compiler in order to build the main components. The secondary componets might require the compiler to support GNU extensions.

#### Build system requirements

To build the main components you need to have CMake of at least 2.8.6 version installed. You also need to have pkg-config installed, the build system uses it to find dependency libraries.

Building was not tested on Windows, so it might not work without msys/cygwin, but we are interested in supporting native (i.e. from `cmd.exe`) Windows building and welcome contributions that help with that.

### CMake options

There are some options that are available to configure the build.

| Name                 | Description                                                                                   | Expected Value                             | Default Value                                     |
|----------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------|---------------------------------------------------|
| ASAN                 | Enable address-sanitizer to detect invalid memory accesses.                                   | ON or OFF                                  | OFF                                               |
| BOOTSTRAP_DAEMON     | Enable building of tox-bootstrapd, the DHT bootstrap node daemon. For Unix-like systems only. | ON or OFF                                  | ON                                                |
| BUILD_AV_TEST        | Build toxav test.                                                                             | ON or OFF                                  | ON                                                |
| BUILD_NTOX           | Build nTox client.                                                                            | ON or OFF                                  | OFF                                               |
| CMAKE_INSTALL_PREFIX | Path to where everything should be installed.                                                 | Directory path.                            | Platform-dependent. Refer to CMake documentation. |
| COMPILE_AS_CXX       | Compile all C code as C++ code.                                                               | ON or OFF                                  | OFF                                               |
| DEBUG                | Enable assertions and other debugging facilities.                                             | ON or OFF                                  | OFF                                               |
| DHT_BOOTSTRAP        | Enable building of DHT_bootstrap                                                              | ON or OFF                                  | ON                                                |
| ENABLE_SHARED        | Build shared (dynamic) libraries for all modules.                                             | ON or OFF                                  | ON                                                |
| ENABLE_STATIC        | Build static libraries for all modules.                                                       | ON or OFF                                  | ON                                                |
| ERROR_ON_WARNING     | Make compilation error on a warning.                                                          | ON or OFF                                  | OFF                                               |
| FORMAT_TEST          | Require the format_test to be executed; fail cmake if it can't.                               | ON or OFF                                  | OFF                                               |
| STRICT_ABI           | Enforce strict ABI export in dynamic libraries.                                               | ON or OFF                                  | OFF                                               |
| TEST_TIMEOUT_SECONDS | Limit runtime of each test to the number of seconds specified.                                | Positive number or nothing (empty string). | Empty string.                                     |
| TRACE                | Enable TRACE level logging (expensive, for network debugging).                                | ON or OFF                                  | OFF                                               |
| WARNINGS             | Enable additional compiler warnings.                                                          | ON or OFF                                  | ON                                                |

You can get this list of option using the following commands

```sh
grep "option(" CMakeLists.txt cmake/*
grep "set(.* CACHE" CMakeLists.txt cmake/*
```

Example of setting cmake options

```sh
cmake
  -DENABLE_STATIC=OFF
  -DDEBUG=ON -DCMAKE_INSTALL_PREFIX=/opt
  -DTEST_TIMEOUT_SECONDS=120
  <the-rest-of-cmake-arguments>
```

### Build process

#### Unix-like

Assuming all the [requirements](#requirements) are met, just run

```sh
cd build
cmake ..
make
make install
```

#### Windows

##### Building on Windows host

###### cmd.exe

There are currently no instructions on how to build toxcore on Windows host in cmd.exe. Contribution of the instructions is welcome!

###### msys/cygwin

There are currently no instructions on how to build toxcore on Windows host in msys/cygwin. Contribution of the instructions is welcome!

##### Cross-compiling from Linux

These cross-compilation instructions were tested on and written for Ubuntu 16.04. You could generalize them for any Linux system, the only requirement is that you have Docker version of >= 1.9.0.

The cross-compilation is fully automated by a parameterized [Dockerfile](/other/docker/Dockerfile).

Install Docker

```sh
apt-get update
apt-get install docker.io
```

Get the toxcore source code and navigate to `other/docker`.

Build the container image based on the Dockerfile. The following options are available to customize the building of the container image.

| Name                | Description                                                    | Expected Value                      | Default Value |
|---------------------|----------------------------------------------------------------|-------------------------------------|---------------|
| SUPPORT_ARCH_i686   | Support building 32-bit toxcore.                               | "true" or "false" (case sensitive). | true          |
| SUPPORT_ARCH_x86_64 | Support building 64-bit toxcore.                               | "true" or "false" (case sensitive). | true          |
| SUPPORT_TEST        | Support running toxcore automated tests.                       | "true" or "false" (case sensitive). | false         |
| VERSION_CHECK       | Version of libcheck. Needed only when SUPPORT_TEST is enabled. | Git branch name.                    | 0.10.0        |
| VERSION_OPUS        | Version of libopus to build toxcore with.                      | Git branch name.                    | v1.1.3        |
| VERSION_SODIUM      | Version of libsodium to build toxcore with.                    | Git branch name.                    | 1.0.11        |
| VERSION_VPX         | Version of libvpx to build toxcore with.                       | Git branch name.                    | v1.5.0        |

Example of building a container image with options

```sh
docker build
  --build-arg SUPPORT_TEST=true
  --build-arg VERSION_CHECK=0.11.0
  -t toxcore
  .
```

Run the container to build toxcore. The following options are available to customize the running of the container image.

| Name               | Description                                                                              | Expected Value                      | Default Value                                                      |
|--------------------|------------------------------------------------------------------------------------------|-------------------------------------|--------------------------------------------------------------------|
| ALLOW_TEST_FAILURE | Don't stop if a test suit fails.                                                         | "true" or "false" (case sensitive). | false                                                              |
| ENABLE_ARCH_i686   | Build 32-bit toxcore. The image should have been built with SUPPORT_ARCH_i686 enabled.   | "true" or "false" (case sensitive). | true                                                               |
| ENABLE_ARCH_x86_64 | Build 64-bit toxcore. The image should have been built with SUPPORT_ARCH_x86_64 enabled. | "true" or "false" (case sensitive). | true                                                               |
| ENABLE_TEST        | Run the test suite. The image should have been built with SUPPORT_TEST enabled.          | "true" or "false" (case sensitive). | false                                                              |
| EXTRA_CMAKE_FLAGS  | Extra arguments to pass to the CMake command when building toxcore.                      | CMake options.                      | "-DWARNINGS=OFF -DBOOTSTRAP_DAEMON=OFF -DTEST_TIMEOUT_SECONDS=300" |

Example of running the container with options

```sh
docker run
  -e ENABLE_TEST=true
  -e ALLOW_TEST_FAILURE=true
  -v /path/to/toxcore/sourcecode:/toxcore
  -v /path/to/where/output/build/result:/prefix
  --rm
  toxcore
```

After the build succeeds, you should see the built toxcore libraries in `/path/to/where/output/build/result`.

## Pre-build binaries

### Linux

#### Debian

Toxcore packages are available in [tox.chat's package repository](https://tox.chat/download.html#gnulinux).

#### Ubuntu

Toxcore packages are available in [tox.chat's package repository](https://tox.chat/download.html#gnulinux).

#### Arch Linux

Toxcore package [is available](https://www.archlinux.org/packages/?q=toxcore) in Arch Linux's official packages.

### Windows

There are nightly cross-compiled binaries available on Jenkins.

|        | Shared                                                                                                                                                                              | Static                                                                                                                                                                              |
|--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 32-bit | [Download](https://build.tox.chat/job/libtoxcore-toktok_build_windows_x86_shared_release/lastSuccessfulBuild/artifact/libtoxcore-toktok_build_windows_x86_shared_release.zip)       | [Download](https://build.tox.chat/job/libtoxcore-toktok_build_windows_x86_static_release/lastSuccessfulBuild/artifact/libtoxcore-toktok_build_windows_x86_static_release.zip)       |
| 64-bit | [Download](https://build.tox.chat/job/libtoxcore-toktok_build_windows_x86-64_shared_release/lastSuccessfulBuild/artifact/libtoxcore-toktok_build_windows_x86-64_shared_release.zip) | [Download](https://build.tox.chat/job/libtoxcore-toktok_build_windows_x86-64_static_release/lastSuccessfulBuild/artifact/libtoxcore-toktok_build_windows_x86-64_static_release.zip) |
