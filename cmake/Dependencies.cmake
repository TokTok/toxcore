###############################################################################
#
# :: For UNIX-like systems that have pkg-config.
#
###############################################################################

include(ModulePackage)
include(SimpleFindPackage)

set(THREADS_USE_PTHREADS_WIN32 1)
find_package(Threads REQUIRED)

if (MSVC)
  set_property(TARGET Threads::Threads APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS "HAVE_STRUCT_TIMESPEC")
endif()

find_library(NSL_LIBRARIES          nsl          )
find_library(RT_LIBRARIES           rt           )
find_library(SOCKET_LIBRARIES       socket       )

# for toxcore
find_package(sodium REQUIRED)

# For toxav.
simple_find_package(Opus
  INCLUDE_NAMES opus.h
  PKGCFG_NAME opus
  LIB_NAMES opus
  PATH_SUFFIXES opus
  )

simple_find_package(Vpx
  PKGCFG_NAME vpx
  INCLUDE_NAMES vpx_codec.h
  PATH_SUFFIXES vpx
  LIB_NAMES vpx vpxmd)

# For tox-bootstrapd.
pkg_use_module(LIBCONFIG            libconfig    )

# For tox-spectest.
pkg_use_module(MSGPACK              msgpack      )

# For av_test.
pkg_use_module(OPENCV               opencv       )
pkg_use_module(PORTAUDIO            portaudio-2.0)
pkg_use_module(SNDFILE              sndfile      )
