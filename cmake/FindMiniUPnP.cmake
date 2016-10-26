include(FindPackageHandleStandardArgs)

find_package(PkgConfig)
pkg_check_modules(MINIUPNP QUIET miniupnpc)
set(MINIUPNP_DEFINITIONS ${PC_MINIUPNP_CFLAGS_OTHER})

find_path(MINIUPNP_INCLUDE_DIR miniupnpc/miniupnpc.h
  HINTS ${PC_MINIUPNP_INCLUDEDIR} ${PC_MINIUPNP_INCLUDE_DIRS}
  PATH_SUFFIXES miniupnpc)

find_library(MINIUPNP_LIBRARY NAMES miniupnpc libminiupnpc
  HINTS ${PC_MINIUPNP_LIBDIR} ${PC_MINIUPNP_LIBRARY_DIRS})

# handle the QUIETLY and REQUIRED arguments and set MINIUPNP_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(MINIUPNP DEFAULT_MSG
  MINIUPNP_LIBRARY MINIUPNP_INCLUDE_DIR)

if(MINIUPNP_FOUND)
  mark_as_advanced(MINIUPNP_INCLUDE_DIR MINIUPNP_LIBRARY)
  set(MINIUPNP_LIBRARIES ${MINIUPNP_LIBRARY})
  set(MINIUPNP_INCLUDE_DIRS ${MINIUPNP_INCLUDE_DIR})
endif()
