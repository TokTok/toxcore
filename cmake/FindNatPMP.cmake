include(FindPackageHandleStandardArgs)

find_package(PkgConfig)
pkg_check_modules(NATPMP QUIET miniupnpc)
set(NATPMP_DEFINITIONS ${PC_NATPMP_CFLAGS_OTHER})

find_path(NATPMP_INCLUDE_DIR natpmp.h
  HINTS ${PC_NATPMP_INCLUDEDIR} ${PC_NATPMP_INCLUDE_DIRS}
  PATH_SUFFIXES natpmp)

find_library(NATPMP_LIBRARY NAMES natpmp libnatpmp
  HINTS ${PC_NATPMP_LIBDIR} ${PC_NATPMP_LIBRARY_DIRS})

# handle the QUIETLY and REQUIRED arguments and set NATPMP_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(NATPMP DEFAULT_MSG
  NATPMP_LIBRARY NATPMP_INCLUDE_DIR)

if(NATPMP_FOUND)
  mark_as_advanced(NATPMP_INCLUDE_DIR NATPMP_LIBRARY)
  set(NATPMP_LIBRARIES ${NATPMP_LIBRARY})
  set(NATPMP_INCLUDE_DIRS ${NATPMP_INCLUDE_DIR})
endif()
