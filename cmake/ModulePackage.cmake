option(ENABLE_SHARED "Build shared (dynamic) libraries for all modules" ON)
if(WIN32)
  # Our win32 builds are fully static, since we use the MXE cross compiling
  # environment, which builds everything statically by default. Building
  # shared libraries will result in multiple definition errors, since multiple
  # tox libraries will link against libsodium and other libraries that are
  # built statically in MXE.
  set(ENABLE_SHARED OFF)
endif()

option(ENABLE_STATIC "Build static libraries for all modules" ON)

find_package(PkgConfig REQUIRED)

function(pkg_use_module mod)
  pkg_search_module(${mod} ${ARGN})
  if(${mod}_FOUND)
    link_directories(${${mod}_LIBRARY_DIRS})
    include_directories(${${mod}_INCLUDE_DIRS})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${${mod}_CFLAGS_OTHER}")
  endif()
endfunction()

function(add_module lib)
  if(ENABLE_SHARED)
    add_library(${lib}_shared SHARED ${ARGN})
    set_target_properties(${lib}_shared PROPERTIES OUTPUT_NAME ${lib})
    install(TARGETS ${lib}_shared DESTINATION "lib")
  endif()
  if(ENABLE_STATIC)
    add_library(${lib}_static STATIC ${ARGN})
    set_target_properties(${lib}_static PROPERTIES OUTPUT_NAME ${lib})
    install(TARGETS ${lib}_static DESTINATION "lib")
  endif()
endfunction()

function(target_link_modules target)
  if(TARGET ${target}_shared)
    set(_targets ${_targets} ${target}_shared)
  endif()
  if(TARGET ${target}_static)
    set(_targets ${_targets} ${target}_static)
  endif()
  if(NOT _targets)
    set(_targets ${_targets} ${target})
  endif()

  foreach(target ${_targets})
    foreach(dep ${ARGN})
      if(TARGET ${dep}_shared)
        target_link_libraries(${target} ${dep}_shared)
      elseif(TARGET ${dep}_static)
        target_link_libraries(${target} ${dep}_static)
      else()
        target_link_libraries(${target} ${dep})
      endif()
    endforeach()
  endforeach()
endfunction()
