
#.rst:
# AddFlag
# -------
#
# Functions to add compile flags to different build types.
#
# A collection of easy to use function. The function automcaticaly proofes
# the support of the flag by the compiler.
#
# The following functions are provided by this module:
# 
# ::
#
#   handle_flag_check
#   add_x_cxxflag
#   add_x_cflag
#   add_debug_flag
#   add_debug_cflag
#   add_debug_cxxflag
#   add_release_flag
#   add_release_cflag
#   add_release_cxxflag
#   add_cxxflag
#   add_cflag
#   add_flag
#   add_dllflag
#
# ::
#
#   HANDLE_FLAG_CHECK(<mode> <flag> <lang>)
#
# Add the "flag" to the list of compile options. Also add additional
# information to the flags like compile mode "mode" (Release, Debug, none)
# and the programming language "lang" (CXX or C).
# 
# @mode Set the compile mode 
# @flag One compile flag that will be added to list of flags
# @lang Defines the prpgramming languate for the flag
#
# Only for internal usage
#
# ::
#
#   ADD_X_CXXFLAGS(<flag> <mode>)
#
# Allows adding C++ compile flags to different compile modes.
# 
# @flag Flag that will be added as compile instructions for C++
# @mode Specifies a compile mode like debug or release.
# @argv2 Returns True if flag is supported and False if the flag is unsupported. No error message will be printed.(Optional).
#
# Only for internal usage
#
# ::
#
#   ADD_X_CFLAGS(<flag> <mode>)
#
# Allows adding C compile flags to different compile modes.
# 
# @flag Flag that will be added as compile instructions for C
# @mode Specifies a compile mode like debug or release.
# @argv2 Returns True if flag is supported and False if the flag is unsupported. No error message will be printed.(Optional).
#
#
# Only for internal usage
#
# ::
#
#   ADD_DEBUG_FLAG(<flag>)
#
# Allows adding a debug compile flag for C and C++.
#
# This flag will be used for debug build
# 
# @flag Flag that will be added as debug compile instruction for C and C++.
# @argv1 Returns True if flag is supported for C and C++, else return False (Optional).
#
# ::
#
#   ADD_DEBUG_CFLAG(<flag>)
#
# Allows adding a debug compile flag for C.
#
# This flag will be used for debug build
# 
# @flag Flag that will be added as debug compile instruction for C.
#
# ::
#
#   ADD_DEBUG_CXXFLAG(<flag>)
#
# Allows adding a debug compile flag for C++.
#
# This flag will be used for debug build
# 
# @flag Flag that will be added as debug compile instruction for C++.
#
# ::
#
#   ADD_RELEASE_FLAG(<flag>)
#
# Allows adding a release compile flag for C and C++.
#
# This flag will be used for release build
# 
# @flag Flag that will be added as release compile instruction for C++.
#
# ::
#
#   ADD_RELEASE_CFLAG(<flag>)
#
# Allows adding a release compile flag for C.
#
# This flag will be used for release build
# 
# @flag Flag that will be added as release compile instruction for C.
#
# ::
#
#   ADD_RELEASE_CXXFLAG(<flag>)
# 
# Allows adding a release compile flag for C++.
#
# This flag will be used for release build.
# 
# @flag Flag that will be added as release compile instruction for C++.
#
# ::
#
#   ADD_CXXFLAG(<flag>)
#
# Allows adding a default compile flag for C++.
#
# This flag will be used for every build
# 
# @flag Flag that will be added as default compile instruction for C++.
#
# ::
#
#   ADD_CFLAG(<flag>)
#
# Allows adding a default compile flag for C.
# 
# This flag will be used for every build
#
# @flag Flag that will be added as default compile instruction for C.
#
# ::
#
#   ADD_FLAG(<flag>)
#
# Allows adding a default compile flag for C and C++.
#
# This flag will be used for every build
#
# @flag Flag that will be added as default compile instruction.
#

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

#-----------------------------------------------------------------------------
# Helper function.  DO NOT CALL DIRECTLY.

function(handle_flag_check mode flag lang)
    if(NOT "${mode}" STREQUAL "")
            string(CONCAT newflag "$<$<AND:$<COMPILE_LANGUAGE:${lang}>,$<CONFIG:" "${mode}" ">>:" "${flag}" ">")
    else()
            string(CONCAT newflag "$<$<COMPILE_LANGUAGE:${lang}>:" ${flag} ">") 
    endif()
    add_compile_options(${newflag})
endfunction()

function(add_x_cxxflag flag mode)
  if(ARGV2)
    set(${ARGV2} TRUE PARENT_SCOPE)
  endif()
  string(REGEX REPLACE "[^a-zA-Z0-9_]" "_" var ${flag})
  if(NOT DEFINED HAVE_CXX_${flag})
  	set(CMAKE_REQUIRED_QUIET TRUE)

	message(STATUS "checking for C++ compiler flag: ${flag}")
  	CHECK_CXX_COMPILER_FLAG("${flag}" HAVE_CXX_${flag})
  	if(HAVE_CXX_${flag})
  		handle_flag_check("${mode}" "${flag}" "CXX")
  	else()
	  	if(ARGV2)
            set(${ARGV2} FALSE PARENT_SCOPE)
        else()
            message(STATUS "${flag} is not supported by ${CMAKE_CXX_COMPILER_ID}")
        endif()
  	endif()
  else()
	  message(STATUS "${flag} Is already defined for C")
  endif()
endfunction()

function(add_x_cflag flag mode)
  if(ARGV2)
    set(${ARGV2} TRUE PARENT_SCOPE)
  endif()
  string(REGEX REPLACE "[^a-zA-Z0-9_]" "_" var ${flag})
  if(NOT DEFINED HAVE_C_${flag})
  	set(CMAKE_REQUIRED_QUIET TRUE)

	message(STATUS "checking for C compiler flag: ${flag}")
  	CHECK_C_COMPILER_FLAG("${flag}" HAVE_C_${flag})
  	if(HAVE_C_${flag})
  		handle_flag_check("${mode}" "${flag}" "C")
  	else()
        if(ARGV2)
            set(${ARGV2} FALSE PARENT_SCOPE)
        else()
            message(STATUS "${flag} is not supported by ${CMAKE_C_COMPILER_ID}")
        endif()
  	endif()
  else()
	  message(STATUS "${flag} is already defined for C++")
  endif()
endfunction()
#-----------------------------------------------------------------------------

function(add_debug_flag flag)
    if(ARGV1)
        set(${ARGV1} TRUE PARENT_SCOPE)
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
            add_x_cxxflag(${flag} "DEBUG" ret1)
            add_x_cflag(${flag} "DEBUG" ret2)
            if(NOT (${ret1} AND ${ret2}))
                set(${ARGV1} FALSE PARENT_SCOPE)
            endif()
        endif()
    else()
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
            add_x_cxxflag(${flag} "DEBUG")
            add_x_cflag(${flag} "DEBUG")
        endif()
    endif()
endfunction()

function(add_debug_cflag flag)
    if(ARGV1)
        set(${ARGV1} TRUE PARENT_SCOPE)
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
            add_x_cflag(${flag} "DEBUG" ret1)
            set(${ARGV1} ${ret1} PARENT_SCOPE)
        endif()
    else()
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
            add_x_cflag(${flag} "DEBUG")
        endif()
    endif()
endfunction()

function(add_debug_cxxflag flag)
    if(ARGV1)
        set(${ARGV1} TRUE PARENT_SCOPE)
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
            add_x_cxxflag(${flag} "DEBUG" ret1)
            set(${ARGV1} ${ret1} PARENT_SCOPE)
        endif()
    else()
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
            add_x_cxxflag(${flag} "DEBUG")
        endif()
    endif()
endfunction()

function(add_release_flag flag)
    if(ARGV1)
        set(${ARGV1} TRUE PARENT_SCOPE)
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
            add_x_cxxflag(${flag} "RELEASE" ret1)
            add_x_cflag(${flag} "RELEASE" ret2)
            if(NOT (${ret1} AND ${ret2}))
                set(${ARGV1} FALSE PARENT_SCOPE)
            endif()
        endif()
    else()
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
            add_x_cxxflag(${flag} "RELEASE")
            add_x_cflag(${flag} "RELEASE")
        endif()
    endif()
endfunction()

function(add_release_cflag flag)
    if(ARGV1)
        set(${ARGV1} TRUE PARENT_SCOPE)
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
            add_x_cflag(${flag} "RELEASE" ret1)
            set(${ARGV1} ${ret1} PARENT_SCOPE)
        endif()
    else()
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
            add_x_cflag(${flag} "RELEASE")
        endif()
    endif()
endfunction()

function(add_release_cxxflag flag)
    if(ARGV1)
        set(${ARGV1} TRUE PARENT_SCOPE)
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
            add_x_cxxflag(${flag} "RELEASE" ret1)
            set(${ARGV1} ${ret1} PARENT_SCOPE)
        endif()
    else()
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
            add_x_cxxflag(${flag} "RELEASE")
        endif()
    endif()
endfunction()

function(add_cxxflag flag)
    if(ARGV1)
        add_x_cxxflag(${flag} "" ret1)
        set(${ARGV1} ${ret1} PARENT_SCOPE)
    else()
        add_x_cxxflag(${flag} "")
    endif()
endfunction()

function(add_cflag flag)
    if(ARGV1)
        add_x_cflag(${flag} "" ret1)
        set(${ARGV1} ${ret1} PARENT_SCOPE)
    else()
        add_x_cflag(${flag} "")
    endif()
endfunction()

function(add_flag flag)
    if(ARGV1)
        set(${ARGV1} TRUE PARENT_SCOPE)
        add_x_cxxflag(${flag} "DEBUG" ret1)
        add_x_cflag(${flag} "DEBUG" ret2)
        if(NOT (${ret1} AND ${ret2}))
            set(${ARGV1} FALSE PARENT_SCOPE)
        endif()
    else()
        add_x_cxxflag(${flag} "DEBUG")
        add_x_cflag(${flag} "DEBUG")
    endif()
endfunction()

function(add_dllflag flag)
  string(REGEX REPLACE "[^a-zA-Z0-9_]" "_" var ${flag})
  if(NOT DEFINED HAVE_LD${var})
    message(STATUS "checking for C++ compiler flag: ${flag}")
  endif()
  set(CMAKE_REQUIRED_QUIET TRUE)

  check_c_compiler_flag("${flag}" HAVE_LD${var} QUIET)
  if(HAVE_LD${var})
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${flag}" PARENT_SCOPE)
  endif()
endfunction()
