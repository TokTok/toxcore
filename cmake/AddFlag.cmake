include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)


function(handle_flag_check mode flag lang)
    if(NOT "${mode}" STREQUAL "")
            string(CONCAT newflag "$<$<AND:$<COMPILE_LANGUAGE:${lang}>,$<CONFIG:" "${mode}" ">>:" "${flag}" ">")
    else()
            string(CONCAT newflag "$<$<COMPILE_LANGUAGE:${lang}>:" ${flag} ">") 
    endif()
    add_compile_options(${newflag})
endfunction()

macro(add_x_cxxflag flag mode)
  string(REGEX REPLACE "[^a-zA-Z0-9_]" "_" var ${flag})
  if(NOT DEFINED HAVE_CXX_${flag})
  	set(CMAKE_REQUIRED_QUIET TRUE)

	message(STATUS "checking for C++ compiler flag: ${flag}")
  	CHECK_CXX_COMPILER_FLAG("${flag}" HAVE_CXX_${flag})
  	if(HAVE_CXX_${flag})
  		handle_flag_check("${mode}" "${flag}" "CXX")
  	else()
	  	message(STATUS "${flag} is not supported by ${CMAKE_CXX_COMPILER_ID}")
  	endif()
  else()
	  message(STATUS "${flag} Is already defined for C")
  endif()
endmacro()

##
 # Allows adding compile flags to different compile modes for c++ 
 # 
 # @flag Flag that will be added as compile instructions for c++
 # @mode Specifies a compile mode like debug or release.
 #
macro(add_x_cflag flag mode)
  string(REGEX REPLACE "[^a-zA-Z0-9_]" "_" var ${flag})
  if(NOT DEFINED HAVE_C_${flag})
  	set(CMAKE_REQUIRED_QUIET TRUE)

	message(STATUS "checking for C compiler flag: ${flag}")
  	CHECK_C_COMPILER_FLAG("${flag}" HAVE_C_${flag})
  	if(HAVE_C_${flag})
  		handle_flag_check("${mode}" "${flag}" "C")
  	else()
	  	message(STATUS "${flag} is not supported by ${CMAKE_C_COMPILER_ID}")
  	endif()
  else()
	  message(STATUS "${flag} is already defined for C++")
  endif()
endmacro()

##
 # Allows adding a debug compile flag for c and c++.
 #
 # This flag will be used for debug build
 # 
 # @flag Flag that will be added as debug compile instruction for c and c++.
 #
macro(add_debug_flag flag)
	if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_x_cxxflag(${flag} "DEBUG")
    add_x_cflag(${flag} "DEBUG")
    endif()
endmacro()

##
 # Allows adding a debug compile flag for c.
 #
 # This flag will be used for debug build
 # 
 # @flag Flag that will be added as debug compile instruction for c.
 #
macro(add_debug_cflag flag)
	if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_x_cflag(${flag} "DEBUG")
    endif()
endmacro()

##
 # Allows adding a debug compile flag for c++.
 #
 # This flag will be used for debug build
 # 
 # @flag Flag that will be added as debug compile instruction for c++.
 #
macro(add_debug_cxxflag flag)
	if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_x_cxxflag(${flag} "DEBUG")
    endif()
endmacro()

##
 # Allows adding a release compile flag for c and c++.
 #
 # This flag will be used for release build
 # 
 # @flag Flag that will be added as release compile instruction for c++.
 #
macro(add_release_flag flag)
    add_x_cxxflag(${flag} "RELEASE")
    add_x_cflag(${flag} "RELEASE")
endmacro()

##
 # Allows adding a release compile flag for c.
 #
 # This flag will be used for release build
 # 
 # @flag Flag that will be added as release compile instruction for c.
 #
macro(add_release_cflag flag)
    add_x_cflag(${flag} "RELEASE")
endmacro()

##
 # Allows adding a release compile flag for c++.
 #
 # This flag will be used for release build.
 # 
 # @flag Flag that will be added as release compile instruction for c++.
 #
macro(add_release_cxxflag flag)
    add_x_cxxflag(${flag} "RELEASE")
endmacro()

##
 # Allows adding a default compile flag for c++.
 #
 # This flag will be used for every build
 # 
 # @flag Flag that will be added as default compile instruction for c++.
 #
macro(add_cxxflag flag)
    add_x_cxxflag(${flag} "")
endmacro()

##
 # Allows adding a default compile flag for c.
 # 
 # This flag will be used for every build
 #
 # @flag Flag that will be added as default compile instruction for c.
 #
macro(add_cflag flag)
    add_x_cflag(${flag} "")
endmacro()

##
 # Allows adding a default compile flag for c and c++.
 #
 # This flag will be used for every build
 #
 # @flag Flag that will be added as default compile instruction.
 #
macro(add_flag flag)
  add_x_cflag(${flag} "")
  add_x_cxxflag(${flag} "")
endmacro()
