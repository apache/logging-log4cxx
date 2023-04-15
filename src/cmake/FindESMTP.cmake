# Locate libesmtp include paths and libraries
include(FindPackageHandleStandardArgs)

# This module defines
# ESMTP_INCLUDE_DIR, where to find libesmtp.h, etc.
# ESMTP_LIBRARIES, the libraries to link against to use libesmtp.
# ESMTP_FOUND, set to 'yes' if found
macro(_esmtp_invoke _varname)
    execute_process(
        COMMAND ${_esmtp_CONFIG_EXECUTABLE} ${ARGN}
        OUTPUT_VARIABLE _esmtp_output
        RESULT_VARIABLE _esmtp_failed
    )

    if(_esmtp_failed)
        message(FATAL_ERROR "${_esmtp_CONFIG_EXECUTABLE} ${ARGN} failed with result ${_esmtp_failed}")
    else()
        string(REGEX REPLACE "[\r\n]"  "" _esmtp_output "${_esmtp_output}")
        string(REGEX REPLACE " +$"     "" _esmtp_output "${_esmtp_output}")
        string(REGEX REPLACE "^ +"     "" _esmtp_output "${_esmtp_output}")

        separate_arguments(_esmtp_output)
        set(${_varname} "${_esmtp_output}")
    endif(_esmtp_failed)
endmacro(_esmtp_invoke)

if(NOT LIBESMTP_STATIC) # libesmtp-config does not support --static used in FindPkgConfig.cmake
find_package(PkgConfig)
pkg_check_modules(esmtp esmtp)
#message("esmtp_FOUND=${esmtp_FOUND}")
endif()

if(esmtp_FOUND)
  find_path(ESMTP_INCLUDE_DIR
            NAMES libesmtp.h
            HINTS ${ESMTP_INCLUDE_DIRS}
            PATH_SUFFIXES esmtp)
  if (LIBESMTP_STATIC OR NOT BUILD_SHARED_LIBS)
    set(ESMTP_LIBRARIES ${LIBESMTP_STATIC_LINK_LIBRARIES})
  else()
    set(ESMTP_LIBRARIES ${ESMTP_LINK_LIBRARIES})
  endif()
else()
  find_program(_esmtp_CONFIG_EXECUTABLE
      libesmtp-config
      PATHS /usr/local/opt/libesmtp/bin    $ENV{ProgramFiles}/esmtp/bin
      )
  mark_as_advanced(_esmtp_CONFIG_EXECUTABLE)
  if(EXISTS ${_esmtp_CONFIG_EXECUTABLE})
      _esmtp_invoke(_esmtp_cflags_args  --cflags)
      #message("_esmtp_cflags_args=${_esmtp_cflags_args}")
      string(REGEX MATCH "-I([^ ;]+)" _esmtp_include_flag "${_esmtp_cflags_args}")
      set(ESMTP_INCLUDE_DIR  "${CMAKE_MATCH_1}")
      if (LIBESMTP_STATIC OR NOT BUILD_SHARED_LIBS)
        find_library(ESMTP_LIBRARIES NAMES libesmtp.a)
      else()
        _esmtp_invoke(ESMTP_LIBRARIES  --libs)
      endif()
  else()
      find_path(ESMTP_INCLUDE_DIR libesmtp.h PATH_SUFFIXES esmtp)
      if (LIBESMTP_STATIC OR NOT BUILD_SHARED_LIBS)
        find_library(ESMTP_LIBRARIES NAMES libesmtp.a)
      else()
        find_library(ESMTP_LIBRARIES NAMES esmtp)
      endif()
  endif()
endif()

#message("ESMTP_INCLUDE_DIR=${ESMTP_INCLUDE_DIR}")
#message("ESMTP_LIBRARIES=${ESMTP_LIBRARIES}")
find_package_handle_standard_args(ESMTP
    ESMTP_INCLUDE_DIR ESMTP_LIBRARIES)
