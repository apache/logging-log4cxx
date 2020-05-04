# Locate APR-Util include paths and libraries
include(FindPackageHandleStandardArgs)

# This module defines
# APR_UTIL_INCLUDE_DIR, where to find apr.h, etc.
# APR_UTIL_LIBRARIES, the libraries to link against to use APR.
# APR_UTIL_DLL_DIR, where to find libaprutil-1.dll
# APR_UTIL_FOUND, set to yes if found

macro(_apu_invoke _varname)
    execute_process(
        COMMAND ${APR_UTIL_CONFIG_EXECUTABLE} ${ARGN}
        OUTPUT_VARIABLE _apr_output
        RESULT_VARIABLE _apr_failed
    )

    if(_apr_failed)
        message(FATAL_ERROR "apu-1-config ${ARGN} failed with result ${_apr_failed}")
    else(_apr_failed)
        string(REGEX REPLACE "[\r\n]"  "" _apr_output "${_apr_output}")
        string(REGEX REPLACE " +$"     "" _apr_output "${_apr_output}")
        string(REGEX REPLACE "^ +"     "" _apr_output "${_apr_output}")

        separate_arguments(_apr_output)

        set(${_varname} "${_apr_output}")
    endif(_apr_failed)
endmacro(_apu_invoke)

find_program(APR_UTIL_CONFIG_EXECUTABLE
    apu-1-config
    PATHS /usr/local/bin    /usr/bin    C:/Progra~1/apr-util/bin
    )
mark_as_advanced(APR_UTIL_CONFIG_EXECUTABLE)
if(EXISTS ${APR_UTIL_CONFIG_EXECUTABLE})
    _apu_invoke(APR_UTIL_INCLUDE_DIR   --includedir)
    if (APU_STATIC OR NOT BUILD_SHARED_LIBS)
      _apu_invoke(_apu_util_link_args  --link-ld)
      string(REGEX MATCH "-L([^ ]+)" _apu_util_L_flag ${_apu_util_link_args})
      find_library(APR_UTIL_LIBRARIES NAMES libaprutil-1.a PATHS "${CMAKE_MATCH_1}")
      _apu_invoke(XMLLIB_LIBRARIES --libs)
      set(APR_UTIL_COMPILE_DEFINITIONS APU_DECLARE_STATIC)
    else()
      _apu_invoke(APR_UTIL_LIBRARIES   --link-ld)
    endif()
else()
    find_path(APR_UTIL_INCLUDE_DIR apu.h PATH_SUFFIXES apr-1)
    if (APU_STATIC OR NOT BUILD_SHARED_LIBS)
      set(APR_UTIL_COMPILE_DEFINITIONS APU_DECLARE_STATIC)
      find_library(APR_UTIL_LIBRARIES NAMES aprutil-1)
      find_library(XMLLIB_LIBRARIES NAMES libexpat)
      find_program(XMLLIB_DLL libexpat.dll)
    else()
      find_library(APR_UTIL_LIBRARIES NAMES libaprutil-1)
      find_program(APR_UTIL_DLL libaprutil-1.dll)
    endif()
endif()

find_package_handle_standard_args(APR-Util
  APR_UTIL_INCLUDE_DIR APR_UTIL_LIBRARIES)
