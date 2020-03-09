# Locate APR include paths and libraries
include(FindPackageHandleStandardArgs)

# This module defines
# APR_INCLUDE_DIR, where to find apr.h, etc.
# APR_LIBRARIES, the libraries to link against to use APR.
# APR_DLL_DIR, where to find libapr-1.dll
# APR_FOUND, set to 'yes' if found
macro(_apr_invoke _varname)
    execute_process(
        COMMAND ${APR_CONFIG_EXECUTABLE} ${ARGN}
        OUTPUT_VARIABLE _apr_output
        RESULT_VARIABLE _apr_failed
    )

    if(_apr_failed)
        message(FATAL_ERROR "apr-1-config ${ARGN} failed with result ${_apr_failed}")
    else(_apr_failed)
        string(REGEX REPLACE "[\r\n]"  "" _apr_output "${_apr_output}")
        string(REGEX REPLACE " +$"     "" _apr_output "${_apr_output}")
        string(REGEX REPLACE "^ +"     "" _apr_output "${_apr_output}")

        separate_arguments(_apr_output)
        set(${_varname} "${_apr_output}")
    endif(_apr_failed)
endmacro(_apr_invoke)


find_program(APR_CONFIG_EXECUTABLE
    apr-1-config
    PATHS /usr/local/bin    /usr/bin    C:/Progra~1/apr/bin
    )
mark_as_advanced(APR_CONFIG_EXECUTABLE)
if(EXISTS ${APR_CONFIG_EXECUTABLE})
    _apr_invoke(APR_INCLUDE_DIR  --includedir)
    _apr_invoke(APR_LIBRARIES  --link-ld)
else()
    find_path(APR_INCLUDE_DIR apr.h PATH_SUFFIXES apr-1)
    if (LINK_APR_STATICALLY OR NOT BUILD_SHARED_LIBS)
      set(APR_SYSTEM_LIBS  ws2_32  mswsock  rpcrt4)
      set(APR_COMPILE_DEFINITIONS APR_DECLARE_STATIC)
      find_library(APR_LIBRARIES NAMES apr-1)
    else()
      find_library(APR_LIBRARIES NAMES libapr-1)
      find_program(APR_DLL libapr-1.dll)
    endif()
endif()

find_package_handle_standard_args(apr
    APR_INCLUDE_DIR APR_LIBRARIES)
