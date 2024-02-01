# Locate odbcinst include paths and libraries
include(FindPackageHandleStandardArgs)

# This module defines
# ODBC_INCLUDE_DIR, where to find odbc.h, etc.
# ODBC_LIBRARIES, the libraries to link against to use odbc.
# ODBC_FOUND, set to 1 if found
set(ODBC_FOUND 0)
if(WIN32)
  set(ODBC_LIBRARIES odbc32.lib user32.lib)
  try_compile(ODBC_FOUND "${CMAKE_BINARY_DIR}/find-odbc"
    "${CMAKE_CURRENT_LIST_DIR}/SQLAllocHandleTest.cpp"
    LINK_LIBRARIES ${ODBC_LIBRARIES})
else()
  option(ODBC_STATIC "Link to the odbc static library" OFF)
  if(NOT ODBC_STATIC) # 'pkg-config --static odbc' does not provide libodbc.a file path
    find_package(PkgConfig)
    pkg_check_modules(odbc odbc)
    set(ODBC_FOUND ${odbc_FOUND})
  endif()
  #message("ODBC_FOUND=${ODBC_FOUND}")

  if(ODBC_FOUND)
    #message("odbc_INCLUDE_DIRS=${odbc_INCLUDE_DIRS}")
    #message("odbc_LINK_LIBRARIES=${odbc_LINK_LIBRARIES}")
    #message("odbc_STATIC_LINK_LIBRARIES=${odbc_STATIC_LINK_LIBRARIES}")
    find_path(ODBC_INCLUDE_DIR
              NAMES odbcinst.h
              HINTS ${odbc_INCLUDE_DIRS}
              PATH_SUFFIXES odbc)
    if (ODBC_STATIC OR NOT BUILD_SHARED_LIBS)
      set(ODBC_LIBRARIES ${odbc_STATIC_LINK_LIBRARIES})
    else()
      set(ODBC_LIBRARIES ${odbc_LINK_LIBRARIES})
    endif()
  else()
    find_path(ODBC_INCLUDE_DIR odbcinst.h)
    if (ODBC_STATIC OR NOT BUILD_SHARED_LIBS)
      find_library(ODBC_LIBRARIES NAMES libodbc.a HINTS ${ODBC_LIBRARY_DIRS} )
    else()
      find_library(ODBC_LIBRARIES NAMES odbc HINTS ${ODBC_LIBRARY_DIRS} )
    endif()
    if(ODBC_INCLUDE_DIR AND ODBC_LIBRARIES)
      set(ODBC_FOUND 1)
    endif()
  endif()

  #message("ODBC_INCLUDE_DIR=${ODBC_INCLUDE_DIR}")
  #message("ODBC_LIBRARIES=${ODBC_LIBRARIES}")
  find_package_handle_standard_args(ODBC
      ODBC_LIBRARIES)
endif()
