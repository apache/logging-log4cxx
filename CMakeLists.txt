cmake_minimum_required(VERSION 3.13)
include(src/cmake/projectVersionDetails.cmake)
project(log4cxx VERSION ${log4cxx_VER} LANGUAGES CXX)
include(CTest)

# FindAPR and FindAPR-util are not provided by APR and APR-Util so source them locally
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/src/cmake")

# Find Apache Runtime
find_package(apr QUIET)
# If APR find module sets the cache, the following will do nothing
find_path(APR_INCLUDE_DIR apr.h PATH_SUFFIXES apr-1)
find_library(APR_LIBRARIES NAMES libapr-1 apr-1)

# Find Apache Runtime Utilities
find_package(apr-util QUIET)
# If APR-UTIL find module sets the cache, the following will do nothing
find_path(APR_UTIL_INCLUDE_DIR apu.h PATH_SUFFIXES apr-1)
find_library(APR_UTIL_LIBRARIES NAMES libaprutil-1 aprutil-1)

# Building
add_subdirectory(src)

## Installing
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src/main/include/log4cxx
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h"
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/main/include/log4cxx
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h"
)

install(TARGETS log4cxx EXPORT log4cxxTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} 
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
IF(WIN32 AND LOG4CXX_INSTALL_PDB)
  INSTALL(FILES $<TARGET_PDB_FILE:log4cxx>
          DESTINATION ${CMAKE_INSTALL_BINDIR}
          CONFIGURATIONS RelWithDebInfo Debug
  )
ENDIF()

# create export file which can be imported by other cmake projects
install(EXPORT log4cxxTargets
  FILE log4cxx-targets.cmake
  NAMESPACE log4cxx::
  DESTINATION share/cmake/log4cxx
)
