cmake_minimum_required(VERSION 3.13)
include(src/cmake/projectVersionDetails.cmake)
project(log4cxx VERSION ${log4cxx_VER} LANGUAGES CXX)
include(CTest)

# FindAPR and FindAPR-util are not provided by APR and APR-Util so source them locally
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/src/cmake")

# Find Apache Runtime
find_package(APR QUIET)

# Find Apache Runtime Utilities
find_package(APR-Util QUIET)

# Building
add_subdirectory(src)

## Installing
include(GNUInstallDirs)
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
ENDIF(WIN32 AND LOG4CXX_INSTALL_PDB)

if(UNIX)
  set(prefix "${CMAKE_INSTALL_PREFIX}")
  set(exec_prefix "${CMAKE_INSTALL_PREFIX}")
  set(libdir "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
  set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
  set(VERSION "${log4cxx_VERSION_MAJOR}.${log4cxx_VERSION_MINOR}.${log4cxx_VERSION_PATCH}")
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/liblog4cxx.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/liblog4cxx.pc"
  )

  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/liblog4cxx.pc" 
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
endif(UNIX)


# create export file which can be imported by other cmake projects
install(EXPORT log4cxxTargets
  FILE log4cxx-targets.cmake
  NAMESPACE log4cxx::
  DESTINATION share/cmake/log4cxx
)
