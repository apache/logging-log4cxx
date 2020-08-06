cmake_minimum_required(VERSION 3.13)
include(src/cmake/projectVersionDetails.cmake)
project(log4cxx VERSION ${log4cxx_VER} LANGUAGES CXX)
include(CTest)

# define the SO Version of the library. Version of the log4cxx project is subtly different than the version of the library
# (at least in the past it was project vesion: 0.a.b.c and the library so vesion a.b.c.0
set(LIBLOG4CXX_LIB_VERSION ${log4cxx_VERSION_MINOR}.${log4cxx_VERSION_PATCH}.${log4cxx_VERSION_TWEAK})
set(LIBLOG4CXX_LIB_SOVERSION ${log4cxx_VERSION_MINOR})

# FindAPR and FindAPR-util are not provided by APR and APR-Util so source them locally
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/src/cmake")

# Add support for linking statically
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
if(NOT BUILD_SHARED_LIBS)
  set(LOG4CXX_COMPILE_DEFINITIONS LOG4CXX_STATIC)
endif()

# Find Apache Runtime
find_package(APR REQUIRED)

# Find Apache Runtime Utilities
find_package(APR-Util REQUIRED)

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

IF(WIN32 AND BUILD_SHARED_LIBS AND LOG4CXX_INSTALL_PDB)
  INSTALL(FILES $<TARGET_PDB_FILE:log4cxx>
          DESTINATION ${CMAKE_INSTALL_BINDIR}
          CONFIGURATIONS RelWithDebInfo Debug
  )
ENDIF()

if(UNIX)
  # Support for pkg-config in consuming projects
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

# Support for find_package(log4cxx) in consuming CMake projects using
# target_include_directories(myApplication PRIVATE $<TARGET_PROPERTY:log4cxx,INTERFACE_INCLUDE_DIRECTORIES>)
# target_link_libraries( myApplication PRIVATE log4cxx)
install(EXPORT log4cxxTargets
  FILE        log4cxxConfig.cmake
  DESTINATION share/cmake/log4cxx
)
# Support for find_package(log4cxx 0.11) in consuming CMake projects
include(CMakePackageConfigHelpers)
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/log4cxxConfigVersion.cmake"
  VERSION       ${PROJECT_VERSION}
  COMPATIBILITY SameMinorVersion
)
install(FILES   "${CMAKE_CURRENT_BINARY_DIR}/log4cxxConfigVersion.cmake"
  DESTINATION   share/cmake/log4cxx
)

#
# Get the varaibles from the subdirectories
#
get_directory_property( HAS_LIBESMTP DIRECTORY src/main/include DEFINITION HAS_LIBESMTP )
get_directory_property( HAS_ODBC DIRECTORY src/main/include DEFINITION HAS_ODBC )
get_directory_property( HAS_SYSLOG DIRECTORY src/main/include DEFINITION HAS_SYSLOG )

foreach(varName HAS_STD_LOCALE  HAS_ODBC  HAS_MBSRTOWCS  HAS_WCSTOMBS  HAS_FWIDE  HAS_LIBESMTP  HAS_SYSLOG)
  if(${varName} EQUAL 0)
    set(${varName} "OFF" )
  elseif(${varName} EQUAL 1)
    set(${varName} "ON" )
  else()
    set(${varName} "UNKNOWN" )
  endif()
endforeach()

#
# Output configuration information
# Similar to APR CMake configuration
#
message(STATUS "")
message(STATUS "")
message(STATUS "log4cxx configuration summary:")
message(STATUS "")

message(STATUS "  Build shared library ............ : ${BUILD_SHARED_LIBS}")
message(STATUS "  Build tests ..................... : ${BUILD_TESTING}")
message(STATUS "  Install prefix .................. : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  C++ compiler .................... : ${CMAKE_CXX_COMPILER}")
message(STATUS "  log4cxx char API ................ : ${LOG4CXX_CHAR}")
message(STATUS "  log4cxx wchar API ............... : ${LOG4CXX_WCHAR_T}")
message(STATUS "  log4cxx unichar API ............. : ${LOG4CXX_UNICHAR}")
if(APPLE)
message(STATUS "  log4cxx cfstring API ............ : ${LOG4CXX_CFSTRING}")
endif()
message(STATUS "  logchar type .................... : ${LOG4CXX_CHAR}")
message(STATUS "  Using libESMTP .................. : ${HAS_LIBESMTP}")
message(STATUS "  ODBC library .................... : ${HAS_ODBC}")
message(STATUS "  syslog .......................... : ${HAS_SYSLOG}")
