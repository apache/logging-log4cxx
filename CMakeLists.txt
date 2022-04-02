#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
cmake_minimum_required(VERSION 3.13)
include(src/cmake/projectVersionDetails.cmake)
project(log4cxx VERSION ${log4cxx_VER} LANGUAGES CXX)
include(CTest)

# If you are including log4cxx from a higher-level CMake file(perhaps as a submodule?)
# CMAKE_SOURCE_DIR will refer to the first CMakeLists.txt.  Since we need some files
# in relation to the log4cxx source root, set a variable that contains the log4cxx root.
set(LOG4CXX_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

# define the SO Version of the library. Version of the log4cxx project is subtly different than the version of the library
# (at least in the past it was project vesion: 0.a.b.c and the library so vesion a.b.c.0
set(LIBLOG4CXX_LIB_VERSION ${log4cxx_VERSION_MINOR}.${log4cxx_VERSION_PATCH}.${log4cxx_VERSION_TWEAK})
set(LIBLOG4CXX_LIB_SOVERSION ${log4cxx_VERSION_MINOR})
# Set the 'release' version.  This is the human-readable version
set(LOG4CXX_RELEASE_VERSION ${log4cxx_VERSION_MAJOR}.${log4cxx_VERSION_MINOR}.${log4cxx_VERSION_PATCH})

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

find_package( Threads REQUIRED )

# Find expat for XML parsing
find_package(EXPAT REQUIRED)
if(TARGET EXPAT::EXPAT)
  set(EXPAT_LIBRARIES EXPAT::EXPAT)
elseif(TARGET expat::expat)
  set(EXPAT_LIBRARIES expat::expat)
endif()

# Request C++17, if available
# This *should* fallback to an older standard if it is not available
if( NOT "${CMAKE_CXX_STANDARD}")
    set(CMAKE_CXX_STANDARD 17)
endif()

# Don't allow for compiler-specific extensions
set(CMAKE_CXX_EXTENSIONS OFF)

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

if(LOG4CXX_QT_SUPPORT)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/main/include/log4cxx-qt
      DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
      FILES_MATCHING PATTERN "*.h"
    )
    install(TARGETS log4cxx-qt EXPORT log4cxx-qtTargets
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif(LOG4CXX_QT_SUPPORT)

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
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

  if(LOG4CXX_QT_SUPPORT)
      set(prefix "${CMAKE_INSTALL_PREFIX}")
      set(exec_prefix "${CMAKE_INSTALL_PREFIX}")
      set(libdir "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
      set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
      set(VERSION "${log4cxx_VERSION_MAJOR}.${log4cxx_VERSION_MINOR}.${log4cxx_VERSION_PATCH}")
      configure_file("${CMAKE_CURRENT_SOURCE_DIR}/liblog4cxx-qt.pc.in"
	"${CMAKE_CURRENT_BINARY_DIR}/liblog4cxx-qt.pc"
      )

      install(FILES "${CMAKE_CURRENT_BINARY_DIR}/liblog4cxx-qt.pc"
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
  endif(LOG4CXX_QT_SUPPORT)
endif(UNIX)

# Support for find_package(log4cxx) in consuming CMake projects using
# target_include_directories(myApplication PRIVATE $<TARGET_PROPERTY:log4cxx,INTERFACE_INCLUDE_DIRECTORIES>)
# target_link_libraries( myApplication PRIVATE log4cxx)
install(EXPORT log4cxxTargets
  FILE        log4cxxConfig.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/log4cxx
)
# Support for find_package(log4cxx 0.11) in consuming CMake projects
include(CMakePackageConfigHelpers)
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/log4cxxConfigVersion.cmake"
  VERSION       ${PROJECT_VERSION}
  COMPATIBILITY SameMinorVersion
)
install(FILES   "${CMAKE_CURRENT_BINARY_DIR}/log4cxxConfigVersion.cmake"
  DESTINATION   ${CMAKE_INSTALL_LIBDIR}/cmake/log4cxx
)

if(LOG4CXX_QT_SUPPORT)
    install(EXPORT log4cxx-qtTargets
      FILE        log4cxx-qtConfig.cmake
      DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/log4cxx
    )
    # Support for find_package(log4cxx 0.11) in consuming CMake projects
    include(CMakePackageConfigHelpers)
    write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/log4cxx-qtConfigVersion.cmake"
      VERSION       ${PROJECT_VERSION}
      COMPATIBILITY SameMinorVersion
    )
    install(FILES   "${CMAKE_CURRENT_BINARY_DIR}/log4cxx-qtConfigVersion.cmake"
      DESTINATION   ${CMAKE_INSTALL_LIBDIR}/cmake/log4cxx
    )
endif(LOG4CXX_QT_SUPPORT)

#
# Get the varaibles from the subdirectories
#
get_directory_property( HAS_LIBESMTP DIRECTORY src/main/include DEFINITION HAS_LIBESMTP )
get_directory_property( HAS_ODBC DIRECTORY src/main/include DEFINITION HAS_ODBC )
get_directory_property( HAS_SYSLOG DIRECTORY src/main/include DEFINITION HAS_SYSLOG )
get_directory_property( THREAD_IMPL DIRECTORY src/main/include DEFINITION THREAD_IMPL )
get_directory_property( SMART_PTR_IMPL DIRECTORY src/main/include DEFINITION SMART_PTR_IMPL )
get_directory_property( MUTEX_IMPL DIRECTORY src/main/include DEFINITION MUTEX_IMPL )
get_directory_property( SHARED_MUTEX_IMPL DIRECTORY src/main/include DEFINITION SHARED_MUTEX_IMPL )
get_directory_property( ATOMIC_IMPL DIRECTORY src/main/include DEFINITION ATOMIC_IMPL )

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
# Package and sign if Apache maintainer
#
option(APACHE_MAINTAINER "Apache maintainer" OFF)
if(APACHE_MAINTAINER)
    set(CPACK_SOURCE_PACKAGE_FILE_NAME "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}")
    set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
    set(CPACK_SOURCE_IGNORE_FILES ".git/;build/;.vs/;out/;CMakeLists.txt.user;src/main/abi-symbols/*;src/test/resources/output/")
    include(CPack)

    add_custom_target( dist
	COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} -- package_source
	COMMAND ${CMAKE_COMMAND} -E sha512sum "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}.tar.gz" > "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}.tar.gz.sha512"
	COMMAND ${CMAKE_COMMAND} -E sha512sum "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}.zip" > "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}.zip.sha512"
	COMMAND gpg -ab --yes "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}.tar.gz" > "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}.tar.gz.asc"
	COMMAND gpg -ab --yes "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}.zip" > "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}.zip.asc"
	)
endif()

#
# Check for any fatal configuration errors
#
if( "${SHARED_MUTEX_IMPL}" STREQUAL "NONE" )
    message( FATAL_ERROR "No shared_mutex implementation found.  Requires Boost or C++17" )
endif()

#
# Output configuration information
# Similar to APR CMake configuration
#
message(STATUS "")
message(STATUS "")
message(STATUS "log4cxx configuration summary:")
message(STATUS "")

message(STATUS "  C++ standard: ................... : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build shared library ............ : ${BUILD_SHARED_LIBS}")
message(STATUS "  Build tests ..................... : ${BUILD_TESTING}")
message(STATUS "  Build site ...................... : ${BUILD_SITE}")
message(STATUS "  Install prefix .................. : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  C++ compiler .................... : ${CMAKE_CXX_COMPILER}")
message(STATUS "  log4cxx char API ................ : ${LOG4CXX_CHAR}")
message(STATUS "  log4cxx wchar API ............... : ${LOG4CXX_WCHAR_T}")
message(STATUS "  log4cxx unichar API ............. : ${LOG4CXX_UNICHAR}")
if(APPLE)
message(STATUS "  log4cxx cfstring API ............ : ${LOG4CXX_CFSTRING}")
endif()
message(STATUS "  logchar type .................... : ${LOG4CXX_CHAR}")
message(STATUS "  charset ......................... : ${LOG4CXX_CHARSET}")
message(STATUS "  Using libESMTP .................. : ${HAS_LIBESMTP}")
message(STATUS "  ODBC library .................... : ${HAS_ODBC}")
message(STATUS "  syslog .......................... : ${HAS_SYSLOG}")
message(STATUS "  Qt support ...................... : ${LOG4CXX_QT_SUPPORT}")
message(STATUS "C++ version and Boost settings:")
message(STATUS "  Prefer boost: ................... : ${PREFER_BOOST}")
message(STATUS "  thread implementation ........... : ${THREAD_IMPL}")
message(STATUS "  mutex implementation ............ : ${MUTEX_IMPL}")
message(STATUS "  shared_ptr implementation ....... : ${SMART_PTR_IMPL}")
message(STATUS "  shared_mutex implementation ..... : ${SHARED_MUTEX_IMPL}")
message(STATUS "  atomic implementation ........... : ${ATOMIC_IMPL}")

if(BUILD_TESTING)
message(STATUS "Applications required for tests:")
message(STATUS "  zip ............................. : ${ZIP_APP}")
message(STATUS "  sed ............................. : ${SED_APP}")
message(STATUS "  gzip ............................ : ${GZIP_APP}")
endif(BUILD_TESTING)
