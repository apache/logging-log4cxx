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

# Configure

if(WIN32)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/version_info.h.in
	           ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/version_info.h
		   @ONLY
    )
    set(LOG4CXX_CHAR "utf-8" CACHE STRING "Interal character representation, choice of utf-8, wchar_t(default), unichar")
    set_property(CACHE LOG4CXX_CHAR PROPERTY STRINGS "utf-8" "wchar_t" "unichar")
    set(LOGCHAR_IS_UNICHAR 0)
    set(LOGCHAR_IS_WCHAR 1)
    set(LOGCHAR_IS_UTF8 0)
else()
    set(LOG4CXX_CHAR "utf-8" CACHE STRING "Interal character representation, choice of utf-8 (default), wchar_t, unichar")
    set_property(CACHE LOG4CXX_CHAR PROPERTY STRINGS "utf-8" "wchar_t" "unichar")
    set(LOGCHAR_IS_UNICHAR 0)
    set(LOGCHAR_IS_WCHAR 0)
    set(LOGCHAR_IS_UTF8 1)
endif()

# Configure log4cxx.h

if(${LOG4CXX_CHAR} STREQUAL "unichar")
  set(LOGCHAR_IS_UNICHAR 1)
elseif(${LOG4CXX_CHAR} STREQUAL "wchar_t")
  set(LOGCHAR_IS_WCHAR 1)
endif()
option(LOG4CXX_WCHAR_T "Enable wchar_t API methods" ON)
option(LOG4CXX_UNICHAR "Enable UniChar API methods" OFF)
set(INIT_IOS_BASE 0)
if(APPLE)
option(LOG4CXX_CFSTRING "Enable CFString API methods, requires Mac OS/X CoreFoundation" OFF)
set(INIT_IOS_BASE 1)
endif()
set(CHAR_API 1)
foreach(varName WCHAR_T  UNICHAR  CFSTRING )
  if(${LOG4CXX_${varName}})
    set("${varName}_API" 1)
  else()
    set("${varName}_API" 0)
  endif()
endforeach()


# Configure log4cxx_private.h
set(LOG4CXX_CHARSET "locale" CACHE STRING "LogString characters, choice of locale (default), utf-8, ISO-8859-1, US-ASCII, EBCDIC")
set_property(CACHE LOG4CXX_CHARSET PROPERTY STRINGS "locale" "utf-8" "ISO-8859-1" "US-ASCII" "EBCDIC")
set(CHARSET_EBCDIC 0)
set(CHARSET_USASCII 0)
set(CHARSET_ISO88591 0)
set(CHARSET_UTF8 0)
if(${LOG4CXX_CHARSET} STREQUAL "EBCDIC")
  set(CHARSET_EBCDIC 1)
elseif(${LOG4CXX_CHARSET} STREQUAL "US-ASCII")
  set(CHARSET_USASCII 1)
elseif(${LOG4CXX_CHARSET} STREQUAL "ISO-8859-1")
  set(CHARSET_ISO88591 1)
elseif(${LOG4CXX_CHARSET} STREQUAL "utf-8")
  set(CHARSET_UTF8 1)
endif()

#
# Test for various functions
#
include(CheckFunctionExists)
include(CheckCXXSymbolExists)
include(CheckIncludeFiles)
include(CheckIncludeFileCXX)
include(CheckLibraryExists)

if(WIN32)
	CHECK_INCLUDE_FILES(sqlext.h HAS_ODBC)
else()
	include(FindPkgConfig)

	pkg_check_modules( odbc QUIET odbc )
	if(${odbc_FOUND})
		set(HAS_ODBC 1)
	endif(${odbc_FOUND})
endif(WIN32)

CHECK_INCLUDE_FILE_CXX(locale HAS_STD_LOCALE)
CHECK_FUNCTION_EXISTS(mbsrtowcs HAS_MBSRTOWCS)
CHECK_FUNCTION_EXISTS(wcstombs HAS_WCSTOMBS)
CHECK_FUNCTION_EXISTS(fwide HAS_FWIDE)
CHECK_LIBRARY_EXISTS(esmtp smtp_create_session "" HAS_LIBESMTP)
CHECK_FUNCTION_EXISTS(syslog HAS_SYSLOG)
if(UNIX)
    set(CMAKE_REQUIRED_LIBRARIES "pthread")
    CHECK_SYMBOL_EXISTS(pthread_sigmask "signal.h" HAS_PTHREAD_SIGMASK)

    # Check for the (linux) pthread_setname_np.
    # OSX and BSD are special apparently.  OSX only lets you name
    # the current thread, while BSD calls it pthread_set_name_np.
    # Since this is really not a core feature and the end-user can configure
    # it anyway, we're only going to worry about linux.
    include(${LOG4CXX_SOURCE_DIR}/src/cmake/pthread/log4cxx-pthread.cmake)
    if(${PTHREAD_SETNAME_NP_FOUND})
	set(HAS_PTHREAD_SETNAME 1)
    endif()
    if(${PTHREAD_GETNAME_NP_FOUND})
	set(HAS_PTHREAD_GETNAME 1)
    endif()
endif(UNIX)

if(WIN32)
    CHECK_SYMBOL_EXISTS(SetThreadDescription "windows.h;processthreadsapi.h" HAS_SETTHREADDESCRIPTION)
    CHECK_SYMBOL_EXISTS(GetThreadDescription "windows.h;processthreadsapi.h" HAS_GETTHREADDESCRIPTION)
endif(WIN32)

foreach(varName HAS_STD_LOCALE  HAS_ODBC  HAS_MBSRTOWCS  HAS_WCSTOMBS  HAS_FWIDE  HAS_LIBESMTP  HAS_SYSLOG HAS_PTHREAD_SIGMASK HAS_PTHREAD_SETNAME HAS_PTHREAD_GETNAME HAS_SETTHREADDESCRIPTION HAS_GETTHREADDESCRIPTION)
  if(${varName} EQUAL 0)
    continue()
  elseif(${varName} EQUAL 1)
    continue()
  elseif("${varName}" STREQUAL "ON")
    set(${varName} 1 )
  elseif("${varName}" STREQUAL "OFF")
    set(${varName} 0 )
  else()
    set(${varName} 0 )
  endif()
endforeach()

# Check for standard headers that we need, fall back to boost if they're not found
include(${LOG4CXX_SOURCE_DIR}/src/cmake/boost-fallback/boost-fallback.cmake)
set(NAMESPACE_ALIAS log4cxx)
option(PREFER_BOOST "Prefer Boost over std:: equivalents" OFF)

if( ${STD_THREAD_FOUND} AND NOT ${PREFER_BOOST} )
    set( THREAD_IMPL "std::thread" )
elseif( ${Boost_THREAD_FOUND} )
    set( THREAD_IMPL "boost::thread" )
else()
    set( THREAD_IMPL "NONE" )
endif()

if( ${STD_MUTEX_FOUND} AND NOT ${PREFER_BOOST} )
    set( MUTEX_IMPL "std::mutex" )
elseif( ${Boost_MUTEX_FOUND} )
    set( MUTEX_IMPL "boost::mutex" )
else()
    set( MUTEX_IMPL "NONE" )
endif()

if( ${STD_SHARED_PTR_FOUND} AND NOT ${PREFER_BOOST} )
    set( SMART_PTR_IMPL "std::shared_ptr" )
elseif( ${Boost_SHARED_PTR_FOUND} )
    set( SMART_PTR_IMPL "boost::shared_ptr" )
else()
    set( SMART_PTR_IMPL "NONE" )
endif()

if( ${STD_SHARED_MUTEX_FOUND} AND NOT ${PREFER_BOOST} )
    set( SHARED_MUTEX_IMPL "std::shared_mutex" )
elseif( ${Boost_SHARED_MUTEX_FOUND} )
    set( SHARED_MUTEX_IMPL "boost::shared_mutex" )
else()
    set( SHARED_MUTEX_IMPL "NONE" )
endif()

if( ${STD_ATOMIC_FOUND} AND NOT ${PREFER_BOOST} )
    set( ATOMIC_IMPL "std::atomic" )
elseif( ${Boost_ATOMIC_FOUND} )
    set( ATOMIC_IMPL "boost::atomic" )
else()
    set( ATOMIC_IMPL "NONE" )
endif()

# Configure both our private header and our public header
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/private/log4cxx_private.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/private/log4cxx_private.h
               @ONLY
)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/log4cxx.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/log4cxx.h
	       @ONLY
)
configure_file(${LOG4CXX_SOURCE_DIR}/src/cmake/boost-fallback/boost-std-configuration.h.cmake
                ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/boost-std-configuration.h
)

# Provide the dependencies
add_custom_target(configure_log4cxx
  COMMAND "${CMAKE_COMMAND}" -E echo "Checking configuration"
)
