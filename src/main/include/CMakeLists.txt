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
    set(LOG4CXX_CHAR "utf-8" CACHE STRING "Internal character representation, choice of utf-8, wchar_t(default), unichar")
    set_property(CACHE LOG4CXX_CHAR PROPERTY STRINGS "utf-8" "wchar_t" "unichar")
    set(LOGCHAR_IS_UNICHAR 0)
    set(LOGCHAR_IS_WCHAR 1)
    set(LOGCHAR_IS_UTF8 0)
else()
    set(LOG4CXX_CHAR "utf-8" CACHE STRING "Internal character representation, choice of utf-8 (default), wchar_t, unichar")
    set_property(CACHE LOG4CXX_CHAR PROPERTY STRINGS "utf-8" "wchar_t" "unichar")
    set(LOGCHAR_IS_UNICHAR 0)
    set(LOGCHAR_IS_WCHAR 0)
    set(LOGCHAR_IS_UTF8 1)
endif()

# Configure log4cxx.h

if(${LOG4CXX_CHAR} STREQUAL "unichar")
  set(LOGCHAR_IS_UNICHAR 1)
  set(LOGCHAR_IS_WCHAR 0)
  set(LOGCHAR_IS_UTF8 0)
elseif(${LOG4CXX_CHAR} STREQUAL "wchar_t")
  set(LOGCHAR_IS_WCHAR 1)
  set(LOGCHAR_IS_UNICHAR 0)
  set(LOGCHAR_IS_UTF8 0)
elseif(${LOG4CXX_CHAR} STREQUAL "utf-8")
    set(LOGCHAR_IS_UNICHAR 0)
    set(LOGCHAR_IS_WCHAR 0)
    set(LOGCHAR_IS_UTF8 1)
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

option(LOG4CXX_NETWORKING_SUPPORT "Support logging over a network socket" ON)
if(LOG4CXX_NETWORKING_SUPPORT)
    set(NETWORKING_SUPPORT 1)
else()
    set(NETWORKING_SUPPORT 0)
endif()

option(LOG4CXX_MULTIPROCESS_ROLLING_FILE_APPENDER "Support multiple processes logging to the same file" OFF)
if(LOG4CXX_MULTIPROCESS_ROLLING_FILE_APPENDER)
    set(MULTIPROCESS_RFA 1)
else()
    set(MULTIPROCESS_RFA 0)
endif()

option(LOG4CXX_EVENTS_AT_EXIT "Prevent static data cleanup to allow event logging during application exit. Note: Appenders should not configure the \"BufferedIO\" option to true." OFF)
if(LOG4CXX_EVENTS_AT_EXIT )
    set(EVENTS_AT_EXIT 1)
else()
    set(EVENTS_AT_EXIT 0)
endif()

set(LOG4CXX_NS "log4cxx" CACHE STRING "Root namespace name")

# Configure log4cxx_private.h
set(LOG4CXX_CHARSET "utf-8" CACHE STRING "LogString characters, choice of utf-8 (default), ISO-8859-1, US-ASCII, EBCDIC, locale")
set_property(CACHE LOG4CXX_CHARSET PROPERTY STRINGS "utf-8" "ISO-8859-1" "US-ASCII" "EBCDIC" "locale")
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
include(CheckIncludeFileCXX)
include(CheckLibraryExists)

CHECK_INCLUDE_FILE_CXX(locale HAS_STD_LOCALE)
CHECK_SYMBOL_EXISTS(mbsrtowcs "cwchar" HAS_MBSRTOWCS)
CHECK_SYMBOL_EXISTS(wcstombs "cstdlib" HAS_WCSTOMBS)
CHECK_SYMBOL_EXISTS(fwide "cwchar" HAS_FWIDE )
CHECK_SYMBOL_EXISTS(syslog "syslog.h" HAS_SYSLOG)
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

foreach(varName
  HAS_THREAD_LOCAL
  HAS_STD_LOCALE
  HAS_ODBC
  HAS_MBSRTOWCS
  HAS_WCSTOMBS
  HAS_FWIDE
  HAS_LIBESMTP
  HAS_SYSLOG
  HAS_PTHREAD_SIGMASK
  HAS_PTHREAD_SETNAME
  HAS_PTHREAD_GETNAME
  )
  if(${varName} EQUAL 0)
    continue()
  elseif(${varName} EQUAL 1)
    continue()
  elseif(${varName} STREQUAL "ON" OR ${varName} STREQUAL "TRUE")
    set(${varName} 1 )
 else()
    set(${varName} 0 )
  endif()
endforeach()

# Configure both our private header and our public header
configure_file(${LOG4CXX_SOURCE_DIR}/src/cmake/compiler-features/makeunique.h.cmake
               ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/helpers/makeunique.h
)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/private/log4cxx_private.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/private/log4cxx_private.h
               @ONLY
)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/log4cxx.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/log4cxx.h
               @ONLY
)
configure_file(${LOG4CXX_SOURCE_DIR}/src/cmake/boost-fallback/boost-std-configuration.h.cmake
               ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/private/boost-std-configuration.h
)
# Provide the dependencies
add_custom_target(configure_log4cxx
  COMMAND "${CMAKE_COMMAND}" -E echo "Checking configuration"
)
