# Configure
if(WIN32)
add_custom_target(configure_log4cxx
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different
    ${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/log4cxx.hw
    ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/log4cxx.h
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different
    ${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/private/log4cxx_private.hw
    ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/private/log4cxx_private.h
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/log4cxx.hw
    ${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/private/log4cxx_private.hw
  BYPRODUCTS
    ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/log4cxx.h
    ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/private/log4cxx_private.h
)
else()
# Configure log4cxx.h
set(LOG4CXX_CHAR "utf-8" CACHE STRING "Interal character representation, choice of utf-8 (default), wchar_t, unichar")
set_property(CACHE LOG4CXX_CHAR PROPERTY STRINGS "utf-8" "wchar_t" "unichar")
set(LOGCHAR_IS_UNICHAR 0)
set(LOGCHAR_IS_WCHAR 0)
set(LOGCHAR_IS_UTF8 0)
if(${LOG4CXX_CHAR} STREQUAL "unichar")
  set(LOGCHAR_IS_UNICHAR 1)
elseif(${LOG4CXX_CHAR} STREQUAL "wchar_t")
  set(LOGCHAR_IS_WCHAR 1)
else()
  set(LOGCHAR_IS_UTF8 1)
endif()
option(LOG4CXX_WCHAR_T "Enable wchar_t API methods" ON)
option(LOG4CXX_UNICHAR "Enable UniChar API methods" OFF)
if(APPLE)
option(LOG4CXX_CFSTRING "Enable CFString API methods, requires Mac OS/X CoreFoundation" OFF)
endif()
set(CHAR_API 1)
foreach(varName WCHAR_T  UNICHAR  CFSTRING )
  if(${LOG4CXX_${varName}})
    set("${varName}_API" 1)
  else()
    set("${varName}_API" 0)
  endif()
endforeach()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/log4cxx.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/log4cxx.h
               @ONLY
)

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

option(LOG4CXX_HAS_STD_LOCALE "Is the standard locale header available?" OFF)
option(LOG4CXX_HAS_ODBC "Build with ODBC appender?" OFF)
option(LOG4CXX_HAS_MBSRTOWCS "Default character encoder converts multi-byte string to LogString using mbstowcs()?" OFF)
option(LOG4CXX_HAS_WCSTOMBS "Default wide character encoder converts using wcstombs()?" OFF)
option(LOG4CXX_HAS_FWIDE "Is the fwide(fd) function available?" OFF)
option(LOG4CXX_HAS_LIBESMTP "Use libESMTP in SMTPAppender?" OFF)
option(LOG4CXX_HAS_SYSLOG "Is the syslog function available?" OFF)

foreach(varName HAS_STD_LOCALE  HAS_ODBC  HAS_MBSRTOWCS  HAS_WCSTOMBS  HAS_FWIDE  HAS_LIBESMTP  HAS_SYSLOG)
  if(${LOG4CXX_${varName}})
    set(${varName} 1)
  else()
    set(${varName} 0)
  endif()
endforeach()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/log4cxx/private/log4cxx_private.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/log4cxx/private/log4cxx_private.h
               @ONLY
)

# Provide the dependencies
add_custom_target(configure_log4cxx
  COMMAND "${CMAKE_COMMAND}" -E echo "Checking configuration"
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/log4cxx/log4cxx.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/include/log4cxx/private/log4cxx_private.h.in
  BYPRODUCTS
    ${CMAKE_CURRENT_BINARY_DIR}/include/log4cxx/log4cxx.h
    ${CMAKE_CURRENT_BINARY_DIR}/include/log4cxx/private/log4cxx_private.h
)
endif()
