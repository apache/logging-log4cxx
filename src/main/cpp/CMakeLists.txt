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

# Build the log4cxx library
add_library(log4cxx)
if(${log4cxx_ABI_VER} GREATER 15)
  set_target_properties(log4cxx PROPERTIES CXX_VISIBILITY_PRESET hidden)
endif()
set(PRIVATE_COMPILE_DEFINITIONS)
set(PUBLIC_COMPILE_DEFINITIONS)
if(BUILD_SHARED_LIBS)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS LOG4CXX)
    if(UNIX AND NOT APPLE)
        # Make defined symbols non-preemptible, which can optimize relocation processing
        target_link_options(log4cxx PRIVATE "LINKER:-Bsymbolic")
    endif()
else()
    list(APPEND PUBLIC_COMPILE_DEFINITIONS LOG4CXX_STATIC)
endif()
if(LOG4CXX_TEST_ONLY_BUILD)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS
      "ENABLE_FAILING_APPENDER_SIMULATION_TESTING=1"
      "LOGLOG_THRESHOLD=1"
    )
endif()
target_compile_definitions(log4cxx
    PUBLIC ${PUBLIC_COMPILE_DEFINITIONS}
    PRIVATE ${PRIVATE_COMPILE_DEFINITIONS}
)

add_dependencies(log4cxx log4cxx-include)

set(extra_classes "")

if(LOG4CXX_NETWORKING_SUPPORT)
    list(APPEND extra_classes
        datagrampacket.cpp
        datagramsocket.cpp
        aprdatagramsocket.cpp
        serversocket.cpp
        aprserversocket.cpp
        socket.cpp
        aprsocket.cpp
        telnetappender.cpp
        socketappenderskeleton.cpp
        socketoutputstream.cpp
        xmlsocketappender.cpp
        syslogwriter.cpp
        syslogappender.cpp
    )
endif()

if(LOG4CXX_DOMCONFIGURATOR_SUPPORT)
    list(APPEND extra_classes
	domconfigurator.cpp
	)
endif()

if(LOG4CXX_MULTIPROCESS_ROLLING_FILE_APPENDER)
    target_compile_definitions(log4cxx PRIVATE LOG4CXX_MULTI_PROCESS)
    list(APPEND extra_classes
        multiprocessrollingfileappender.cpp
    )
endif()

if(${ENABLE_FMT_LAYOUT})
    list(APPEND extra_classes
        fmtlayout.cpp
    )
endif()

target_sources(log4cxx
  PRIVATE
  action.cpp
  andfilter.cpp
  appender.cpp
  appenderattachableimpl.cpp
  appenderskeleton.cpp
  aprinitializer.cpp
  asyncappender.cpp
  asyncbuffer.cpp
  basicconfigurator.cpp
  bufferedwriter.cpp
  bytearrayinputstream.cpp
  bytearrayoutputstream.cpp
  bytebuffer.cpp
  cacheddateformat.cpp
  charsetdecoder.cpp
  charsetencoder.cpp
  class.cpp
  classnamepatternconverter.cpp
  classregistration.cpp
  colorstartpatternconverter.cpp
  colorendpatternconverter.cpp
  configurator.cpp
  consoleappender.cpp
  consolewriter.cpp
  cyclicbuffer.cpp
  date.cpp
  dateformat.cpp
  datepatternconverter.cpp
  dbappender.cpp
  defaultconfigurator.cpp
  defaultloggerfactory.cpp
  defaultrepositoryselector.cpp
  errorhandler.cpp
  exception.cpp
  fallbackerrorhandler.cpp
  file.cpp
  fileappender.cpp
  filedatepatternconverter.cpp
  fileinputstream.cpp
  filelocationpatternconverter.cpp
  fileoutputstream.cpp
  filerenameaction.cpp
  filewatchdog.cpp
  filter.cpp
  filterbasedtriggeringpolicy.cpp
  fixedwindowrollingpolicy.cpp
  formattinginfo.cpp
  fulllocationpatternconverter.cpp
  gzcompressaction.cpp
  hexdump.cpp
  hierarchy.cpp
  htmllayout.cpp
  inetaddress.cpp
  inputstream.cpp
  inputstreamreader.cpp
  integer.cpp
  integerpatternconverter.cpp
  jsonlayout.cpp
  layout.cpp
  level.cpp
  levelmatchfilter.cpp
  levelpatternconverter.cpp
  levelrangefilter.cpp
  linelocationpatternconverter.cpp
  lineseparatorpatternconverter.cpp
  literalpatternconverter.cpp
  loader.cpp
  locale.cpp
  locationinfo.cpp
  locationinfofilter.cpp
  logger.cpp
  loggermatchfilter.cpp
  loggerpatternconverter.cpp
  loggingevent.cpp
  loggingeventpatternconverter.cpp
  loglog.cpp
  logmanager.cpp
  logstream.cpp
  manualtriggeringpolicy.cpp
  mapfilter.cpp
  mdc.cpp
  messagebuffer.cpp
  messagepatternconverter.cpp
  methodlocationpatternconverter.cpp
  nameabbreviator.cpp
  namepatternconverter.cpp
  ndc.cpp
  mdcpatternconverter.cpp
  ndcpatternconverter.cpp
  nteventlogappender.cpp
  odbcappender.cpp
  onlyonceerrorhandler.cpp
  optionconverter.cpp
  optionhandler.cpp
  outputdebugstringappender.cpp
  outputstream.cpp
  outputstreamwriter.cpp
  patternconverter.cpp
  patternlayout.cpp
  patternparser.cpp
  pool.cpp
  properties.cpp
  propertiespatternconverter.cpp
  propertyconfigurator.cpp
  propertyresourcebundle.cpp
  propertysetter.cpp
  reader.cpp
  relativetimedateformat.cpp
  relativetimepatternconverter.cpp
  resourcebundle.cpp
  rollingfileappender.cpp
  rollingpolicy.cpp
  rollingpolicybase.cpp
  rolloverdescription.cpp
  rootlogger.cpp
  shortfilelocationpatternconverter.cpp
  simpledateformat.cpp
  simplelayout.cpp
  sizebasedtriggeringpolicy.cpp
  smtpappender.cpp
  strftimedateformat.cpp
  stringhelper.cpp
  stringmatchfilter.cpp
  stringtokenizer.cpp
  system.cpp
  systemerrwriter.cpp
  systemoutwriter.cpp
  threadpatternconverter.cpp
  threadusernamepatternconverter.cpp
  threadspecificdata.cpp
  threadutility.cpp
  throwableinformationpatternconverter.cpp
  timebasedrollingpolicy.cpp
  timezone.cpp
  transcoder.cpp
  transform.cpp
  triggeringpolicy.cpp
  writer.cpp
  writerappender.cpp
  xmllayout.cpp
  zipcompressaction.cpp
  ${extra_classes}
)
if(${log4cxx_ABI_VER} LESS 16)
  target_sources(log4cxx
    PRIVATE
    threadlocal.cpp
  )
endif()
if(LOG4CXX_EVENTS_AT_EXIT)
  target_sources(log4cxx
    PRIVATE atexitregistry.cpp
  )
endif(LOG4CXX_EVENTS_AT_EXIT)

if(WIN32)
  target_sources(log4cxx
    PRIVATE visualstudio.natvis
  )
endif(WIN32)

set(LOG4CXX_LIB_NAME "log4cxx" CACHE STRING "Main library base name")
set_target_properties(log4cxx PROPERTIES
  VERSION ${LIBLOG4CXX_LIB_VERSION}
  SOVERSION ${LIBLOG4CXX_LIB_SOVERSION}
  OUTPUT_NAME ${LOG4CXX_LIB_NAME}
  PDB_NAME ${LOG4CXX_LIB_NAME}
  COMPILE_PDB_NAME ${LOG4CXX_LIB_NAME}
  EXPORT_NAME ${LOG4CXX_LIB_NAME}
)
get_directory_property( FILESYSTEM_IMPL DIRECTORY "${LOG4CXX_SOURCE_DIR}/src/main/include" DEFINITION FILESYSTEM_IMPL )
if("${FILESYSTEM_IMPL}" STREQUAL "std::filesystem" OR
   "${FILESYSTEM_IMPL}" STREQUAL "std::experimental::filesystem" )
  target_link_libraries(log4cxx PUBLIC $<$<AND:$<CXX_COMPILER_ID:GNU>,$<VERSION_LESS:$<CXX_COMPILER_VERSION>,9.0>>:stdc++fs>)
endif()

if(${ENABLE_FMT_LAYOUT})
    target_link_libraries(log4cxx PUBLIC fmt::fmt)
endif()

# --- Safe Buffers Programming Model enforcement ------------------------------
# Translation units below have been migrated to the Safe Buffers Programming
# Model: raw C buffers and pointer arithmetic over untrusted input are replaced
# by bounds-aware views/containers (e.g. std::span).  Compiling them with
# Clang's -Wunsafe-buffer-usage prevents the unsafe patterns from being
# reintroduced.  Append a file to this list once it has been migrated.
set(LOG4CXX_SAFE_BUFFERS_SOURCES
  hexdump.cpp
)

option(LOG4CXX_ENABLE_SAFE_BUFFERS
  "Compile Safe-Buffers-migrated sources with -Wunsafe-buffer-usage (Clang)" OFF)
option(LOG4CXX_SAFE_BUFFERS_AS_ERROR
  "Treat -Wunsafe-buffer-usage as an error in Safe-Buffers-migrated sources" OFF)

if(LOG4CXX_ENABLE_SAFE_BUFFERS)
  if(LOG4CXX_HAS_WUNSAFE_BUFFER_USAGE)
    set(_safe_buffers_flags -Wunsafe-buffer-usage)
    if(LOG4CXX_SAFE_BUFFERS_AS_ERROR)
      list(APPEND _safe_buffers_flags -Werror=unsafe-buffer-usage)
    endif()
    set_source_files_properties(${LOG4CXX_SAFE_BUFFERS_SOURCES}
      PROPERTIES COMPILE_OPTIONS "${_safe_buffers_flags}")
    message(STATUS "Safe Buffers enforcement enabled for: ${LOG4CXX_SAFE_BUFFERS_SOURCES}")
  else()
    message(WARNING
      "LOG4CXX_ENABLE_SAFE_BUFFERS is ON but the compiler does not support "
      "-Wunsafe-buffer-usage; Safe Buffers enforcement is disabled.")
  endif()
endif()
