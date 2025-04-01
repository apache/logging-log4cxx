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

# Options
option(LOG4CXX_ABI_CHECK "Check for ABI changes" OFF)

set(foundation_classes
  class.cpp
  date.cpp
  appenderattachableimpl.cpp
  appenderskeleton.cpp
  aprinitializer.cpp
  bytebuffer.cpp
  charsetdecoder.cpp
  charsetencoder.cpp
  classregistration.cpp
  configurator.cpp
  defaultconfigurator.cpp
  defaultloggerfactory.cpp
  defaultrepositoryselector.cpp
  exception.cpp
  fallbackerrorhandler.cpp
  file.cpp
  fileinputstream.cpp
  fileoutputstream.cpp
  filewatchdog.cpp
  filter.cpp
  hierarchy.cpp
  inetaddress.cpp
  inputstream.cpp
  inputstreamreader.cpp
  layout.cpp
  level.cpp
  loader.cpp
  locale.cpp
  locationinfo.cpp
  logger.cpp
  loggingevent.cpp
  loglog.cpp
  logmanager.cpp
  mdc.cpp
  ndc.cpp
  onlyonceerrorhandler.cpp
  optionconverter.cpp
  outputstream.cpp
  pool.cpp
  properties.cpp
  propertyresourcebundle.cpp
  reader.cpp
  resourcebundle.cpp
  rollingpolicy.cpp
  rootlogger.cpp
  stringhelper.cpp
  system.cpp
  systemerrwriter.cpp
  systemoutwriter.cpp
  threadspecificdata.cpp
  threadutility.cpp
  transcoder.cpp
  triggeringpolicy.cpp
  writer.cpp
)

option(BUILD_FOUNDATION_LIBRARY "Build a minimal part of the log4cxx library" OFF)
if(BUILD_FOUNDATION_LIBRARY)
    add_library(log4cxx_foundation)
    set(LOG4CXX_FOUNDATION_NAME "log4cxx_foundation")
    set_target_properties(log4cxx_foundation PROPERTIES
      VERSION ${LIBLOG4CXX_LIB_VERSION}
      SOVERSION ${LIBLOG4CXX_LIB_SOVERSION}
      OUTPUT_NAME ${LOG4CXX_FOUNDATION_NAME}
      PDB_NAME ${LOG4CXX_FOUNDATION_NAME}
      COMPILE_PDB_NAME ${LOG4CXX_FOUNDATION_NAME}
      EXPORT_NAME ${LOG4CXX_FOUNDATION_NAME}
    )
    target_sources(log4cxx_foundation PRIVATE ${foundation_classes})
    target_include_directories(log4cxx_foundation
      PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/../include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
      INTERFACE
        $<INSTALL_INTERFACE:include>
      PRIVATE
        ${APR_INCLUDE_DIR}
        ${APR_UTIL_INCLUDE_DIR}
    )
    target_compile_definitions(log4cxx_foundation
      PRIVATE
        LOG4CXX
        LOG4CXX_FOUNDATION_ONLY
        ${LOG4CXX_COMPILE_DEFINITIONS}
        ${APR_COMPILE_DEFINITIONS}
        ${APR_UTIL_COMPILE_DEFINITIONS}
    )
    target_link_libraries(log4cxx_foundation
      PRIVATE
        ${APR_UTIL_LIBRARIES}
        ${EXPAT_LIBRARIES}
        ${APR_LIBRARIES}
        ${APR_SYSTEM_LIBS}
    )
endif(BUILD_FOUNDATION_LIBRARY)

# Build the log4cxx library
add_library(log4cxx)
if(${log4cxx_ABI_VER} GREATER 15)
  set_target_properties(log4cxx PROPERTIES CXX_VISIBILITY_PRESET hidden)
endif()
if(BUILD_SHARED_LIBS)
    target_compile_definitions(log4cxx PRIVATE LOG4CXX)
    if(UNIX AND NOT APPLE)
        # Make defined symbols non-preemptible, which can optimize relocation processing
        target_link_options(log4cxx PRIVATE "LINKER:-Bsymbolic")
    endif()
else()
    target_compile_definitions(log4cxx PUBLIC LOG4CXX_STATIC)
endif()
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
  ${foundation_classes}
  action.cpp
  andfilter.cpp
  asyncappender.cpp
  basicconfigurator.cpp
  bufferedwriter.cpp
  bytearrayinputstream.cpp
  bytearrayoutputstream.cpp
  cacheddateformat.cpp
  classnamepatternconverter.cpp
  colorstartpatternconverter.cpp
  colorendpatternconverter.cpp
  consoleappender.cpp
  cyclicbuffer.cpp
  dateformat.cpp
  datepatternconverter.cpp
  dbappender.cpp
  fileappender.cpp
  filedatepatternconverter.cpp
  filelocationpatternconverter.cpp
  filerenameaction.cpp
  filterbasedtriggeringpolicy.cpp
  fixedwindowrollingpolicy.cpp
  formattinginfo.cpp
  fulllocationpatternconverter.cpp
  gzcompressaction.cpp
  hexdump.cpp
  htmllayout.cpp
  integer.cpp
  integerpatternconverter.cpp
  jsonlayout.cpp
  levelmatchfilter.cpp
  levelpatternconverter.cpp
  levelrangefilter.cpp
  linelocationpatternconverter.cpp
  lineseparatorpatternconverter.cpp
  literalpatternconverter.cpp
  locationinfofilter.cpp
  loggermatchfilter.cpp
  loggerpatternconverter.cpp
  loggingeventpatternconverter.cpp
  logstream.cpp
  manualtriggeringpolicy.cpp
  mapfilter.cpp
  messagebuffer.cpp
  messagepatternconverter.cpp
  methodlocationpatternconverter.cpp
  nameabbreviator.cpp
  namepatternconverter.cpp
  mdcpatternconverter.cpp
  ndcpatternconverter.cpp
  nteventlogappender.cpp
  odbcappender.cpp
  outputdebugstringappender.cpp
  outputstream.cpp
  outputstreamwriter.cpp
  patternconverter.cpp
  patternlayout.cpp
  patternparser.cpp
  propertiespatternconverter.cpp
  propertyconfigurator.cpp
  propertysetter.cpp
  relativetimedateformat.cpp
  relativetimepatternconverter.cpp
  rollingfileappender.cpp
  rollingpolicybase.cpp
  rolloverdescription.cpp
  shortfilelocationpatternconverter.cpp
  simpledateformat.cpp
  simplelayout.cpp
  sizebasedtriggeringpolicy.cpp
  smtpappender.cpp
  strftimedateformat.cpp
  stringmatchfilter.cpp
  stringtokenizer.cpp
  threadlocal.cpp
  threadpatternconverter.cpp
  threadusernamepatternconverter.cpp
  throwableinformationpatternconverter.cpp
  timebasedrollingpolicy.cpp
  timezone.cpp
  transform.cpp
  writerappender.cpp
  xmllayout.cpp
  zipcompressaction.cpp
  ${extra_classes}
)
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

if(LOG4CXX_ABI_CHECK)
    if(NOT "log4cxx" STREQUAL "${LOG4CXX_NS}")
      message(FATAL_ERROR "ABI compatability can only be checked if LOG4CXX_NS=log4cxx, but LOG4CXX_NS=${LOG4CXX_NS}.")
    endif()

    message("Getting dependencies for ABI compatability check...")
    # Get the latest version of abi-dumper and abi-compliance-checker
    include(FetchContent)
    FetchContent_Declare(abi-dumper
      GIT_REPOSITORY https://github.com/lvc/abi-dumper.git
      GIT_TAG 1.4
    )
    FetchContent_GetProperties(abi-dumper)
    if(NOT abi-dumper_POPULATED)
      FetchContent_MakeAvailable(abi-dumper)
    endif()

    FetchContent_Declare(abi-compliance-checker
      GIT_REPOSITORY https://github.com/lvc/abi-compliance-checker.git
      GIT_TAG f60ce442c33f1d5cda1cec7cfddee24af1777572
    )
    FetchContent_GetProperties(abi-compliance-checker)
    if(NOT abi-compliance-checker_POPULATED)
      FetchContent_MakeAvailable(abi-compliance-checker)
    endif()

    set(abi-dumper-script ${abi-dumper_SOURCE_DIR}/abi-dumper.pl)
    set(abi-compliance-script ${abi-compliance-checker_SOURCE_DIR}/abi-compliance-checker.pl)

    add_custom_target(dump-abi ALL
        COMMAND perl ${abi-dumper-script} -public-headers public_header_files.txt -o new-abi.dump -skip-cxx -vnum ${log4cxx_ABI_VER} $<TARGET_FILE:log4cxx>
        DEPENDS log4cxx
        COMMENT "Dumping ABI symbols")

    add_custom_target(compare-abi ALL
        COMMAND perl ${abi-compliance-script} -skip-internal-symbols "\\d\\(fmt\\)" -skip-internal-types "\\(fmt\\)::" -l log4cxx -old ${LOG4CXX_SOURCE_DIR}/src/main/abi-symbols/abi.dump -new new-abi.dump
        DEPENDS dump-abi
        COMMENT "Comparing ABI symbols")
endif(LOG4CXX_ABI_CHECK)
