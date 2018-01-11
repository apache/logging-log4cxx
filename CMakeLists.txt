#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#

cmake_minimum_required(VERSION 3.1)
set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(PROJECT_DESCRIPTION "Apache Logging Framework for C++")
set(PROJECT_NAME        "log4cxx")
set(PROJECT_LICENSE     "Apache Software License 2.0")
set(PROJECT_LICURL      "http://www.apache.org/licenses/LICENSE-2.0")
set(PROJECT_URL         "http://logging.apache.org/log4cxx/")

include(ExtractVersion)
extract_version(PROJECT_VERSION)

message(STATUS "Configuring build environment for ${PROJECT_NAME} version ${PROJECT_VERSION}")

### project

project(${PROJECT_NAME} VERSION ${PROJECT_VERSION})

### options

option(BUILD_SHARED_LIBS "Build shared libraries instead of static" ON)
option(MSVC_SHARED_RUNTIME "Build using shared Microsoft Runtime (MSVC-only)" ON)

### dependencies

# The APR CMake build drops static and shared libraries into the same location
# when processing the install target and they have different names on Windows.
if (MSVC AND BUILD_SHARED_LIBS)
  set(APR2_LIBNAMES "libapr-2")
endif ()

find_package(APR2 REQUIRED)

### includes

include(LanguageSpecific)
include(PlatformSpecific)
include(Summary)

### targets

set(LOG4CXX_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/main")

configure_file("${LOG4CXX_DIR}/include/log4cxx/log4cxx.hw"
  "${CMAKE_CURRENT_BINARY_DIR}/include/log4cxx/log4cxx.h"
  COPYONLY
)

configure_file("${LOG4CXX_DIR}/include/log4cxx/private/log4cxx_private.hw"
  "${CMAKE_CURRENT_BINARY_DIR}/include/log4cxx/private/log4cxx_private.h"
  COPYONLY
)

set(LOG4CXX_INCLUDE_DIRECTORIES
  ${LOG4CXX_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/include
  ${APR2_INCLUDE_DIRS}
  )

set(LOG4CXX_HEADERS
  ${LOG4CXX_DIR}/include/log4cxx/appender.h
  ${LOG4CXX_DIR}/include/log4cxx/appenderskeleton.h
  ${LOG4CXX_DIR}/include/log4cxx/asyncappender.h
  ${LOG4CXX_DIR}/include/log4cxx/basicconfigurator.h
  ${LOG4CXX_DIR}/include/log4cxx/config/propertysetter.h
  ${LOG4CXX_DIR}/include/log4cxx/consoleappender.h
  ${LOG4CXX_DIR}/include/log4cxx/dailyrollingfileappender.h
  ${LOG4CXX_DIR}/include/log4cxx/db/odbcappender.h
  ${LOG4CXX_DIR}/include/log4cxx/defaultconfigurator.h
  ${LOG4CXX_DIR}/include/log4cxx/defaultloggerfactory.h
  ${LOG4CXX_DIR}/include/log4cxx/fileappender.h
  ${LOG4CXX_DIR}/include/log4cxx/file.h
  ${LOG4CXX_DIR}/include/log4cxx/filter/andfilter.h
  ${LOG4CXX_DIR}/include/log4cxx/filter/denyallfilter.h
  ${LOG4CXX_DIR}/include/log4cxx/filter/expressionfilter.h
  ${LOG4CXX_DIR}/include/log4cxx/filter/levelmatchfilter.h
  ${LOG4CXX_DIR}/include/log4cxx/filter/levelrangefilter.h
  ${LOG4CXX_DIR}/include/log4cxx/filter/locationinfofilter.h
  ${LOG4CXX_DIR}/include/log4cxx/filter/loggermatchfilter.h
  ${LOG4CXX_DIR}/include/log4cxx/filter/mapfilter.h
  ${LOG4CXX_DIR}/include/log4cxx/filter/propertyfilter.h
  ${LOG4CXX_DIR}/include/log4cxx/filter/stringmatchfilter.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/absolutetimedateformat.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/appenderattachableimpl.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/aprinitializer.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/bufferedoutputstream.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/bufferedwriter.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/bytearrayinputstream.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/bytearrayoutputstream.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/bytebuffer.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/cacheddateformat.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/charsetdecoder.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/charsetencoder.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/class.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/classregistration.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/condition.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/cyclicbuffer.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/datagrampacket.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/datagramsocket.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/dateformat.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/date.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/datelayout.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/datetimedateformat.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/exception.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/fileinputstream.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/fileoutputstream.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/filewatchdog.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/inetaddress.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/inputstream.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/inputstreamreader.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/integer.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/iso8601dateformat.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/loader.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/locale.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/loglog.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/messagebuffer.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/mutex.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/object.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/objectimpl.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/objectoutputstream.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/objectptr.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/onlyonceerrorhandler.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/optionconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/outputstream.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/outputstreamwriter.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/pool.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/properties.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/propertyresourcebundle.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/reader.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/relativetimedateformat.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/resourcebundle.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/serversocket.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/simpledateformat.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/socket.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/socketoutputstream.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/strftimedateformat.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/strictmath.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/stringhelper.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/stringtokenizer.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/synchronized.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/syslogwriter.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/systemerrwriter.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/system.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/systemoutwriter.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/tchar.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/thread.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/threadlocal.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/threadspecificdata.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/timezone.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/transcoder.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/transform.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/writer.h
  ${LOG4CXX_DIR}/include/log4cxx/helpers/xml.h
  ${LOG4CXX_DIR}/include/log4cxx/hierarchy.h
  ${LOG4CXX_DIR}/include/log4cxx/htmllayout.h
  ${LOG4CXX_DIR}/include/log4cxx/layout.h
  ${LOG4CXX_DIR}/include/log4cxx/level.h
  ${LOG4CXX_DIR}/include/log4cxx/logger.h
  ${LOG4CXX_DIR}/include/log4cxx/logmanager.h
  ${LOG4CXX_DIR}/include/log4cxx/logstring.h
  ${LOG4CXX_DIR}/include/log4cxx/mdc.h
  ${LOG4CXX_DIR}/include/log4cxx/ndc.h
  ${LOG4CXX_DIR}/include/log4cxx/net/smtpappender.h
  ${LOG4CXX_DIR}/include/log4cxx/net/socketappender.h
  ${LOG4CXX_DIR}/include/log4cxx/net/socketappenderskeleton.h
  ${LOG4CXX_DIR}/include/log4cxx/net/sockethubappender.h
  ${LOG4CXX_DIR}/include/log4cxx/net/syslogappender.h
  ${LOG4CXX_DIR}/include/log4cxx/net/telnetappender.h
  ${LOG4CXX_DIR}/include/log4cxx/net/xmlsocketappender.h
  ${LOG4CXX_DIR}/include/log4cxx/nt/nteventlogappender.h
  ${LOG4CXX_DIR}/include/log4cxx/nt/outputdebugstringappender.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/classnamepatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/datepatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/filedatepatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/filelocationpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/formattinginfo.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/fulllocationpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/integerpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/patternlayout.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/levelpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/linelocationpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/lineseparatorpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/literalpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/loggerpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/loggingeventpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/messagepatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/methodlocationpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/nameabbreviator.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/namepatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/ndcpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/patternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/patternparser.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/propertiespatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/relativetimepatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/threadpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/pattern/throwableinformationpatternconverter.h
  ${LOG4CXX_DIR}/include/log4cxx/portability.h
  ${LOG4CXX_DIR}/include/log4cxx/propertyconfigurator.h
  ${LOG4CXX_DIR}/include/log4cxx/provisionnode.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/action.h
  ${LOG4CXX_DIR}/include/log4cxx/rollingfileappender.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/filerenameaction.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/filterbasedtriggeringpolicy.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/fixedwindowrollingpolicy.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/gzcompressaction.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/manualtriggeringpolicy.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/rollingfileappender.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/rollingfileappenderskeleton.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/rollingpolicybase.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/rollingpolicy.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/rolloverdescription.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/sizebasedtriggeringpolicy.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/timebasedrollingpolicy.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/triggeringpolicy.h
  ${LOG4CXX_DIR}/include/log4cxx/rolling/zipcompressaction.h
  ${LOG4CXX_DIR}/include/log4cxx/simplelayout.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/appenderattachable.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/configurator.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/defaultrepositoryselector.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/errorhandler.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/filter.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/hierarchyeventlistener.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/location/locationinfo.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/loggerfactory.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/loggerrepository.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/loggingevent.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/optionhandler.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/repositoryselector.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/rootlogger.h
  ${LOG4CXX_DIR}/include/log4cxx/spi/triggeringeventevaluator.h
  ${LOG4CXX_DIR}/include/log4cxx/stream.h
  ${LOG4CXX_DIR}/include/log4cxx/ttcclayout.h
  ${LOG4CXX_DIR}/include/log4cxx/varia/fallbackerrorhandler.h
  ${LOG4CXX_DIR}/include/log4cxx/writerappender.h
  ${LOG4CXX_DIR}/include/log4cxx/xml/domconfigurator.h
  ${LOG4CXX_DIR}/include/log4cxx/xml/xmllayout.h
)

set(LOG4CXX_SRC
  ${LOG4CXX_DIR}/cpp/action.cpp
  ${LOG4CXX_DIR}/cpp/andfilter.cpp
  ${LOG4CXX_DIR}/cpp/appenderattachableimpl.cpp
  ${LOG4CXX_DIR}/cpp/appenderskeleton.cpp
  ${LOG4CXX_DIR}/cpp/aprinitializer.cpp
  ${LOG4CXX_DIR}/cpp/asyncappender.cpp
  ${LOG4CXX_DIR}/cpp/basicconfigurator.cpp
  ${LOG4CXX_DIR}/cpp/bufferedwriter.cpp
  ${LOG4CXX_DIR}/cpp/bytearrayinputstream.cpp
  ${LOG4CXX_DIR}/cpp/bytearrayoutputstream.cpp
  ${LOG4CXX_DIR}/cpp/bytebuffer.cpp
  ${LOG4CXX_DIR}/cpp/cacheddateformat.cpp
  ${LOG4CXX_DIR}/cpp/charsetdecoder.cpp
  ${LOG4CXX_DIR}/cpp/charsetencoder.cpp
  ${LOG4CXX_DIR}/cpp/class.cpp
  ${LOG4CXX_DIR}/cpp/classnamepatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/classregistration.cpp
  ${LOG4CXX_DIR}/cpp/condition.cpp
  ${LOG4CXX_DIR}/cpp/configurator.cpp
  ${LOG4CXX_DIR}/cpp/consoleappender.cpp
  ${LOG4CXX_DIR}/cpp/cyclicbuffer.cpp
  ${LOG4CXX_DIR}/cpp/dailyrollingfileappender.cpp
  ${LOG4CXX_DIR}/cpp/datagrampacket.cpp
  ${LOG4CXX_DIR}/cpp/datagramsocket.cpp
  ${LOG4CXX_DIR}/cpp/date.cpp
  ${LOG4CXX_DIR}/cpp/dateformat.cpp
  ${LOG4CXX_DIR}/cpp/datelayout.cpp
  ${LOG4CXX_DIR}/cpp/datepatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/defaultconfigurator.cpp
  ${LOG4CXX_DIR}/cpp/defaultloggerfactory.cpp
  ${LOG4CXX_DIR}/cpp/defaultrepositoryselector.cpp
  ${LOG4CXX_DIR}/cpp/domconfigurator.cpp
  ${LOG4CXX_DIR}/cpp/exception.cpp
  ${LOG4CXX_DIR}/cpp/fallbackerrorhandler.cpp
  ${LOG4CXX_DIR}/cpp/fileappender.cpp
  ${LOG4CXX_DIR}/cpp/file.cpp
  ${LOG4CXX_DIR}/cpp/filedatepatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/fileinputstream.cpp
  ${LOG4CXX_DIR}/cpp/filelocationpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/fileoutputstream.cpp
  ${LOG4CXX_DIR}/cpp/filerenameaction.cpp
  ${LOG4CXX_DIR}/cpp/filewatchdog.cpp
  ${LOG4CXX_DIR}/cpp/filterbasedtriggeringpolicy.cpp
  ${LOG4CXX_DIR}/cpp/filter.cpp
  ${LOG4CXX_DIR}/cpp/fixedwindowrollingpolicy.cpp
  ${LOG4CXX_DIR}/cpp/formattinginfo.cpp
  ${LOG4CXX_DIR}/cpp/fulllocationpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/gzcompressaction.cpp
  ${LOG4CXX_DIR}/cpp/hierarchy.cpp
  ${LOG4CXX_DIR}/cpp/htmllayout.cpp
  ${LOG4CXX_DIR}/cpp/inetaddress.cpp
  ${LOG4CXX_DIR}/cpp/inputstream.cpp
  ${LOG4CXX_DIR}/cpp/inputstreamreader.cpp
  ${LOG4CXX_DIR}/cpp/integer.cpp
  ${LOG4CXX_DIR}/cpp/integerpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/layout.cpp
  ${LOG4CXX_DIR}/cpp/level.cpp
  ${LOG4CXX_DIR}/cpp/levelmatchfilter.cpp
  ${LOG4CXX_DIR}/cpp/levelpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/levelrangefilter.cpp
  ${LOG4CXX_DIR}/cpp/linelocationpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/lineseparatorpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/literalpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/loader.cpp
  ${LOG4CXX_DIR}/cpp/locale.cpp
  ${LOG4CXX_DIR}/cpp/locationinfo.cpp
  ${LOG4CXX_DIR}/cpp/logger.cpp
  ${LOG4CXX_DIR}/cpp/loggermatchfilter.cpp
  ${LOG4CXX_DIR}/cpp/loggerpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/loggingevent.cpp
  ${LOG4CXX_DIR}/cpp/loggingeventpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/loglog.cpp
  ${LOG4CXX_DIR}/cpp/logmanager.cpp
  ${LOG4CXX_DIR}/cpp/logstream.cpp
  ${LOG4CXX_DIR}/cpp/manualtriggeringpolicy.cpp
  ${LOG4CXX_DIR}/cpp/mdc.cpp
  ${LOG4CXX_DIR}/cpp/messagebuffer.cpp
  ${LOG4CXX_DIR}/cpp/messagepatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/methodlocationpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/mutex.cpp
  ${LOG4CXX_DIR}/cpp/nameabbreviator.cpp
  ${LOG4CXX_DIR}/cpp/namepatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/ndc.cpp
  ${LOG4CXX_DIR}/cpp/ndcpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/nteventlogappender.cpp
  ${LOG4CXX_DIR}/cpp/objectimpl.cpp
  ${LOG4CXX_DIR}/cpp/objectoutputstream.cpp
  ${LOG4CXX_DIR}/cpp/objectptr.cpp
  ${LOG4CXX_DIR}/cpp/obsoleterollingfileappender.cpp
  ${LOG4CXX_DIR}/cpp/odbcappender.cpp
  ${LOG4CXX_DIR}/cpp/onlyonceerrorhandler.cpp
  ${LOG4CXX_DIR}/cpp/optionconverter.cpp
  ${LOG4CXX_DIR}/cpp/outputdebugstringappender.cpp
  ${LOG4CXX_DIR}/cpp/outputstream.cpp
  ${LOG4CXX_DIR}/cpp/outputstreamwriter.cpp
  ${LOG4CXX_DIR}/cpp/patternconverter.cpp
  ${LOG4CXX_DIR}/cpp/patternlayout.cpp
  ${LOG4CXX_DIR}/cpp/patternparser.cpp
  ${LOG4CXX_DIR}/cpp/pool.cpp
  ${LOG4CXX_DIR}/cpp/properties.cpp
  ${LOG4CXX_DIR}/cpp/propertiespatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/propertyconfigurator.cpp
  ${LOG4CXX_DIR}/cpp/propertyresourcebundle.cpp
  ${LOG4CXX_DIR}/cpp/propertysetter.cpp
  ${LOG4CXX_DIR}/cpp/reader.cpp
  ${LOG4CXX_DIR}/cpp/relativetimedateformat.cpp
  ${LOG4CXX_DIR}/cpp/relativetimepatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/resourcebundle.cpp
  ${LOG4CXX_DIR}/cpp/rollingfileappender.cpp
  ${LOG4CXX_DIR}/cpp/rollingpolicybase.cpp
  ${LOG4CXX_DIR}/cpp/rollingpolicy.cpp
  ${LOG4CXX_DIR}/cpp/rolloverdescription.cpp
  ${LOG4CXX_DIR}/cpp/rootlogger.cpp
  ${LOG4CXX_DIR}/cpp/serversocket.cpp
  ${LOG4CXX_DIR}/cpp/simpledateformat.cpp
  ${LOG4CXX_DIR}/cpp/simplelayout.cpp
  ${LOG4CXX_DIR}/cpp/sizebasedtriggeringpolicy.cpp
  ${LOG4CXX_DIR}/cpp/smtpappender.cpp
  ${LOG4CXX_DIR}/cpp/socketappender.cpp
  ${LOG4CXX_DIR}/cpp/socketappenderskeleton.cpp
  ${LOG4CXX_DIR}/cpp/socket.cpp
  ${LOG4CXX_DIR}/cpp/sockethubappender.cpp
  ${LOG4CXX_DIR}/cpp/socketoutputstream.cpp
  ${LOG4CXX_DIR}/cpp/strftimedateformat.cpp
  ${LOG4CXX_DIR}/cpp/stringhelper.cpp
  ${LOG4CXX_DIR}/cpp/stringmatchfilter.cpp
  ${LOG4CXX_DIR}/cpp/stringtokenizer.cpp
  ${LOG4CXX_DIR}/cpp/synchronized.cpp
  ${LOG4CXX_DIR}/cpp/syslogappender.cpp
  ${LOG4CXX_DIR}/cpp/syslogwriter.cpp
  ${LOG4CXX_DIR}/cpp/system.cpp
  ${LOG4CXX_DIR}/cpp/systemerrwriter.cpp
  ${LOG4CXX_DIR}/cpp/systemoutwriter.cpp
  ${LOG4CXX_DIR}/cpp/telnetappender.cpp
  ${LOG4CXX_DIR}/cpp/threadcxx.cpp
  ${LOG4CXX_DIR}/cpp/threadlocal.cpp
  ${LOG4CXX_DIR}/cpp/threadpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/threadspecificdata.cpp
  ${LOG4CXX_DIR}/cpp/throwableinformationpatternconverter.cpp
  ${LOG4CXX_DIR}/cpp/timebasedrollingpolicy.cpp
  ${LOG4CXX_DIR}/cpp/timezone.cpp
  ${LOG4CXX_DIR}/cpp/transcoder.cpp
  ${LOG4CXX_DIR}/cpp/transform.cpp
  ${LOG4CXX_DIR}/cpp/triggeringpolicy.cpp
  ${LOG4CXX_DIR}/cpp/ttcclayout.cpp
  ${LOG4CXX_DIR}/cpp/writerappender.cpp
  ${LOG4CXX_DIR}/cpp/writer.cpp
  ${LOG4CXX_DIR}/cpp/xmllayout.cpp
  ${LOG4CXX_DIR}/cpp/xmlsocketappender.cpp
  ${LOG4CXX_DIR}/cpp/zipcompressaction.cpp
)

add_library(${PROJECT_NAME} ${LOG4CXX_SRC} ${LOG4CXX_HEADERS})
target_include_directories(${PROJECT_NAME} PUBLIC ${LOG4CXX_INCLUDE_DIRECTORIES})
target_link_libraries(${PROJECT_NAME}
  ${APR2_LIBRARIES}
  odbc32
# rpcrt4
# ws2_32
)

install(
  TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/include/log4cxx/log4cxx.h"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/include/log4cxx/"
  PERMISSIONS OWNER_READ GROUP_READ WORLD_READ OWNER_WRITE
)

install(
  DIRECTORY "${LOG4CXX_DIR}/include/"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/include/"
  DIRECTORY_PERMISSIONS OWNER_READ GROUP_READ WORLD_READ OWNER_WRITE
  FILES_MATCHING PATTERN "*.h"
                 PATTERN "*/private/*" EXCLUDE
  PERMISSIONS OWNER_READ GROUP_READ WORLD_READ OWNER_WRITE
)

#if(MSVC)
#  install (FILES "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_BUILD_TYPE}/${PROJECT_NAME}*.pdb" DESTINATION ${CMAKE_INSTALL_LIBDIR} CONFIGURATIONS Debug RelWithDebInfo)
#endif()

summary()
