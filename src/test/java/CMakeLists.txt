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

find_package(Java)
include(UseJava)

include(FetchContent)
FetchContent_Declare(log4j
  URL https://downloads.apache.org/logging/log4j/1.2.17/log4j-1.2.17.tar.gz
  URL_HASH SHA256=a528e3771ee6234661b5eb0fa02e14faee89dfec38de94088c163ddf2a0a8663
)

find_jar(LOG4J NAMES log4j-1.2 DOC "System log4j location")

if(${LOG4J} STREQUAL "LOG4J-NOTFOUND")
  FetchContent_GetProperties(log4j)
  if(NOT log4j_POPULATED)
    FetchContent_Populate(log4j)
  endif()
  set(log4j_CLASSPATH "${log4j_SOURCE_DIR}/log4j-1.2.17.jar" )
else()
  set(log4j_CLASSPATH "${LOG4J}" )
endif()

set(SOCKET_SERVER_SOURCES org/apache/log4j/net/ShortSocketServer.java)
add_custom_target(test-classes
  COMMAND ${Java_JAVAC_EXECUTABLE} -d ${CMAKE_CURRENT_BINARY_DIR}
          -classpath "${log4j_CLASSPATH}" ${SOCKET_SERVER_SOURCES}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
if(WIN32)
  set(SOCKET_SERVER_CLASSPATH "${CMAKE_CURRENT_BINARY_DIR};${log4j_CLASSPATH}")
else()
  set(SOCKET_SERVER_CLASSPATH "${CMAKE_CURRENT_BINARY_DIR}:${log4j_CLASSPATH}")
endif()

# Use a parameter file to avoid issues with processing ';'
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/StartSocketServerParams.txt
"${Java_JAVA_EXECUTABLE}
-classpath
${SOCKET_SERVER_CLASSPATH}
org.apache.log4j.net.ShortSocketServer
8
input/socketServer
"
)
set(START_SOCKET_SERVER_PARAMETER_FILE ${CMAKE_CURRENT_BINARY_DIR}/StartSocketServerParams.txt PARENT_SCOPE)
