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

# Tests defined in this directory
set(NET_TESTS
    socketappendertestcase
    sockethubappendertestcase
    syslogappendertestcase
    telnetappendertestcase
    xmlsocketappendertestcase
)
if(HAS_LIBESMPT)
    list(APPEND NET_TESTS smtpappendertestcase)
endif(HAS_LIBESMPT)
foreach(fileName IN LISTS NET_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
endforeach()
if(Java_Development_FOUND)
    add_executable(socketservertestcase socketserverstarter.cpp socketservertestcase.cpp)
    add_dependencies(socketservertestcase test-classes)
    list(APPEND NET_TESTS socketservertestcase)
endif()
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} ${NET_TESTS} PARENT_SCOPE)
