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

set(HELPER_TESTS 
    absolutetimedateformattestcase
    cacheddateformattestcase
    casttestcase
    charsetdecodertestcase
    charsetencodertestcase
    cyclicbuffertestcase
    datetimedateformattestcase
    filewatchdogtest
    inetaddresstestcase
    iso8601dateformattestcase
    messagebuffertest
    optionconvertertestcase
    propertiestestcase
    relativetimedateformattestcase
    stringhelpertestcase
    stringtokenizertestcase
    syslogwritertest
    timezonetestcase
    transcodertestcase
    threadutilitytestcase
)
foreach(fileName IN LISTS HELPER_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
    target_compile_definitions(${fileName} PRIVATE ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(${fileName} PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES> ${APR_INCLUDE_DIR})
endforeach()
target_sources(cacheddateformattestcase PRIVATE localechanger.cpp)
target_sources(datetimedateformattestcase PRIVATE  localechanger.cpp)
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} ${HELPER_TESTS} PARENT_SCOPE)
