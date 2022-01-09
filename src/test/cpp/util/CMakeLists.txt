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

# Components required by all tests
add_library(testingUtilities STATIC
    serializationtesthelper.cpp
    absolutedateandtimefilter.cpp
    absolutetimefilter.cpp
    binarycompare.cpp
    compare.cpp
    controlfilter.cpp
    filenamefilter.cpp
    iso8601filter.cpp
    linenumberfilter.cpp
    relativetimefilter.cpp
    threadfilter.cpp
    transformer.cpp
    utilfilter.cpp
    xmlfilenamefilter.cpp
    xmllineattributefilter.cpp
    xmlthreadfilter.cpp
    xmltimestampfilter.cpp
)
target_compile_definitions(testingUtilities PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
target_include_directories(testingUtilities PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
