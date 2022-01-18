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

set(ALL_LOG4CXX_EXAMPLES console delayedloop stream trivial custom-appender)

foreach(exampleName IN LISTS ALL_LOG4CXX_EXAMPLES)
    add_executable(${exampleName} ${exampleName}.cpp)
    target_compile_definitions(${exampleName} PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(${exampleName} PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(${exampleName} PRIVATE log4cxx ${APR_UTIL_LIBRARIES} ${EXPAT_LIBRARIES} ${APR_LIBRARIES} ${APR_SYSTEM_LIBS})
endforeach()

configure_file( custom-appender.xml
    ${CMAKE_CURRENT_BINARY_DIR}/custom-appender.xml
    COPYONLY )

# Custom handling for format string example, since it utilizes libfmt
find_package(fmt QUIET)
if(${fmt_FOUND})
    add_executable( format-string format-string.cpp )
    target_compile_definitions(format-string PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(format-string PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(format-string PRIVATE log4cxx ${APR_UTIL_LIBRARIES} ${EXPAT_LIBRARIES} ${APR_LIBRARIES} ${APR_SYSTEM_LIBS} fmt::fmt)
endif(${fmt_FOUND})
