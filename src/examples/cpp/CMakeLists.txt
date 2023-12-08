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

set(ALL_LOG4CXX_EXAMPLES auto-configured console delayedloop stream ndc-example custom-appender MyApp1 MyApp2)
if(NOT LOG4CXX_DOMCONFIGURATOR_SUPPORT)
    list(REMOVE_ITEM ALL_LOG4CXX_EXAMPLES delayedloop custom-appender)
endif()

if(LOG4CXX_QT_SUPPORT)
  list(APPEND ALL_LOG4CXX_EXAMPLES MyApp-qt)
endif(LOG4CXX_QT_SUPPORT)
if( WIN32 )
    include(win32_target_environment_path)
    get_target_environment_path(ESCAPED_PATH)
elseif(CMAKE_BUILD_TYPE)
  string(TOUPPER ${CMAKE_BUILD_TYPE} UPPER_BUILD_TYPE)
  if (UPPER_BUILD_TYPE STREQUAL "DEBUG")
    set(EXAMPLE_COMPILE_DEFINITIONS _DEBUG)
  endif()
else()
  set(EXAMPLE_COMPILE_DEFINITIONS _DEBUG)
endif()

foreach(exampleName IN LISTS ALL_LOG4CXX_EXAMPLES)
    set(PROGRAM_NAME "${exampleName}")
    add_executable(${PROGRAM_NAME} ${exampleName}.cpp)
    if(${exampleName} STREQUAL MyApp2)
        target_sources(${PROGRAM_NAME} PRIVATE com/foo/config2.cpp com/foo/bar.cpp)
    endif()
    if(${exampleName} STREQUAL MyApp-qt)
        target_sources(${PROGRAM_NAME} PRIVATE com/foo/config-qt.cpp com/foo/bar-qt.cpp)
        target_link_libraries(${PROGRAM_NAME} PRIVATE log4cxx-qt)
    endif()
    if(${exampleName} STREQUAL auto-configured)
        target_sources(${PROGRAM_NAME} PRIVATE com/foo/config3.cpp )
    endif()
    target_compile_definitions(${PROGRAM_NAME} PRIVATE ${EXAMPLE_COMPILE_DEFINITIONS} ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(${PROGRAM_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(${PROGRAM_NAME} PRIVATE log4cxx ${APR_UTIL_LIBRARIES} ${EXPAT_LIBRARIES} ${APR_LIBRARIES} ${APR_SYSTEM_LIBS})
    if( WIN32 )
        set_target_properties(${PROGRAM_NAME} PROPERTIES
          VS_DEBUGGER_ENVIRONMENT "PATH=${ESCAPED_PATH}"
          VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
          FOLDER Examples
        )
    endif()
endforeach()

# Custom handling for format string example, since it utilizes libfmt
if(${fmt_FOUND})
    add_executable( format-string format-string.cpp )
    target_compile_definitions(format-string PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(format-string PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(format-string PRIVATE log4cxx ${APR_UTIL_LIBRARIES} ${EXPAT_LIBRARIES} ${APR_LIBRARIES} ${APR_SYSTEM_LIBS} fmt::fmt)
    if( WIN32 )
        set_target_properties( format-string PROPERTIES
          VS_DEBUGGER_ENVIRONMENT "PATH=${ESCAPED_PATH}"
          VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
          FOLDER Examples
        )
    endif()
endif(${fmt_FOUND})
