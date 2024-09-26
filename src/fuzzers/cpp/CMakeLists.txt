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

set(ALL_LOG4CXX_FUZZERS PatternLayoutFuzzer)

# Get the most recent Git commit ID
execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_ID
    OUTPUT_STRIP_TRAILING_WHITESPACE)

set(FUZZER_SANITIZE_FLAGS "-fsanitize=fuzzer,address,signed-integer-overflow")
set(FUZZER_COMPILE_DEFINITIONS "-DCOMPILE_DEFINITIONS=${FUZZER_SANITIZE_FLAGS}" "-DGIT_COMMIT_ID=\"${GIT_COMMIT_ID}\"")

if(WIN32)
  include(win32_target_environment_path)
  get_target_environment_path(ESCAPED_PATH)
elseif(CMAKE_BUILD_TYPE)
  string(TOUPPER ${CMAKE_BUILD_TYPE} UPPER_BUILD_TYPE)
  if (UPPER_BUILD_TYPE STREQUAL "DEBUG")
    list(APPEND FUZZER_COMPILE_DEFINITIONS _DEBUG)
  endif()
else()
  list(APPEND FUZZER_COMPILE_DEFINITIONS _DEBUG)
endif()

foreach(fuzzerName IN LISTS ALL_LOG4CXX_FUZZERS)
  set(PROGRAM_NAME "${fuzzerName}")
  add_executable(${PROGRAM_NAME} ${fuzzerName}.cpp)
  target_compile_definitions(${PROGRAM_NAME}
    PRIVATE
      ${FUZZER_COMPILE_DEFINITIONS}
      ${LOG4CXX_COMPILE_DEFINITIONS}
      ${APR_COMPILE_DEFINITIONS}
      ${APR_UTIL_COMPILE_DEFINITIONS})
  target_include_directories(${PROGRAM_NAME}
    PRIVATE
      ${CMAKE_CURRENT_LIST_DIR}
      $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
  target_link_libraries(${PROGRAM_NAME}
    PRIVATE
      ${FUZZER_SANITIZE_FLAGS}
      log4cxx
      ${APR_UTIL_LIBRARIES}
      ${EXPAT_LIBRARIES}
      ${APR_LIBRARIES}
      ${APR_SYSTEM_LIBS})
  if(WIN32)
      set_target_properties(${PROGRAM_NAME}
        PROPERTIES
          VS_DEBUGGER_ENVIRONMENT "PATH=${ESCAPED_PATH}"
          VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
          FOLDER Fuzzers)
  endif()
endforeach()
