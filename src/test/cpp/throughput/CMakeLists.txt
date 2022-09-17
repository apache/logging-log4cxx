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

option(BUILD_THROUGHPUT_TESTS "Build throughput tests"  OFF)

if( NOT BUILD_THROUGHPUT_TESTS )
	return()
endif()

find_package(fmt REQUIRED)

add_executable(throughputtests
	throughput-main.cpp
	log4cxxbenchmarker.cpp)

# Note: we need to include the APR DLLs on our path so that the tests will run.
# The way that CMake sets the environment is that it actually generates a secondary file,
# CTestTestfile.cmake, which sets the final properties of the test.
# However, this results in a secondary quirk to the running of the tests: CMake uses
# a semicolon to deliminate entries in a list!  Since the Windows PATH is semicolon-delimited
# as well, CMake uses only the first entry in the list when setting the path.
# So, we need to do a triple escape on the PATH that we want to set in order for CMake to
# properly interpret the PATH
if( WIN32 )
  get_filename_component(APR_DLL_DIR "${APR_DLL}" DIRECTORY)
  get_filename_component(APR_UTIL_DLL_DIR "${APR_UTIL_DLL}" DIRECTORY)
  get_filename_component(EXPAT_LIB_DIR "${EXPAT_LIBRARY}" DIRECTORY)


  set(EXPAT_DLL_DIR "${EXPAT_LIB_DIR}/../bin")
  set(LOG4CXX_DLL_DIR "$<SHELL_PATH:$<TARGET_FILE_DIR:log4cxx>>;")
  set(PATH_FOR_TESTS ${CMAKE_PROGRAM_PATH};${APR_DLL_DIR};${APR_UTIL_DLL_DIR};${LOG4CXX_DLL_DIR};${EXPAT_DLL_DIR}\;)
  list(REMOVE_DUPLICATES PATH_FOR_TESTS)
  set(NORMAL_PATH $ENV{PATH})
  set(ESCAPED_PATH "")
  foreach( ENTRY ${PATH_FOR_TESTS}${NORMAL_PATH} )
	  set(ESCAPED_PATH "${ESCAPED_PATH}${ENTRY}\\\;")
  endforeach()
endif( WIN32 )

target_compile_definitions(throughputtests PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
target_include_directories(throughputtests PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
target_link_libraries(throughputtests PRIVATE log4cxx ${APR_LIBRARIES} ${APR_SYSTEM_LIBS} Threads::Threads fmt::fmt)

add_custom_target(run-throughput COMMAND throughputtests DEPENDS throughputtests)
