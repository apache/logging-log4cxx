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
add_subdirectory(include)
add_subdirectory(cpp)
add_subdirectory(cpp-qt)
add_subdirectory(resources)

# setup include directories 
include(GNUInstallDirs)
target_include_directories(log4cxx PUBLIC 
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(LOG4CXX_CFSTRING)
  if(APPLE)
    target_link_libraries(log4cxx PUBLIC "-framework CoreFoundation")
  else()
    add_subdirectory(mock-apple)
  endif()
endif()

if(LOG4CXX_QT_SUPPORT)
    target_include_directories(log4cxx-qt PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
endif(LOG4CXX_QT_SUPPORT)

option(LOG4CXX_ABI_CHECK "Check for ABI changes" OFF)
if(LOG4CXX_ABI_CHECK)
  if(NOT "log4cxx" STREQUAL "${LOG4CXX_NS}")
    message(FATAL_ERROR "ABI compatability can only be checked if LOG4CXX_NS=log4cxx, but LOG4CXX_NS=${LOG4CXX_NS}.")
  endif()
  add_subdirectory(abi-symbols)
endif(LOG4CXX_ABI_CHECK)
