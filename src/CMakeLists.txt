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
cmake_policy(SET CMP0079 NEW)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/boost-fallback/boost-fallback.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/compiler-features/check-compiler-support.cmake)

add_subdirectory(main)
target_compile_definitions(log4cxx PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
target_include_directories(log4cxx INTERFACE $<INSTALL_INTERFACE:include> PRIVATE ${APR_INCLUDE_DIR} ${APR_UTIL_INCLUDE_DIR})
target_link_libraries(log4cxx PRIVATE ${APR_UTIL_LIBRARIES} ${EXPAT_LIBRARIES} ${APR_LIBRARIES} ${APR_SYSTEM_LIBS})
if(HAS_LIBESMTP)
  target_include_directories(log4cxx PRIVATE ${ESMTP_INCLUDE_DIR})
  target_link_libraries(log4cxx PRIVATE ${ESMTP_LIBRARIES})
endif()
if(HAS_ODBC)
  target_include_directories(log4cxx PRIVATE ${ODBC_INCLUDE_DIR})
  target_link_libraries( log4cxx PRIVATE ${ODBC_LIBRARIES})
endif(HAS_ODBC)

if(BUILD_TESTING)
  add_subdirectory(test)
endif()

option(BUILD_EXAMPLES "Build log4cxx examples" ${BUILD_TESTING})
if(BUILD_EXAMPLES)
  add_subdirectory(examples/cpp)
endif()

add_subdirectory(site)
