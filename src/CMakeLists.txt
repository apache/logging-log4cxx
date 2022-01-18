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

add_subdirectory(main)
target_compile_definitions(log4cxx PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
target_include_directories(log4cxx INTERFACE $<INSTALL_INTERFACE:include> PRIVATE ${APR_INCLUDE_DIR} ${APR_UTIL_INCLUDE_DIR})
target_link_libraries(log4cxx PRIVATE ${APR_UTIL_LIBRARIES} ${EXPAT_LIBRARIES} ${APR_LIBRARIES} ${APR_SYSTEM_LIBS})
if(WIN32)
	# The ODBC appender is always enabled in the Windows configuration
	target_link_libraries(log4cxx PRIVATE odbc32.lib)
	option(LOG4CXX_INSTALL_PDB "Install .pdb files (if generated)"  ON)
else()
	if(${odbc_FOUND})
		target_include_directories(log4cxx PRIVATE ${odbc_INCLUDE_DIRS})
		target_link_directories( log4cxx PRIVATE ${odbc_LIBRARY_DIRS})
		target_link_libraries( log4cxx PRIVATE ${odbc_LIBRARIES})
	endif(${odbc_FOUND})
endif()

if(BUILD_TESTING)
   add_subdirectory(test)
   add_subdirectory(examples/cpp)
endif()

add_subdirectory(site)
