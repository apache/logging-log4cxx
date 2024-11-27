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

file(RELATIVE_PATH LOG4CXX_REL_BIN_TO_SRC_DIR "${LOG4CXX_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}")

find_package( Doxygen REQUIRED dot )

set(LOG4CXX_SOURCE_PACKAGE_FILE_NAME "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}")
set(LOG4CXX_SOURCE_MIRROR_URL "https://www.apache.org/dyn/closer.cgi/logging/log4cxx/${LOG4CXX_RELEASE_VERSION}/${LOG4CXX_SOURCE_PACKAGE_FILE_NAME}")
set(APACHE_LOGGING_DISTRIBUTION_URL "https://www.apache.org/dist/logging")
set(LOG4CXX_DOCUMENTATION_URL "https://logging.apache.org/log4cxx")
set(LOG4CXX_DISTRIBUTION_URL "${APACHE_LOGGING_DISTRIBUTION_URL}/log4cxx/${LOG4CXX_RELEASE_VERSION}/${LOG4CXX_SOURCE_PACKAGE_FILE_NAME}")
set(LOG4CXX_RELEASE_MANAGER "ASF Logging Services RM")
set(LOG4CXX_RELEASE_MANAGER_KEY "077E8893A6DCC33DD4A4D5B256E73BA9A0B592D0")

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doxy/Doxyfile.in
    ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile )

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/markdown/download.md.in
    ${CMAKE_CURRENT_BINARY_DIR}/markdown/download.md )

add_custom_target( doc_doxygen ALL
    COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${LOG4CXX_SOURCE_DIR}
    COMMENT "Generate site with Doxygen"
    VERBATIM )
