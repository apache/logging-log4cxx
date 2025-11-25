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

set(APACHE_LOGGING_DOWNLOAD_URL "https://downloads.apache.org/logging/")
set(LOG4CXX_SOURCE_PACKAGE_FILE_NAME "apache-log4cxx-${LOG4CXX_RELEASE_VERSION}")
set(LOG4CXX_SOURCE_MIRROR_URL "https://www.apache.org/dyn/closer.cgi/logging/log4cxx/${LOG4CXX_RELEASE_VERSION}")
set(LOG4CXX_SOURCE_MIRROR_FILE "${LOG4CXX_SOURCE_MIRROR_URL}/${LOG4CXX_SOURCE_PACKAGE_FILE_NAME}")
set(LOG4CXX_DOCUMENTATION_URL "https://logging.apache.org/log4cxx")
set(LOG4CXX_DISTRIBUTION_URL "${APACHE_LOGGING_DOWNLOAD_URL}/log4cxx/${LOG4CXX_RELEASE_VERSION}/${LOG4CXX_SOURCE_PACKAGE_FILE_NAME}")
set(LOG4CXX_RELEASE_MANAGER "ASF Logging Services RM")
set(LOG4CXX_RELEASE_MANAGER_KEY "077E8893A6DCC33DD4A4D5B256E73BA9A0B592D0")

set(EXPAT_DOWNLOAD_URL "https://github.com/libexpat/libexpat/releases")
set(EXPAT_RELEASE_VERSION "2.7.1")
set(EXPAT_SOURCE_PACKAGE_FILE_NAME "expat-${EXPAT_RELEASE_VERSION}")

set(APACHE_APR_DOWNLOAD_URL "https://apr.apache.org/download.cgi")
set(APACHE_APR_SOURCE_PACKAGE_URL "https://archive.apache.org/dist/apr")
set(APR_RELEASE_VERSION "1.7.6")
set(APR_SOURCE_PACKAGE_FILE_NAME "apr-${APR_RELEASE_VERSION}")
set(APR_SOURCE_PACKAGE_FILE_URL "${APACHE_APR_SOURCE_PACKAGE_URL}/${APR_SOURCE_PACKAGE_FILE_NAME}")
set(APR_UTIL_RELEASE_VERSION "1.6.3")
set(APR_UTIL_SOURCE_PACKAGE_FILE_NAME "apr-util-${APR_UTIL_RELEASE_VERSION}")
set(APR_UTIL_SOURCE_PACKAGE_FILE_URL "${APACHE_APR_SOURCE_PACKAGE_URL}/${APR_UTIL_SOURCE_PACKAGE_FILE_NAME}")

string(TIMESTAMP SITE_PUBLISHED_DATE "%a %b %d %Y" UTC)
configure_file( "${CMAKE_CURRENT_SOURCE_DIR}/doxy/set-site-published-date.js.in"
    "${CMAKE_CURRENT_BINARY_DIR}/set-site-published-date.js" )

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doxy/Doxyfile.in
    ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile )

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/markdown/download.md.in
    ${CMAKE_CURRENT_BINARY_DIR}/markdown/download.md )

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/markdown/development/build-cmake.md.in
    ${CMAKE_CURRENT_BINARY_DIR}/markdown/development/build-cmake.md )

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/resources/performance-data.json
    ${CMAKE_CURRENT_BINARY_DIR}/resources/performance-data.json
    COPYONLY
)
configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/echarts.js
    ${CMAKE_CURRENT_BINARY_DIR}/html/echarts.js
    COPYONLY
)
configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/graph.js
    ${CMAKE_CURRENT_BINARY_DIR}/html/graph.js
    COPYONLY
)

add_custom_target( doc_doxygen ALL
    COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${LOG4CXX_SOURCE_DIR}
    COMMENT "Generate site with Doxygen"
    VERBATIM )
