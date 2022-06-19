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

option(LOG4CXX_QT_SUPPORT "Qt support/integration" OFF)

# Log4cxx Qt support, if enabled
if(LOG4CXX_QT_SUPPORT)
    find_package(Qt5 COMPONENTS Core REQUIRED)

    add_library(log4cxx-qt)
    if(BUILD_SHARED_LIBS)
	target_compile_definitions(log4cxx-qt PRIVATE LOG4CXX)
    else()
	target_compile_definitions(log4cxx-qt PUBLIC LOG4CXX_STATIC)
    endif()
    add_dependencies(log4cxx-qt configure_log4cxx)
    target_compile_definitions(log4cxx-qt PRIVATE "QT_NO_KEYWORDS")
    target_link_libraries(log4cxx-qt Qt5::Core)
    target_sources(log4cxx-qt
      PRIVATE
      messagehandler.cpp
    )
    set_target_properties(log4cxx-qt PROPERTIES
      VERSION ${LIBLOG4CXX_LIB_VERSION}
      SOVERSION ${LIBLOG4CXX_LIB_SOVERSION}
    )
endif( LOG4CXX_QT_SUPPORT)
