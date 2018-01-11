#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#

#
# summary()
#
# Emit a summary of the build options, etc.
#

function(summary)
    if (BUILD_SHARED_LIBS)
        set(LINK_STRATEGY "Shared")
    else()
        set(LINK_STRATEGY "Static")
    endif()

    if (MSVC)
        if (MSVC_SHARED_RUNTIME)
            set(MSVCRT_STRATEGY " with shared runtime")
        else()
            set(MSVCRT_STRATEGY " with static runtime")
        endif()
    endif()

    message(STATUS "")
    message(STATUS "Configuration Summary for ${PROJECT_NAME}:")
    message(STATUS "")
    message(STATUS "  APR2_FOUND           ${APR2_FOUND}")
    message(STATUS "  APR2_INCLUDE_DIRS    ${APR2_INCLUDE_DIRS}")
    message(STATUS "  APR2_LIBRARIES       ${APR2_LIBRARIES}")
    message(STATUS "")
    message(STATUS "  PROJECT_DESCRIPTION  ${PROJECT_DESCRIPTION}")
    message(STATUS "  PROJECT_NAME         ${PROJECT_NAME}")
    message(STATUS "  PROJECT_LICENSE      ${PROJECT_LICENSE}")
    message(STATUS "  PROJECT_LICURL       ${PROJECT_LICURL}")
    message(STATUS "  PROJECT_URL          ${PROJECT_URL}")
    message(STATUS "  PROJECT_VERSION      ${PROJECT_VERSION}")
    message(STATUS "")
  if (NOT MSVC)
    message(STATUS "  Build Type           ${CMAKE_BUILD_TYPE}")
  endif()
    message(STATUS "  Install Prefix       ${CMAKE_INSTALL_PREFIX}")
    message(STATUS "  Language Level       ${CXX_LANGUAGE_LEVEL}")
    message(STATUS "  Link Strategy        ${LINK_STRATEGY}${MSVCRT_STRATEGY}")
    message(STATUS "")

# Uncomment to dump all variables out to console    
# include (NewPlatformDebug)

endfunction()
