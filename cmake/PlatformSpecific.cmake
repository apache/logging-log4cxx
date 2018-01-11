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

# Uncomment this to show some basic cmake variables about platforms
# include (NewPlatformDebug)

if(MSVC)
     add_definitions("/MP") # parallel build
#    add_definitions("/W3") # warning level 3

# These are set in log4cxx/private/log4cxx.h(w), so not set here (for now)
#    add_definitions("/DLOG4CXX_HAVE_LIBESMTP=0")
#    add_definitions("/DLOG4CXX_HAVE_ODBC=1")      # technically it is better to add FindODBC.cmake but
#    add_definitions("/DLOG4CXX_HAVE_SYSLOG=0")    #   we can do that when the cmake builds support unix too

    if(BUILD_SHARED_LIBS)
        add_definitions("/DLOG4CXX")
    else()
        add_definitions("/DAPR_DECLARE_STATIC")
        add_definitions("/DLOG4CXX_STATIC")
		add_definitions("/Z7")
    endif()

    # For Debug build types, append a "d" to the library names.
    set(CMAKE_DEBUG_POSTFIX "d" CACHE STRING "Set debug library postfix" FORCE)
    set(CMAKE_RELEASE_POSTFIX "" CACHE STRING "Set release library postfix" FORCE)
    set(CMAKE_RELWITHDEBINFO_POSTFIX "" CACHE STRING "Set release library postfix" FORCE)

    # For visual studio the library naming is as following:
    # Dynamic libraries:
    #  - log4cxx.dll  for release library
    #  - log4cxxd.dll for debug library
    #
    # Static libraries:
    #  - log4cxxmd.lib for /MD build (release shared runtime)
    #  - log4cxxmt.lib for /MT build (release static runtime)
    #  - log4cxxmdd.lib for /MDd build (debug shared runtime)
    #  - log4cxxmtd.lib for /MTd build (debug static runtime)
    #

    if(NOT MSVC_SHARED_RUNTIME)
        set(CompilerFlags
                CMAKE_CXX_FLAGS
                CMAKE_CXX_FLAGS_DEBUG
                CMAKE_CXX_FLAGS_RELEASE
                CMAKE_CXX_FLAGS_RELWITHDEBINFO
                CMAKE_C_FLAGS
                CMAKE_C_FLAGS_DEBUG
                CMAKE_C_FLAGS_RELEASE
                CMAKE_C_FLAGS_RELWITHDEBINFO
                )
        foreach(CompilerFlag ${CompilerFlags})
          string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        endforeach()
        set(STATIC_POSTFIX "mt" CACHE STRING "Set static library postfix" FORCE)
    else()
        set(STATIC_POSTFIX "md" CACHE STRING "Set static library postfix" FORCE)
    endif()

elseif(UNIX)

    message(WARNING "The log4cxx CMake build environment is currently designed for windows builds...")
    message(WARNING "Use at your own risk!")

    ##find_program( MEMORYCHECK_COMMAND valgrind )
    ##set( MEMORYCHECK_COMMAND_OPTIONS "--gen-suppressions=all --leak-check=full" )
    ##set( MEMORYCHECK_SUPPRESSIONS_FILE "${PROJECT_SOURCE_DIR}/test/valgrind.suppress" )

endif()
