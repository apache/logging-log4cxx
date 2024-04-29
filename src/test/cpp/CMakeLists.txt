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

option(ENABLE_MULTITHREAD_TEST "Enable multithread test.  Note that this test is very unstable,
    it is mostly designed to ensure that we don't crash immediately if exit is called in a thread"  OFF)

# Components required by all tests
add_library(testingFramework STATIC abts.cpp appenderskeletontestcase.cpp logunit.cpp vectorappender.cpp writerappendertestcase.cpp )
target_compile_definitions(testingFramework PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
target_include_directories(testingFramework PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
add_subdirectory(util)
target_sources(testingUtilities PRIVATE xml/xlevel.cpp)

set( LOG4CXX_TEST_PROGRAM_PATH "" CACHE PATH "Extra path for test programs" )
set( CMAKE_PROGRAM_PATH "${LOG4CXX_TEST_PROGRAM_PATH};${CMAKE_PROGRAM_PATH}" )

# sed, zip, and gzip are needed for the tests to work properly
# Note: option 'required' not available until cmake 3.18, however adding
# it does not cause an issue
find_program(SED_APP sed REQUIRED)
find_program(ZIP_APP zip REQUIRED)
find_program(GZIP_APP gzip REQUIRED)

# Tests defined in this directory
set(ALL_LOG4CXX_TESTS
    autoconfiguretestcase
    asyncappendertestcase
    consoleappendertestcase
    decodingtest
    encodingtest
    fileappendertest
    filetestcase
    hexdumptestcase
    hierarchytest
    hierarchythresholdtestcase
    jsonlayouttest
    l7dtestcase
    leveltestcase
    levelchangetestcase
    loggertestcase
    mdctestcase
    minimumtestcase
    ndctestcase
    patternlayouttest
    propertyconfiguratortest
    rollingfileappendertestcase
    streamtestcase
    locationtest
    locationdisabledtest
    terminationtestcase
)
if(${ENABLE_FMT_LAYOUT})
    set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} fmttest)
endif()
if(${ENABLE_MULTITHREAD_TEST})
    set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} multithreadtest)
endif()
if(${LOG4CXX_EVENTS_AT_EXIT})
    set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} eventsatexittest)
endif()
foreach(fileName IN LISTS ALL_LOG4CXX_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
endforeach()
target_sources(rollingfileappendertestcase PRIVATE fileappendertestcase.cpp)

# Tests defined in subdirectories
add_subdirectory(helpers)
if(LOG4CXX_DOMCONFIGURATOR_SUPPORT)
    add_subdirectory(customlogger)
    add_subdirectory(xml)
endif()
if(HAS_ODBC)
    add_subdirectory(db)
endif()
add_subdirectory(defaultinit)
add_subdirectory(filter)
add_subdirectory(net)
if(WIN32)
    add_subdirectory(nt)
endif()
add_subdirectory(pattern)
add_subdirectory(rolling)
add_subdirectory(varia)
add_subdirectory(throughput)
add_subdirectory(benchmark)

if( WIN32 )
  include(win32_target_environment_path)
  get_target_environment_path(ESCAPED_PATH)
elseif(CMAKE_BUILD_TYPE)
  string(TOUPPER ${CMAKE_BUILD_TYPE} UPPER_BUILD_TYPE)
  if (UPPER_BUILD_TYPE STREQUAL "DEBUG")
    set(TEST_COMPILE_DEFINITIONS _DEBUG)
  endif()
else()
  set(TEST_COMPILE_DEFINITIONS _DEBUG)
endif()

get_filename_component(UNIT_TEST_WORKING_DIR ../resources ABSOLUTE)
if(LOG4CXX_CFSTRING)
  set(CFSTR_TESTS filetestcase messagebuffertest leveltestcase streamtestcase transcodertestcase)
endif()
foreach(testName IN LISTS ALL_LOG4CXX_TESTS)
    if (${testName} IN_LIST CFSTR_TESTS)
      if(APPLE)
        target_compile_options(${testName} PRIVATE "-fconstant-cfstrings")
        target_link_libraries(${testName} PRIVATE "-framework CoreFoundation")
      else()
        target_link_libraries(${testName} PRIVATE MockCoreFoundation)
      endif()
    endif()
    target_compile_definitions(${testName} PRIVATE ${TEST_COMPILE_DEFINITIONS} ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(${testName} PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(${testName} PRIVATE testingFramework testingUtilities log4cxx ${APR_LIBRARIES} ${APR_SYSTEM_LIBS} Threads::Threads ${ODBC_LIBRARIES} )
    if(HAS_LIBESMTP)
      target_link_libraries(${testName} PRIVATE ${ESMTP_LIBRARIES})
    endif()
    add_test(NAME ${testName}
        COMMAND ${testName} -v
        WORKING_DIRECTORY ${UNIT_TEST_WORKING_DIR}
    )
    set_tests_properties( ${testName} PROPERTIES TIMEOUT 120 )
    if(WIN32)
        set_target_properties(${testName} PROPERTIES
          VS_DEBUGGER_WORKING_DIRECTORY ${UNIT_TEST_WORKING_DIR}
          FOLDER UnitTests
        )
        set_target_properties(${testName} PROPERTIES
          VS_DEBUGGER_COMMAND_ARGUMENTS "-v"
        )
        if(${testName} STREQUAL socketservertestcase)
            set_target_properties(${testName} PROPERTIES
              VS_DEBUGGER_ENVIRONMENT "SOCKET_SERVER_PARAMETER_FILE=${START_SOCKET_SERVER_PARAMETER_FILE}\nPATH=${ESCAPED_PATH}"
            )
            set_tests_properties(socketservertestcase PROPERTIES
                ENVIRONMENT "SOCKET_SERVER_PARAMETER_FILE=${START_SOCKET_SERVER_PARAMETER_FILE};PATH=${ESCAPED_PATH}"
            )
        elseif(${testName} STREQUAL optionconvertertestcase)
            set_target_properties(${testName} PROPERTIES
              VS_DEBUGGER_ENVIRONMENT "TOTO=wonderful\nkey1=value1\nkey2=value2\nPATH=${ESCAPED_PATH}"
            )
           set_tests_properties(${testName} PROPERTIES
                ENVIRONMENT "TOTO=wonderful;key1=value1;key2=value2;PATH=${ESCAPED_PATH}"
           )
        else()
            set_target_properties(${testName} PROPERTIES
              VS_DEBUGGER_ENVIRONMENT "key1=value1\nkey2=value2\nPATH=${ESCAPED_PATH}"
            )
           set_tests_properties(${testName} PROPERTIES
                ENVIRONMENT "key1=value1;key2=value2;PATH=${ESCAPED_PATH}"
           )
        endif()
        if(NOT BUILD_SHARED_LIBS)
            # cmake selects a multi-threaded dynamically-linked runtime library by default
            # (i.e. MSVC_RUNTIME_LIBRARY target property default value is "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
            # APR static libraries specify the MSVC statically-linked runtime as the default library
            # Use the MSVC statically-linked runtime to prevent the warning message 'LNK4098: defaultlib 'LIBCMT' conflicts with use of other libs'
            set_target_properties(${testName} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        endif()
    else()
        if(${testName} STREQUAL socketservertestcase)
            set_tests_properties(socketservertestcase PROPERTIES
                ENVIRONMENT "SOCKET_SERVER_PARAMETER_FILE=${START_SOCKET_SERVER_PARAMETER_FILE}"
            )
        elseif(${testName} STREQUAL optionconvertertestcase)
            set_tests_properties(optionconvertertestcase PROPERTIES
                ENVIRONMENT "TOTO=wonderful;key1=value1;key2=value2"
            )
        else()
           set_tests_properties(${testName} PROPERTIES
                ENVIRONMENT "key1=value1;key2=value2"
           )
        endif()
    endif()
endforeach()

target_compile_definitions(locationdisabledtest PRIVATE LOG4CXX_DISABLE_LOCATION_INFO)
