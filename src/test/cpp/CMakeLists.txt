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
    hierarchytest
    hierarchythresholdtestcase
    jsonlayouttest
    l7dtestcase
    leveltestcase
    loggertestcase
    mdctestcase
    minimumtestcase
    ndctestcase
    patternlayouttest
    propertyconfiguratortest
    rollingfileappendertestcase
    streamtestcase
    multithreadtest
    locationtest
    locationdisabledtest
)
foreach(fileName IN LISTS ALL_LOG4CXX_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
endforeach()
target_sources(rollingfileappendertestcase PRIVATE fileappendertestcase.cpp)

# Tests defined in subdirectories
add_subdirectory(helpers)
add_subdirectory(customlogger)
if(LOG4CXX_HAS_ODBC OR WIN32)
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
add_subdirectory(spi)
add_subdirectory(varia)
add_subdirectory(xml)
add_subdirectory(throughput)

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

get_filename_component(UNIT_TEST_WORKING_DIR ../resources ABSOLUTE)
foreach(testName IN LISTS ALL_LOG4CXX_TESTS)
    target_compile_definitions(${testName} PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(${testName} PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(${testName} PRIVATE testingFramework testingUtilities log4cxx ${APR_LIBRARIES} ${APR_SYSTEM_LIBS} Threads::Threads)
    add_test(NAME ${testName}
        COMMAND ${testName} -v
        WORKING_DIRECTORY ${UNIT_TEST_WORKING_DIR}
    )
    set_tests_properties( ${testName} PROPERTIES TIMEOUT 120 )

    if(WIN32)
        if(${testName} STREQUAL socketservertestcase)
            set_tests_properties(socketservertestcase PROPERTIES
                ENVIRONMENT "SOCKET_SERVER_PARAMETER_FILE=${START_SOCKET_SERVER_PARAMETER_FILE};PATH=${ESCAPED_PATH}"
            )
        elseif(${testName} STREQUAL autoconfiguretestcase)
            set_tests_properties(autoconfiguretestcase PROPERTIES
                ENVIRONMENT "LOG4CXX_CONFIGURATION=${UNIT_TEST_WORKING_DIR}/input/autoConfigureTest.properties;PATH=${ESCAPED_PATH}"
            )
        else()
           set_tests_properties(${testName} PROPERTIES
                ENVIRONMENT "TOTO=wonderful;key1=value1;key2=value2;PATH=${ESCAPED_PATH}"
           )
        endif()
    else()
        if(${testName} STREQUAL socketservertestcase)
            set_tests_properties(socketservertestcase PROPERTIES
                ENVIRONMENT "SOCKET_SERVER_PARAMETER_FILE=${START_SOCKET_SERVER_PARAMETER_FILE}"
            )
        elseif(${testName} STREQUAL autoconfiguretestcase)
            set_tests_properties(autoconfiguretestcase PROPERTIES
                ENVIRONMENT "LOG4CXX_CONFIGURATION=${UNIT_TEST_WORKING_DIR}/input/autoConfigureTest.properties"
            )
        else()
           set_tests_properties(${testName} PROPERTIES
                ENVIRONMENT "TOTO=wonderful;key1=value1;key2=value2"
           )
        endif()
    endif()
endforeach()

target_compile_definitions(locationdisabledtest PRIVATE LOG4CXX_DISABLE_LOCATION_INFO)
