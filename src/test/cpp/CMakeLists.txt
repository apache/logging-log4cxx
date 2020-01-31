# Components required by all tests
add_library(testingFramework STATIC abts.cpp appenderskeletontestcase.cpp logunit.cpp vectorappender.cpp writerappendertestcase.cpp )
target_include_directories(testingFramework PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
add_subdirectory(util)
target_sources(testingUtilities PRIVATE xml/xlevel.cpp)

# Tests defined in this directory
set(ALL_LOG4CXX_TESTS 
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

foreach(testName IN LISTS ALL_LOG4CXX_TESTS)
    target_include_directories(${testName} PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(${testName} PRIVATE testingFramework testingUtilities log4cxx ${APR_LIBRARIES})
    add_test(NAME ${testName}
        COMMAND ${testName} -v
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../resources
    )
    if(WIN32)
      set_tests_properties(${testName} PROPERTIES ENVIRONMENT
        "PATH=$<SHELL_PATH:$<TARGET_FILE_DIR:log4cxx>>$<SEMICOLON>$ENV{PATH}"
    )
    endif()
endforeach()
