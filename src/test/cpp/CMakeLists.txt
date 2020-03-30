# Components required by all tests
add_library(testingFramework STATIC abts.cpp appenderskeletontestcase.cpp logunit.cpp vectorappender.cpp writerappendertestcase.cpp )
target_compile_definitions(testingFramework PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
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
    target_compile_definitions(${testName} PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(${testName} PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(${testName} PRIVATE testingFramework testingUtilities log4cxx ${APR_LIBRARIES} ${APR_SYSTEM_LIBS})
    add_test(NAME ${testName}
        COMMAND ${testName} -v
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../resources
    )

    if(WIN32)
        get_filename_component(APR_DLL_DIR "${APR_DLL}" DIRECTORY)
        get_filename_component(APR_UTIL_DLL_DIR "${APR_UTIL_DLL}" DIRECTORY)
        get_filename_component(XMLLIB_DLL_DIR "${XMLLIB_DLL}" DIRECTORY)
        set(PATH_FOR_TESTS $<SHELL_PATH:$<TARGET_FILE_DIR:log4cxx>> ${APR_DLL_DIR} ${APR_UTIL_DLL_DIR} ${XMLLIB_DLL_DIR})
        list(REMOVE_DUPLICATES PATH_FOR_TESTS)
        if(${testName} STREQUAL socketservertestcase)
            set_tests_properties(socketservertestcase PROPERTIES
                ENVIRONMENT "SOCKET_SERVER_PARAMETER_FILE=${START_SOCKET_SERVER_PARAMETER_FILE};PATH=${LOG4CXX_DLL_DIR}\;${APR_DLL_DIR}\;${APR_UTIL_DLL_DIR}"
            )
        else()
           set_tests_properties(${testName} PROPERTIES
                ENVIRONMENT "TOTO=wonderful;key1=value1;key2=value2;PATH==${LOG4CXX_DLL_DIR}\;${APR_DLL_DIR}\;${APR_UTIL_DLL_DIR}"
           )
        endif()
    else()
        if(${testName} STREQUAL socketservertestcase)
            set_tests_properties(socketservertestcase PROPERTIES
                ENVIRONMENT "SOCKET_SERVER_PARAMETER_FILE=${START_SOCKET_SERVER_PARAMETER_FILE}"
            )
        else()
           set_tests_properties(${testName} PROPERTIES
                ENVIRONMENT "TOTO=wonderful;key1=value1;key2=value2"
           )
        endif()
    endif()
endforeach()
