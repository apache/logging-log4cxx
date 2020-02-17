# Determine which programs used by tests are available
find_program(sedProgram sed)
find_program(gzipProgram gzip)
find_program(zipProgram zip)

# Some timebasedrollingtest may fail when the output directory is already populated
file(REMOVE_RECURSE ${CMAKE_CURRENT_LIST_DIR}/../resources/output)

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
    ndctestcase
   
    propertyconfiguratortest
    rollingfileappendertestcase
    streamtestcase
)
if(sedProgram)
    list(APPEND ALL_LOG4CXX_TESTS minimumtestcase patternlayouttest)
endif()
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
        get_filename_component(APR_DLL_DIR "${APR_DLL}" DIRECTORY)
        get_filename_component(APR_UTIL_DLL_DIR "${APR_UTIL_DLL}" DIRECTORY)
        get_filename_component(SED_DIR "${sedProgram}" DIRECTORY)
        get_filename_component(GZIP_DIR "${gzipProgram}" DIRECTORY)
        get_filename_component(ZIP_DIR "${zipProgram}" DIRECTORY)
        set(PATH_FOR_TESTS $<SHELL_PATH:$<TARGET_FILE_DIR:log4cxx>> ${APR_DLL_DIR} ${APR_UTIL_DLL_DIR} ${SED_DIR} ${GZIP_DIR} ${ZIP_DIR})
        list(REMOVE_DUPLICATES PATH_FOR_TESTS)
        if(${testName} STREQUAL socketservertestcase)
            set_tests_properties(socketservertestcase PROPERTIES
                ENVIRONMENT "SOCKET_SERVER_PARAMETER_FILE=${START_SOCKET_SERVER_PARAMETER_FILE};PATH=$<JOIN:${PATH_FOR_TESTS},\;>"
            )
        else()
           set_tests_properties(${testName} PROPERTIES
                ENVIRONMENT "TOTO=wonderful;key1=value1;key2=value2;PATH=$<JOIN:${PATH_FOR_TESTS},\;>"
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
