# Components required by all tests
add_library(testingUtilities STATIC
    serializationtesthelper.cpp
    absolutedateandtimefilter.cpp
    absolutetimefilter.cpp
    binarycompare.cpp
    compare.cpp
    controlfilter.cpp
    filenamefilter.cpp
    iso8601filter.cpp
    linenumberfilter.cpp
    relativetimefilter.cpp
    threadfilter.cpp
    transformer.cpp
    utilfilter.cpp
    xmlfilenamefilter.cpp
    xmllineattributefilter.cpp
    xmlthreadfilter.cpp
    xmltimestampfilter.cpp
)
target_compile_definitions(testingUtilities PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
target_include_directories(testingUtilities PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
