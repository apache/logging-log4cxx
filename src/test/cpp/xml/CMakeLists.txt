add_executable(xmltests
    domtestcase.cpp
    xmllayouttest.cpp
    xmllayouttestcase.cpp
)

target_link_libraries(xmltests PRIVATE ${APR_UTIL_LIBRARIES} EXPAT::EXPAT)
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} xmltests PARENT_SCOPE)
