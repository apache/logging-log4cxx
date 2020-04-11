add_executable(xmltests
    domtestcase
    xmllayouttest
    xmllayouttestcase
)

target_link_libraries(xmltests PRIVATE ${APR_UTIL_LIBRARIES} ${XMLLIB_LIBRARIES})
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} xmltests PARENT_SCOPE)
