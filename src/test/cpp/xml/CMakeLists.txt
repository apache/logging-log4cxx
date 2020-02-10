add_executable(xmltests
    xmllayouttest
)
if(sedProgram)
    list(APPEND xmltests domtestcase xmllayouttestcase)
endif()

target_link_libraries(xmltests PRIVATE ${APR_UTIL_LIBRARIES})
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} xmltests PARENT_SCOPE)
