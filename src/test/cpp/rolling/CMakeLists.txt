# Tests defined in this directory
set(ROLLING_TESTS
    filenamepatterntestcase
    filterbasedrollingtest
    manualrollingtest
    obsoletedailyrollingfileappendertest
    obsoleterollingfileappendertest
    sizebasedrollingtest
    timebasedrollingtest
)
foreach(fileName  IN LISTS ROLLING_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
endforeach()
if(NOT gzipProgram)
	list(APPEND TEST_DEFINITIONS EXCLUDE_GZIP_TESTS)
endif()
if(NOT zipProgram)
	list(APPEND TEST_DEFINITIONS EXCLUDE_ZIP_TESTS)
endif()
set_target_properties(sizebasedrollingtest PROPERTIES
	COMPILE_DEFINITIONS "${TEST_DEFINITIONS}"
)
set_target_properties(timebasedrollingtest PROPERTIES
	COMPILE_DEFINITIONS "${TEST_DEFINITIONS}"
)
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} ${ROLLING_TESTS} PARENT_SCOPE)
