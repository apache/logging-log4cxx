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
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} ${ROLLING_TESTS} PARENT_SCOPE)
