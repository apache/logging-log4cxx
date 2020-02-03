add_executable(uninitializedtestcase testcase1.cpp)
add_executable(defaultinittestcase testcase2.cpp testcase3.cpp testcase4.cpp)
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} uninitializedtestcase defaultinittestcase PARENT_SCOPE)
