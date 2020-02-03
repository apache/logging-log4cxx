add_executable(defaultinittestcase testcase1.cpp testcase2.cpp testcase3.cpp testcase4.cpp)
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} defaultinittestcase PARENT_SCOPE)
