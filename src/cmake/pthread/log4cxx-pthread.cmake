include(FindThreads)

try_compile(PTHREAD_SETNAME_NP_FOUND "${CMAKE_BINARY_DIR}/pthread-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-pthread.cpp")

