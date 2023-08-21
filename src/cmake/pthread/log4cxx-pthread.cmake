include(FindThreads)

try_compile(PTHREAD_SETNAME_NP_FOUND "${CMAKE_BINARY_DIR}/pthread-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-pthread-setname.cpp"
    LINK_LIBRARIES Threads::Threads )

try_compile(PTHREAD_GETNAME_NP_FOUND "${CMAKE_BINARY_DIR}/pthread-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-pthread-getname.cpp"
    LINK_LIBRARIES Threads::Threads )

