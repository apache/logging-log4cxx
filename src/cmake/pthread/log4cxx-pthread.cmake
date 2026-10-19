include(FindThreads)

try_compile(HAS_PTHREAD_SETNAME "${CMAKE_BINARY_DIR}/pthread-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-pthread-setname.cpp"
    LINK_LIBRARIES Threads::Threads )

try_compile(HAS_PTHREAD_GETNAME "${CMAKE_BINARY_DIR}/pthread-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-pthread-getname.cpp"
    LINK_LIBRARIES Threads::Threads )

try_compile(HAS_PTHREAD_GETHANDLE "${CMAKE_BINARY_DIR}/pthread-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-pthread-gethandle.cpp"
    LINK_LIBRARIES Threads::Threads )
