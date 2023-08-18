include(FindThreads)

try_compile(PTHREAD_SETNAME_NP_FOUND
    SOURCES "${CMAKE_CURRENT_LIST_DIR}/test-pthread-setname.cpp"
    LINK_LIBRARIES Threads::Threads
)

try_compile(PTHREAD_GETNAME_NP_FOUND
    SOURCES "${CMAKE_CURRENT_LIST_DIR}/test-pthread-getname.cpp"
    LINK_LIBRARIES Threads::Threads
)

