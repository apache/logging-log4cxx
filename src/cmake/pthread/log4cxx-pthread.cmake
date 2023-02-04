include(FindThreads)

set(CMAKE_REQUIRED_LIBRARIES "pthread")
CHECK_SYMBOL_EXISTS(pthread_sigmask "signal.h" HAS_PTHREAD_SIGMASK)

# Check for the (linux) pthread_setname_np.
# OSX and BSD are special apparently.  OSX only lets you name
# the current thread, while BSD calls it pthread_set_name_np.
# Since this is really not a core feature and the end-user can configure
# it anyway, we're only going to worry about linux.
try_compile(HAS_PTHREAD_SETNAME "${CMAKE_BINARY_DIR}/pthread-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-pthread-setname.cpp"
    LINK_LIBRARIES Threads::Threads )

try_compile(HAS_PTHREAD_GETNAME "${CMAKE_BINARY_DIR}/pthread-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-pthread-getname.cpp"
    LINK_LIBRARIES Threads::Threads )

try_compile(HAS_PTHREAD_SETPROTOCOL "${CMAKE_BINARY_DIR}/pthread-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-pthread-setprotocol.cpp"
    LINK_LIBRARIES Threads::Threads )

