include(FindThreads)
include(CheckSymbolExists)

set(CMAKE_REQUIRED_LIBRARIES "pthread")
check_symbol_exists(pthread_sigmask "signal.h" HAS_PTHREAD_SIGMASK)

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

try_run(PTHREAD_RUN_RESULT HAS_PTHREAD_SETPROTOCOL "${CMAKE_BINARY_DIR}/pthread-compile-tests"
    SOURCES "${CMAKE_CURRENT_LIST_DIR}/test-pthread-setprotocol.cpp"
    LINK_LIBRARIES Threads::Threads )
if(${PTHREAD_RUN_RESULT} EQUAL 0)
  set(MUTEX_SUPPORTS_PRIORITY_INHERITANCE TRUE)
else()
  set(MUTEX_SUPPORTS_PRIORITY_INHERITANCE FALSE)
endif()
