# This module checks compiler and standard library support
#

# Does the compiler support thread_local?
if(MINGW)
  # As at 2024-7-19 the msys2 ucrt-x86_64 runtime terminates with error c0000374 during thread local data cleanup
  set(HAS_THREAD_LOCAL FALSE)
else()
  try_compile(HAS_THREAD_LOCAL "${CMAKE_BINARY_DIR}/Testing/thread-local-test"
    "${CMAKE_CURRENT_LIST_DIR}/test-thread-local.cpp"
    CXX_STANDARD 11
    )
endif()

# Does the standard library support std::make_unique<T>>?
try_compile(STD_MAKE_UNIQUE_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-make-unique.cpp")
if( ${STD_MAKE_UNIQUE_FOUND} )
    set(STD_MAKE_UNIQUE_IMPL "std::make_unique")
    set(STD_MAKE_UNIQUE_FOUND 1)
else()
    set(STD_MAKE_UNIQUE_IMPL "log4cxx std::make_unique")
    set(STD_MAKE_UNIQUE_FOUND 0)
endif()


# Does the standard library support std::basic_string<UniChar> and std::basic_ostream<UniChar>?
try_compile(STD_LIB_HAS_UNICODE_STRING "${CMAKE_BINARY_DIR}/Testing/unicode-test"
    "${CMAKE_CURRENT_LIST_DIR}/test-unicode.cpp"
    )

