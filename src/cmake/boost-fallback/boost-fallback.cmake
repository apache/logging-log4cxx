#include(${CMAKE_MODULE_PATH}/FindPackageHandleStandardArgs.cmake)

# Checks for classes in std::, falling back to boost if the requested
# classes are not available
#
# Available classes to check for:
# thread
# mutex
# shared_mutex
#
# Variables set:
# ${prefix}_

#function(_boost_fallback_thread)
#    try_compile(HAS_STD_THREAD "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
#	"${CMAKE_CURRENT_LIST_DIR}/test-stdthread.cpp")


#    find_package(boost_thread COMPONENTS thread)
#endfunction()

## check for boost fallback instead of std:: classes
## arg1: prefix for variables to set
## arg2: list of classes to check for
#function(boost_fallback prefix classes)
#endfunction()

#
# This module checks for C++ standard classes and their boost counterparts
#
# Thread variables set:
# STD_THREAD_FOUND - if std::thread is found
# Boost_THREAD_FOUND - if boost::thread is found
#
# Mutex variables set:
# STD_MUTEX_FOUND - if std::mutex is found
# STD_SHARED_MUTEX_FOUND - if std::shared_mutex is found
# Boost_MUTEX_FOUND - if boost::mutex is found
# Boost_SHARED_MUTEX_FOUND - if boost::shared_mutex is found
#
# Smart pointer variables set:
# STD_SHARED_PTR_FOUND - if std::shared_ptr is found
# Boost_SHARED_PTR_FOUND - if boost::shared_ptr is found

include(FindThreads)

try_compile(STD_THREAD_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-stdthread.cpp")
try_compile(STD_MUTEX_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-stdmutex.cpp")
try_compile(STD_SHARED_MUTEX_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-stdsharedmutex.cpp")
try_compile(STD_SHARED_PTR_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-stdsharedptr.cpp")
try_compile(STD_ATOMIC_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-stdatomic.cpp")

# We need to have all three boost components in order to run our tests
# Boost thread requires chrono and atomic to work
find_package(Boost COMPONENTS thread chrono atomic)
if( ${Boost_FOUND} )
    try_compile(Boost_SHARED_PTR_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
        "${CMAKE_CURRENT_LIST_DIR}/test-boostsharedptr.cpp")
    try_compile(Boost_MUTEX_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
        "${CMAKE_CURRENT_LIST_DIR}/test-boostmutex.cpp")
    try_compile(Boost_SHARED_MUTEX_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
        "${CMAKE_CURRENT_LIST_DIR}/test-boostsharedmutex.cpp"
        LINK_LIBRARIES Threads::Threads Boost::thread)
    try_compile(Boost_ATOMIC_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
        "${CMAKE_CURRENT_LIST_DIR}/test-boostatomic.cpp")
endif( ${Boost_FOUND} )

# Link the target with the appropriate boost libraries(if required)
function(boostfallback_link target)
    if(NOT ${STD_THREAD_FOUND})
        if(${Boost_THREAD_FOUND})
           find_package(Boost COMPONENTS thread)
           target_link_libraries( ${target} PUBLIC Boost::thread)
        endif()
    endif()
    if(NOT ${STD_SHARED_MUTEX_FOUND})
        if(${Boost_SHARED_MUTEX_FOUND})
           find_package(Boost COMPONENTS thread)
           target_link_libraries( ${target} PUBLIC Boost::thread)
        endif()
    endif()
endfunction()


