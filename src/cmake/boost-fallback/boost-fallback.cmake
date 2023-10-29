# This module checks for C++ standard classes and their boost counterparts
# Filesystem variables set:
# STD_FILESYSTEM_FOUND - if std::filesystem is found
# STD_EXPERIMENTAL_FILESYSTEM_FOUND - if std::experimental::filesystem is found
# Boost_FILESYSTEM_FOUND - if boost::filesystem is found

include(FindThreads)

try_compile(STD_FILESYSTEM_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-stdfilesystem.cpp")
try_compile(STD_EXPERIMENTAL_FILESYSTEM_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
    "${CMAKE_CURRENT_LIST_DIR}/test-stdexpfilesystem.cpp")

# Check for standard headers that we need, fall back to boost if they're not found
set(NAMESPACE_ALIAS ${LOG4CXX_NS})
option(PREFER_BOOST "Prefer Boost over std:: equivalents" OFF)

if( ${PREFER_BOOST} OR NOT ( ${STD_FILESYSTEM_FOUND} OR ${STD_EXPERIMENTAL_FILESYSTEM_FOUND} ) )
    find_package(Boost COMPONENTS filesystem)
    if( ${Boost_FOUND} )
        try_compile(Boost_FILESYSTEM_FOUND "${CMAKE_BINARY_DIR}/boost-fallback-compile-tests"
            "${CMAKE_CURRENT_LIST_DIR}/test-boostfilesystem.cpp")
    endif( ${Boost_FOUND} )
endif()

if( ${STD_FILESYSTEM_FOUND} AND NOT ${PREFER_BOOST} )
    set( FILESYSTEM_IMPL "std::filesystem" )
elseif( ${STD_EXPERIMENTAL_FILESYSTEM_FOUND} AND NOT ${PREFER_BOOST} )
    set( FILESYSTEM_IMPL "std::experimental::filesystem" )
elseif( ${Boost_FILESYSTEM_FOUND} )
    set( FILESYSTEM_IMPL "boost::filesystem" )
else()
    set( FILESYSTEM_IMPL "NONE" )
endif()


