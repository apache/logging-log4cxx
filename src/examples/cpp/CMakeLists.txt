set(ALL_LOG4CXX_EXAMPLES console delayedloop stream trivial custom-appender)

foreach(exampleName IN LISTS ALL_LOG4CXX_EXAMPLES)
    add_executable(${exampleName} ${exampleName}.cpp)
    target_compile_definitions(${exampleName} PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(${exampleName} PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(${exampleName} PRIVATE log4cxx ${APR_UTIL_LIBRARIES} ${XMLLIB_LIBRARIES} ${APR_LIBRARIES} ${APR_SYSTEM_LIBS})
endforeach()

configure_file( custom-appender.xml
    ${CMAKE_CURRENT_BINARY_DIR}/custom-appender.xml
    COPYONLY )

# Custom handling for format string example, since it utilizes libfmt
find_package(fmt QUIET)
if(${fmt_FOUND})
    add_executable( format-string format-string.cpp )
    target_compile_definitions(format-string PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(format-string PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(format-string PRIVATE log4cxx ${APR_UTIL_LIBRARIES} ${XMLLIB_LIBRARIES} ${APR_LIBRARIES} ${APR_SYSTEM_LIBS} fmt::fmt)
endif(${fmt_FOUND})
