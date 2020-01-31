set(ALL_LOG4CXX_EXAMPLES console delayedloop stream trivial)

foreach(exampleName IN LISTS ALL_LOG4CXX_EXAMPLES)
    add_executable(${exampleName} ${exampleName}.cpp)
    target_include_directories(${exampleName} PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
    target_link_libraries(${exampleName} PRIVATE log4cxx ${APR_LIBRARIES})
endforeach()
