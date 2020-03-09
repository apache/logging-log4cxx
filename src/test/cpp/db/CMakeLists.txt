add_executable(odbcappendertestcase odbcappendertestcase.cpp)
target_compile_definitions(odbcappendertestcase PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
target_include_directories(odbcappendertestcase PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES>)
target_link_libraries(odbcappendertestcase log4cxx testingFramework testingUtilities ${APR_LIBRARIES} ${APR_SYSTEM_LIBS})
