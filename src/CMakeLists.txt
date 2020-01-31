add_subdirectory(main)
target_include_directories(log4cxx INTERFACE $<INSTALL_INTERFACE:include> PRIVATE ${APR_INCLUDE_DIR} ${APR_UTIL_INCLUDE_DIR})
target_link_libraries(log4cxx PRIVATE ${APR_LIBRARIES} ${APR_UTIL_LIBRARIES})
if(WIN32)
# The ODBC appender is always enabled in the Windows configuration
target_link_libraries(log4cxx PRIVATE odbc32.lib)
option(LOG4CXX_INSTALL_PDB "Install .pdb files (if generated)"  ON)
endif()

if(BUILD_TESTING)
   add_subdirectory(test)
   add_subdirectory(examples/cpp)
endif()
