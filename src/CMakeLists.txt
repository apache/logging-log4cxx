cmake_policy(SET CMP0079 NEW)

add_subdirectory(main)
target_compile_definitions(log4cxx PRIVATE ${LOG4CXX_COMPILE_DEFINITIONS} ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
target_include_directories(log4cxx INTERFACE $<INSTALL_INTERFACE:include> PRIVATE ${APR_INCLUDE_DIR} ${APR_UTIL_INCLUDE_DIR})
target_link_libraries(log4cxx PRIVATE ${APR_UTIL_LIBRARIES} EXPAT::EXPAT ${APR_LIBRARIES} ${APR_SYSTEM_LIBS})
if(WIN32)
# The ODBC appender is always enabled in the Windows configuration
target_link_libraries(log4cxx PRIVATE odbc32.lib)
option(LOG4CXX_INSTALL_PDB "Install .pdb files (if generated)"  ON)
else()
    if(${odbc_FOUND})
	target_link_libraries( log4cxx PUBLIC ${odbc_LIBRARIES})
    endif(${odbc_FOUND})
endif()

if(BUILD_TESTING)
   add_subdirectory(test)
   add_subdirectory(examples/cpp)
endif()

add_subdirectory(site)
