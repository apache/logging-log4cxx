option(BUILD_SITE "Build log4cxx website" OFF)
if(BUILD_SITE)
    find_package( Doxygen REQUIRED dot )
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doxy/Doxyfile.in
	            ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile )

    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/markdown/download.md.in
	            ${CMAKE_CURRENT_BINARY_DIR}/markdown/download.md )

    add_custom_target( doc_doxygen ALL
	COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	COMMENT "Generate site with Doxygen"
	VERBATIM )
endif()
