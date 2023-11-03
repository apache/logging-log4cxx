# Put the list of runtime path directories into varName.
function(get_target_environment_path varName)
  get_filename_component(APR_DLL_DIR "${APR_DLL}" DIRECTORY)
  get_filename_component(APR_UTIL_DLL_DIR "${APR_UTIL_DLL}" DIRECTORY)
  get_filename_component(EXPAT_LIB_DIR "${EXPAT_LIBRARY}" DIRECTORY)


  set(EXPAT_DLL_DIR "${EXPAT_LIB_DIR}/../bin")
  set(LOG4CXX_DLL_DIR "$<SHELL_PATH:$<TARGET_FILE_DIR:log4cxx>>;")
  set(PATH_FOR_TESTS ${CMAKE_PROGRAM_PATH};${APR_DLL_DIR};${APR_UTIL_DLL_DIR};${LOG4CXX_DLL_DIR};${EXPAT_DLL_DIR}\;)
  if(LOG4CXX_QT_SUPPORT)
    list(APPEND PATH_FOR_TESTS "$<SHELL_PATH:$<TARGET_FILE_DIR:log4cxx-qt>>\;")
  endif(LOG4CXX_QT_SUPPORT)
  list(REMOVE_DUPLICATES PATH_FOR_TESTS)

  # Note: we need to include the APR DLLs on our path so that the tests will run.
  # The way that CMake sets the environment is that it actually generates a secondary file,
  # CTestTestfile.cmake, which sets the final properties of the test.
  # However, this results in a secondary quirk to the running of the tests: CMake uses
  # a semicolon to deliminate entries in a list!  Since the Windows PATH is semicolon-delimited
  # as well, CMake uses only the first entry in the list when setting the path.
  # So, we need to do a triple escape on the PATH that we want to set in order for CMake to
  # properly interpret the PATH
  set(NORMAL_PATH $ENV{PATH})
  set(ESCAPED_PATH "")
  foreach( ENTRY ${PATH_FOR_TESTS}${NORMAL_PATH} )
    set(ESCAPED_PATH "${ESCAPED_PATH}${ENTRY}\\\;")
  endforeach()
  set(${varName} ${ESCAPED_PATH} PARENT_SCOPE)
endfunction()
