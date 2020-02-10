# Tests defined in this directory
set(VARIA_TESTS
    levelmatchfiltertestcase
    levelrangefiltertestcase
)
if(sedProgram)
    list(APPEND VARIA_TESTS errorhandlertestcase)
endif()

foreach(fileName  IN LISTS VARIA_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
endforeach()
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} ${VARIA_TESTS} PARENT_SCOPE)
