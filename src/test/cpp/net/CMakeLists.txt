
# Tests defined in this directory
set(NET_TESTS
    socketappendertestcase
    sockethubappendertestcase
    syslogappendertestcase
    telnetappendertestcase
    xmlsocketappendertestcase
)
if(HAS_LIBESMPT)
    list(APPEND NET_TESTS smtpappendertestcase)
endif(HAS_LIBESMPT)
foreach(fileName IN LISTS NET_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
endforeach()
if(Java_Development_FOUND)
    add_executable(socketservertestcase socketserverstarter.cpp socketservertestcase.cpp)
    add_dependencies(socketservertestcase test-classes)
    list(APPEND NET_TESTS socketservertestcase)
endif()
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} ${NET_TESTS} PARENT_SCOPE)
