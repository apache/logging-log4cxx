
# Tests defined in this directory
set(NET_TESTS 
    smtpappendertestcase
    socketappendertestcase
    sockethubappendertestcase
    socketservertestcase
    syslogappendertestcase
    telnetappendertestcase
    xmlsocketappendertestcase
)
foreach(fileName IN LISTS NET_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
endforeach()
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} ${NET_TESTS} PARENT_SCOPE)
