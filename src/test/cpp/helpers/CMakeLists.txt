set(HELPER_TESTS 
    absolutetimedateformattestcase
    cacheddateformattestcase
    charsetdecodertestcase
    charsetencodertestcase
    cyclicbuffertestcase
    datetimedateformattestcase
    filewatchdogtest
    inetaddresstestcase
    iso8601dateformattestcase
    messagebuffertest
    optionconvertertestcase
    propertiestestcase
    relativetimedateformattestcase
    stringhelpertestcase
    stringtokenizertestcase
    syslogwritertest
    threadtestcase
    timezonetestcase
    transcodertestcase
)
foreach(fileName IN LISTS HELPER_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
    target_compile_definitions(${fileName} PRIVATE ${APR_COMPILE_DEFINITIONS} ${APR_UTIL_COMPILE_DEFINITIONS} )
    target_include_directories(${fileName} PRIVATE ${CMAKE_CURRENT_LIST_DIR} $<TARGET_PROPERTY:log4cxx,INCLUDE_DIRECTORIES> ${APR_INCLUDE_DIR})
endforeach()
target_sources(cacheddateformattestcase PRIVATE localechanger.cpp)
target_sources(datetimedateformattestcase PRIVATE  localechanger.cpp)
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} ${HELPER_TESTS} PARENT_SCOPE)
