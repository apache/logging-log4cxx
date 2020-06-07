add_executable(filtertests
    andfiltertest.cpp
    denyallfiltertest.cpp
    levelmatchfiltertest.cpp
    levelrangefiltertest.cpp
    loggermatchfiltertest.cpp
    mapfiltertest.cpp
    stringmatchfiltertest.cpp
)
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} filtertests PARENT_SCOPE)
