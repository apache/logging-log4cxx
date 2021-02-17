To use:

1. Include boost-fallback.cmake in your project
2. If desired, use the provided header file to switch between the various
 implementations:

```
include(boost-fallback/boost-fallback.cmake)

set(NAMESPACE_ALIAS some_namespace)
configure_file(boost-fallback/boost-std-configuration.h.cmake
    boost-fallback/boost-std-configuration.h)
target_include_directories( executable-name PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/boost-fallback )
```

Fallback looks for the following C++11 features:
* std::thread / boost::thread
* std::mutex / boost::mutex (and the locks for these structures) 
* std::shared\_ptr / boost::shared\_ptr
* std::atomic / boost::atomic

The following C++17 features are looked for:
* std::shared\_mutex / boost::shared\_mutex
