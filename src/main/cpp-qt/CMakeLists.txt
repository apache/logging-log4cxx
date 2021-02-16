option(LOG4CXX_QT_SUPPORT "Qt support/integration" OFF)

# Log4cxx Qt support, if enabled
if(LOG4CXX_QT_SUPPORT)
    find_package(Qt5 COMPONENTS Core REQUIRED)

    add_library(log4cxx-qt)
    if(BUILD_SHARED_LIBS)
	target_compile_definitions(log4cxx-qt PRIVATE LOG4CXX)
    else()
	target_compile_definitions(log4cxx-qt PUBLIC LOG4CXX_STATIC)
    endif()
    add_dependencies(log4cxx-qt configure_log4cxx)
    target_compile_definitions(log4cxx-qt PRIVATE "QT_NO_KEYWORDS")
    target_link_libraries(log4cxx-qt Qt5::Core)
    target_sources(log4cxx-qt
      PRIVATE
      messagehandler.cpp
    )
    set_target_properties(log4cxx-qt PROPERTIES
      VERSION ${LIBLOG4CXX_LIB_VERSION}
      SOVERSION ${LIBLOG4CXX_LIB_SOVERSION}
    )
endif( LOG4CXX_QT_SUPPORT)
