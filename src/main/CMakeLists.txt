add_subdirectory(include)
add_subdirectory(cpp)
add_subdirectory(cpp-qt)
add_subdirectory(resources)

# setup include directories 
include(GNUInstallDirs)
target_include_directories(log4cxx PUBLIC 
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(LOG4CXX_QT_SUPPORT)
    target_include_directories(log4cxx-qt PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
endif(LOG4CXX_QT_SUPPORT)
