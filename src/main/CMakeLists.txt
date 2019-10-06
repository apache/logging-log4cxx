add_subdirectory(include)
add_subdirectory(cpp)

# setup include directories 
include(GNUInstallDirs)
target_include_directories(log4cxx PUBLIC 
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
