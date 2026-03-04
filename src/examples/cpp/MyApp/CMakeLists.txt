#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#       http:/www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
cmake_minimum_required(VERSION 3.13)
project(MyApp LANGUAGES CXX)

# Find the required library
find_package(log4cxx REQUIRED)
# Optionally locate fmt::fmt
find_package(fmt QUIET)

# Build an executable that uses Log4cxx
get_filename_component(SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}" DIRECTORY)
add_executable(MyApp ${SOURCE_DIR}/MyApp2.cpp)
target_include_directories(MyApp PRIVATE ${SOURCE_DIR})
target_sources(MyApp PRIVATE ${SOURCE_DIR}/com/foo/config4.cpp ${SOURCE_DIR}/com/foo/bar.cpp)
target_link_libraries(MyApp PRIVATE log4cxx)
