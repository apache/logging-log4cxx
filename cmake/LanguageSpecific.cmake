#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#

#
# C++ Language Defaults:
#
# CMAKE_CXX_STANDARD           98     (c++98)
# CMAKE_CXX_STANDARD_REQUIRED  ON
# CMAKE_CXX_EXTENSIONS         OFF    (i.e. not gnu++98)
#

if (NOT DEFINED CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 98)
endif()

if (NOT DEFINED CMAKE_CXX_STANDARD_REQUIRED)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

if (NOT DEFINED CMAKE_CXX_EXTENSIONS)
  set(CMAKE_CXX_EXTENSIONS OFF)
endif()


set(CXX_LANGUAGE_LEVEL "c++${CMAKE_CXX_STANDARD}")

if (CMAKE_CXX_STANDARD_REQUIRED)
  string(CONCAT CXX_LANGUAGE_LEVEL "${CXX_LANGUAGE_LEVEL} [compiler must support it]")
else()
  string(CONCAT CXX_LANGUAGE_LEVEL "${CXX_LANGUAGE_LEVEL} [fallback to earlier revision allowed]")
endif()
if (CMAKE_CXX_EXTENSIONS)
  string(CONCAT CXX_LANGUAGE_LEVEL "${CXX_LANGUAGE_LEVEL} [with compiler-specific extensions]")
endif()
