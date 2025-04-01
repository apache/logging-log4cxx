#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

message("Getting dependencies for ABI compatability check...")
# Get the latest version of abi-dumper and abi-compliance-checker
include(FetchContent)
FetchContent_MakeAvailable(abi-dumper
  GIT_REPOSITORY https://github.com/lvc/abi-dumper.git
  GIT_TAG 1.4
)
FetchContent_GetProperties(abi-dumper)
if(NOT abi-dumper_POPULATED)
  FetchContent_Populate(abi-dumper)
endif()

FetchContent_MakeAvailable(abi-compliance-checker
  GIT_REPOSITORY https://github.com/lvc/abi-compliance-checker.git
  GIT_TAG f60ce442c33f1d5cda1cec7cfddee24af1777572
)
FetchContent_GetProperties(abi-compliance-checker)
if(NOT abi-compliance-checker_POPULATED)
  FetchContent_Populate(abi-compliance-checker)
endif()

set(abi-dumper-script ${CMAKE_CURRENT_SOURCE_DIR}/abi-dumper.pl)
set(abi-compliance-script ${abi-compliance-checker_SOURCE_DIR}/abi-compliance-checker.pl)

add_custom_target(dump-abi ALL
    COMMAND perl ${abi-dumper-script} -public-headers public_header_files.txt -o new-abi.dump -skip-cxx -vnum ${log4cxx_ABI_VER} $<TARGET_FILE:log4cxx>
    DEPENDS log4cxx
    COMMENT "Dumping ABI symbols"
)

add_custom_target(compare-abi ALL
    COMMAND perl ${abi-compliance-script} -skip-internal-symbols "\\d\\(fmt\\)" -skip-internal-types "\\(fmt\\)::" -l log4cxx -old ${CMAKE_CURRENT_SOURCE_DIR}/abi.dump -new new-abi.dump
    DEPENDS dump-abi
    COMMENT "Comparing ABI symbols"
)
