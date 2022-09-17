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

# Tests defined in this directory
set(VARIA_TESTS
    errorhandlertestcase
    levelmatchfiltertestcase
    levelrangefiltertestcase
)

foreach(fileName  IN LISTS VARIA_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
endforeach()
set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} ${VARIA_TESTS} PARENT_SCOPE)
