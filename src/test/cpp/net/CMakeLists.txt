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
if(LOG4CXX_NETWORKING_SUPPORT)
    set(NET_TESTS
	syslogappendertestcase
	telnetappendertestcase
	xmlsocketappendertestcase
    )
else()
    set(NET_TESTS "")
endif()

if(NOT LOG4CXX_DOMCONFIGURATOR_SUPPORT)
    list(REMOVE_ITEM NET_TESTS xmlsocketappendertestcase)
endif()

if(HAS_LIBESMTP)
    list(APPEND NET_TESTS smtpappendertestcase)
endif(HAS_LIBESMTP)
foreach(fileName IN LISTS NET_TESTS)
    add_executable(${fileName} "${fileName}.cpp")
endforeach()

set(ALL_LOG4CXX_TESTS ${ALL_LOG4CXX_TESTS} ${NET_TESTS} PARENT_SCOPE)
