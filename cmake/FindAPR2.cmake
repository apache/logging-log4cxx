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
# Locates APR Version 2
#
# APR Version 2 contains APRUTIL. 
# In previous APR releases they were separate libraries.
#
# Usage of this module as follows:
#
#  find_package(APR2)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  APR2_LIBNAMES           Allows the caller to distinguish static vs. shared
#                          libraries when searching, by specifying the full
#                          filename of the library to look for.
#  APR2_ROOT_DIR           Set this variable to the root installation of Apache 
#                          Portable Runtime/Util Library if the module has 
#                          problems finding the proper installation path.
#
# Variables defined by this module:
#
#  APR2_FOUND              System has Apache Portable Runtime 2 libs/headers
#  APR2_INCLUDE_DIRS       The location of Apache Portable Runtime 2 headers
#  APR2_LIBRARIES          The Apache Portable Runtime 2 libraries
#

find_path(APR2_INCLUDE_DIRS
  NAMES apr.h apu.h
  HINTS ${APR2_ROOT_DIR}/include
)

find_library(APR2_LIBRARIES
  NAMES ${APR2_LIBNAMES} apr-2
  HINTS ${APR2_ROOT_DIR}/lib
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(APR2
        "Could not find APR2 - try setting APR2_ROOT_DIR"
        APR2_INCLUDE_DIRS
        APR2_LIBRARIES
)

mark_as_advanced(
  APR2_FOUND
  APR2_INCLUDE_DIR
  APR2_LIBRARIES
)
