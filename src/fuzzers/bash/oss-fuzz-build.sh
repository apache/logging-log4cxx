#!/bin/bash -eu
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

# Read command line arguments
if [[ "$#" -ne 1 ]]; then
  cat >&2 <<EOF
Generates fuzzer runner scripts to be employed by Google OSS-Fuzz.
For details, see: http://logging.apache.org/log4cxx/fuzzing.html

Usage: $0 <outputDir>

  outputDir

    The output directory to dump runner scripts and their dependencies.
EOF
  exit 1
fi
outputDir=$(readlink -f "$1")

# Ensure output directory exists
mkdir -p "$outputDir"

# Switch to the project directory (by referencing from the script directory)
cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && cd ../../..

# Build the project
mkdir -p build && cd $_
cmake \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_FUZZERS=ON \
  ..
cmake --build . -j

# Copy executables & resources
find src/fuzzers/cpp -maxdepth 1 -executable -type f -exec cp -v {} "$outputDir/" \;
cp -v ../src/fuzzers/resources/* "$outputDir/"
