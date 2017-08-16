#! /bin/sh
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

##
# Purge (some) releases during development of release scripts.
#
# This script is mainly used during development of the release scripts itself and simply deletes
# branches and tags created during tests of the release process. Be very careful with execution!
#
git checkout  "release_scripts"
git branch -D "next_stable"
git tag  --delete "v0.11.0-RC1"
git push --delete "origin" "next_stable" "v0.11.0-RC1"
