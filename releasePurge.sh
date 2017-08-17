#! /bin/bash -e
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

function main()
{
  purge_branch_and_tag
  revert_pom_and_changes
}

function purge_branch_and_tag()
{
  git checkout  "release_scripts"
  git branch -D "next_stable"
  git tag  --delete "v0.11.0-RC1"
  git push --delete "origin" "next_stable" 
  git push --delete "origin" "v0.11.0-RC1"
}

function revert_pom_and_changes()
{
  sed -i -r "s/^(\t<version>).+(<)/\10.11.0-SNAPSHOT\2/" "pom.xml"
  sed -i -r "1,/.+<release.+/ s/.+<release.+//"          "src/changes/changes.xml"
  sed -i -r "1,/.+date=.+/ s/.+date=.+//"                "src/changes/changes.xml"
  sed -i -r "1,/.+description=.+/ s/.+description=.+//"  "src/changes/changes.xml"
  sed -i -r "1,/.+<\/release.+/ s/.+<\/release.+//"      "src/changes/changes.xml"
  
  # Don't know ho to remove the created newlines in changes easier...
  local changes=$(cat "src/changes/changes.xml")
  echo "${changes/$'\n\n\n\n\n'/}" > "src/changes/changes.xml"

  git add "pom.xml"
  git add "src/changes/changes.xml"

  git commit -m "No 0.11.1 yet."
}

main
