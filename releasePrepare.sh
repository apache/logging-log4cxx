#! /bin/bash
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
# Prepare a release.
#
# We need to update dates and version numbers at various places during releases
# and quite a lot of the needed changes are possible in this script, so that is
# preferred over manually following some docs in the wiki.
#

if [[ -n $(git status --short) || -n $(git diff-index HEAD) ]]
then
  echo Maven release process requires committed changes!
  exit 1
fi

branch_starting=$(         git branch | grep "\*" | cut -d " " -f 2)
branch_starting_is_ns=$(   git branch | grep "\* next_stable")

if [ -z "${branch_starting_is_ns}" ]
then
  git checkout "next_stable" || git checkout -b "next_stable"
  git merge "${branch_starting}"
fi

today=$(date "+%Y-%m-%d")
sed -i -r "1,/date=\".+?\"/ s/date=\".+?\"/date=\"${today}\"/" "src/changes/changes.xml"
git add "src/changes/changes.xml"
if ! git diff-index --quiet HEAD
then
  git commit -m "Set release date to today."
  commit_changes=$(git log --max-count=1 | grep "commit" | cut -d " " -f 2)
  git checkout "${branch_starting}"
  git merge    "${commit_changes}"
  git checkout "next_stable"
fi

#mvn clean                          || exit 1
#mvn release:prepare -Dresume=false || exit 1

if [ -n "${branch_starting_is_ns}" ]
then
  git checkout "${branch_starting}"
  new_release_cycle=$(grep 'date="XXXX-XX-XX"' "src/changes/changes.xml")
  if [ -n "${new_release_cycle}" ]
  then
    git checkout "next_stable"
    exit 0
  fi
fi

# Propagate new version into some additional files:
new_dev_ver_short=$(grep -E "^project.dev.log4cxx" "release.properties" | cut -d "=" -f 2 | cut -d - -f 1)
new_release=$(cat <<-"END"
	<body>\n\
		<release	version="VER_NEEDED"\n\
					date="XXXX-XX-XX"\n\
					description="Maintenance release">\n\
		<\/release>\n
END
)
new_release="${new_release/VER_NEEDED/${new_dev_ver_short}}"

sed -i -r "s/AC_INIT\(\[log4cxx\], \[.+?\]\)/AC_INIT([log4cxx], [${new_dev_ver_short}])/" "configure.ac"
sed -i -r "s/<body>/${new_release}/" "src/changes/changes.xml"

git add "configure.ac"
git add "src/changes/changes.xml"
if ! git diff-index --quiet HEAD
then
  git commit -m "Prepare for next development iteration: ${new_dev_ver_short}"
fi
git checkout "next_stable"
