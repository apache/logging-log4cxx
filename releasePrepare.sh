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
# Prepare a release.
#
# We need to update dates and version numbers at various places during releases
# and quite a lot of the needed changes are possible in this script, so that is
# preferred over manually following some docs in the wiki.
#

TODAY=$(date "+%Y-%m-%d")
sed -i -r "s/date=\"XXXX-XX-XX\"/date=\"${TODAY}\"/" "src/changes/changes.xml"
git add "src/changes/changes.xml"
git diff-index --quiet HEAD || git commit -m "Set release date to today."

mvn clean
mvn release:prepare -Dresume=false

# Propagate new version into some additional files:
NEW_DEV_VER_SHORT=$(grep -E "^project.dev.log4cxx" "release.properties" | cut -d = -f 2 | cut -d - -f 1)
NEW_RELEASE=$(cat <<-"END"
	<body>\n\
		<release	version="VER_NEEDED"\n\
					date="XXXX-XX-XX"\n\
					description="Maintenance release">\n\
		<\/release>\n
END
)
NEW_RELEASE="${NEW_RELEASE/VER_NEEDED/${NEW_DEV_VER_SHORT}}"

sed -i -r "s/AC_INIT\(\[log4cxx\], \[.+?\]\)/AC_INIT([log4cxx], [${NEW_DEV_VER_SHORT}])/" "configure.ac"
sed -i -r "s/<body>/${NEW_RELEASE}/" "src/changes/changes.xml"

git add "configure.ac"
git add "src/changes/changes.xml"
git diff-index --quiet HEAD || git commit -m "Prepare for next development iteration: ${NEW_DEV_VER_SHORT}"
