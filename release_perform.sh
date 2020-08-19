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
# Perform a release.
#
# Performing a release involves Maven currently to build and test things and we ran into problems
# with the default dir structure maven assumes. This script works around those and we need to sign
# the release archives anyway, which can be easily automated as well to not need to follow manual
# instructions always.
#
# It's important to note that this script is expected to be executed in the branch "next_stable",
# most likely prepared by the preparing counterpart.
#

function main
{
  # log4cxx is able to build using private copies of apr and apr-util, which are expected in some
  # special relative dir structure. That doesn't work with the default working dir "perform" uses,
  # which is "target/checkout". So we either need to make apr and apr-util available in "target" or
  # change the working dir. Making available seems easy using symlinks, but "mvn clean" deletes the
  # contents(!) of the linked dirs then. And always copying things around seems a bit unnecessary as
  # well, so I'm using a relocation of the folder for now. The downside is that "mvn clean" ignores
  # that dir by default.
  WD_RELEASE="$( pwd)/../log4cxx-next_stable"
  WD_DIST_DEV="$(pwd)/../log4cxx-dist-dev"

  perform_release
  prepare_dist_dev
  sign_and_copy
  publish_for_vote
}

function perform_release
{
  rm -rf "${WD_RELEASE}"
  mvn release:perform "-DworkingDirectory=${WD_RELEASE}"
}

# Prepare dist/dev to get the release candidate published for a vote.
function prepare_dist_dev
{
  mkdir -p "${WD_DIST_DEV}"
  pushd    "${WD_DIST_DEV}" > /dev/null

  if [ ! -d ".svn" ]
  then
    svn co "https://dist.apache.org/repos/dist/dev/logging/log4cxx" .
  fi
  svn up
}

function sign_and_copy
{
  # Might be a good idea to have another look at the GPG-plugin for Maven in the future:
  #
  # http://blog.sonatype.com/2010/01/how-to-generate-pgp-signatures-with-maven/
  # http://maven.apache.org/plugins/maven-gpg-plugin/
  pushd "${WD_RELEASE}/target" > /dev/null
  for file in *.tar.gz *.zip
  do
    echo "Processing ${file}:"

    gpg -ab --yes "${file}" > "${file}.asc"
    sha512sum     "${file}" > "${file}.sha512"

    # No symlinks because those would be treated as is, no hard-links because it should be safer for
    # commits.
    cp --force "${file}"        "${WD_DIST_DEV}"
    cp --force "${file}.asc"    "${WD_DIST_DEV}"
    cp --force "${file}.sha512" "${WD_DIST_DEV}"
  done
}

function publish_for_vote
{
  pushd "${WD_DIST_DEV}" > /dev/null
  echo "Please validate the files in $(pwd)"
  #svn add --force *.*
  #svn ci  -m "Publishing artifacts for new release to vote on."
}

main
