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
# Sign release artifacts until a better solution is available.
#

# log4cxx is able to build using private copies of apr and apr-util, which are
# then expected in some special relative dir structure. That doesn't work with
# the default working dir "perform", which is "target/checkout". So we either
# need to make apr and apr-util available in "target" or change the working
# dir. Making available seems easy using symlinks, but "mvn clean" deletes the
# contents of the linked files then. And always copying things around seems a
# bit unnecessary as well, so I'm using a relocation of the folder for now.
WD="$(pwd)/../log4cxx-release"
mvn release:perform "-DworkingDirectory=${WD}"

# Might be a good idea to have another look at the GBG plugin for Maven in the
# future:
#
# http://blog.sonatype.com/2010/01/how-to-generate-pgp-signatures-with-maven/
# http://maven.apache.org/plugins/maven-gpg-plugin/
pushd "${WD}"
for file in *.tar.gz *.zip
do
  echo "Processing ${file}:"

  md5sum        "${file}" > "${file}.md5"
  sha512sum     "${file}" > "${file}.sha"
  gpg -ab --yes "${file}" > "${file}.asc"
done
