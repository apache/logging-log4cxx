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
SUBDIRS = ndc xml rolling
EXTRA_DIST = \
    defaultInit3.properties \
    hierarchyThreshold1.properties \
    hierarchyThreshold2.properties \
    hierarchyThreshold3.properties \
    hierarchyThreshold4.properties \
    hierarchyThreshold5.properties \
    hierarchyThreshold6.properties \
    hierarchyThreshold7.properties \
    hierarchyThreshold8.properties \
    l7d1.properties \
    patternLayout10.properties \
    patternLayout11.properties \
    patternLayout12.properties \
    patternLayout1.properties \
    patternLayout2.properties \
    patternLayout3.properties \
    patternLayout4.properties \
    patternLayout5.properties \
    patternLayout6.properties \
    patternLayout7.properties \
    patternLayout8.properties \
    patternLayout9.properties \
    patternLayout.mdc.1.properties \
    propertiestestcase.properties \
    socketServer1.properties \
    socketServer2.properties \
    socketServer3.properties \
    socketServer4.properties \
    socketServer5.properties \
    socketServer6.properties \
    socketServer7.properties \
    socketServer8.properties

# if we are building in a separate build tree, then prepare all necessary links
all-local:
	@if test "$(top_srcdir)" != "$(top_builddir)"; then \
	  echo "Symlinking test suite data files ..." ; \
	  for file in $(EXTRA_DIST); do \
	    test -a "$$file" || $(LN_S) "$(srcdir)/$$file"; \
	  done \
	fi
