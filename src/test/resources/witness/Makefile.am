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
SUBDIRS = encoding ndc rolling
EXTRA_DIST = \
    customLevel.1 \
    customLevel.2 \
    customLevel.3 \
    customLevel.4 \
    customLogger.1 \
    customLogger.2 \
    dom.A1.1 \
    dom.A1.2 \
    dom.A2.1 \
    dom.A2.2 \
    fallback1 \
    hierarchyThreshold.1 \
    hierarchyThreshold.2 \
    hierarchyThreshold.3 \
    hierarchyThreshold.4 \
    hierarchyThreshold.5 \
    hierarchyThreshold.6 \
    hierarchyThreshold.7 \
    hierarchyThreshold.8 \
    l7d.1 \
    LevelMatchFilter_accept \
    LevelMatchFilter_deny \
    LevelRangeFilter_accept \
    LevelRangeFilter_neutral \
    NDCMatchFilter_accept \
    NDCMatchFilter_deny \
    patternLayout.1 \
    patternLayout.10 \
    patternLayout.11 \
    patternLayout.12 \
    patternLayout.2 \
    patternLayout.3 \
    patternLayout.4 \
    patternLayout.5 \
    patternLayout.6 \
    patternLayout.7 \
    patternLayout.8 \
    patternLayout.9 \
    patternLayout.mdc.1 \
    patternLayout.mdc.2 \
    simple \
    socketServer.1 \
    socketServer.2 \
    socketServer.3 \
    socketServer.4 \
    socketServer.5 \
    socketServer.6 \
    socketServer.7 \
    socketServer.8 \
    ttcc \
    xmlLayout.1 \
    xmlLayout.2 \
    xmlLayout.3 \
    xmlLayout.mdc.1 \
    xmlLayout.mdc.2 \
    xmlLayout.null

# if we are building in a separate build tree, then prepare all necessary links
all-local:
	@if test "$(top_srcdir)" != "$(top_builddir)"; then \
	  echo "Symlinking test suite data files ..." ; \
	  for file in $(EXTRA_DIST); do \
	    test -a "$$file" || $(LN_S) "$(srcdir)/$$file"; \
	  done \
	fi
