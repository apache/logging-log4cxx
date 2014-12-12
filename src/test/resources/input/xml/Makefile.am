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
EXTRA_DIST = \
    log4j.dtd \
    asyncAppender1.xml \
    customLevel1.xml \
    customLevel2.xml \
    customLevel3.xml \
    customLevel4.xml \
    customLogger1.xml \
    customLogger2.xml \
    defaultInit.xml \
    DOMTestCase1.xml \
    DOMTestCase2.xml \
    DOMTestCase3.xml \
    DOMTestCase4.xml \
    fallback1.xml \
    filters.LevelMatchFilter.test4.0.xml \
    filters.LevelMatchFilter.test4.1.xml \
    filters.LevelMatchFilter.test4.2.xml \
    filters.LevelMatchFilter.test4.3.xml \
    filters.LevelMatchFilter.test4.4.xml \
    smtpAppender1.xml

# if we are building in a separate build tree, then prepare all necessary links
all-local:
	@if test "$(top_srcdir)" != "$(top_builddir)"; then \
	  echo "Symlinking test suite data files ..." ; \
	  for file in $(EXTRA_DIST); do \
	    test -a "$$file" || $(LN_S) "$(srcdir)/$$file"; \
	  done \
	fi
