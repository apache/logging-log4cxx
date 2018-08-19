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
    sbr-test2.0 \
    sbr-test2.1 \
    sbr-test2.log \
    sbr-test3.0.gz \
    sbr-test3.1.gz \
    sbr-test3.log \
    sbr-test4.log \
    tbr-test1.0 \
    tbr-test1.1 \
    tbr-test1.2 \
    tbr-test1.3 \
    tbr-test2.0 \
    tbr-test2.1 \
    tbr-test2.2 \
    tbr-test2.3 \
    tbr-test3.3 \
    tbr-test4.0 \
    tbr-test4.1 \
    tbr-test4.2 \
    tbr-test4.3 \
    tbr-test5.0 \
    tbr-test5.1 \
    tbr-test5.2 \
    tbr-test5.3 \
    tbr-test6.3

# if we are building in a separate build tree, then prepare all necessary links
all-local:
	@if test "$(top_srcdir)" != "$(top_builddir)"; then \
	  echo "Symlinking test suite data files ..." ; \
	  for file in $(EXTRA_DIST); do \
	    test -a "$$file" || $(LN_S) "$(srcdir)/$$file"; \
	  done \
	fi
