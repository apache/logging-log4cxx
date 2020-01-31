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
SUBDIRS = helpers net nt rolling spi varia xml config db private pattern filter
log4cxxincdir = $(includedir)/log4cxx
DISTCLEANFILES = log4cxx.h
EXTRA_DIST = log4cxx.hw

# Importantly, $(top_srcdir)/src/main/include/log4cxx/log4cxx.h
# does NOT appear in the following list so the built version is preferred.
# This subtly is important for properly handling VPATH vs non-VPATH builds.
log4cxxinc_HEADERS  = $(top_builddir)/src/main/include/log4cxx/log4cxx.h
log4cxxinc_HEADERS += \
    $(top_srcdir)/src/main/include/log4cxx/appender.h \
    $(top_srcdir)/src/main/include/log4cxx/appenderskeleton.h \
    $(top_srcdir)/src/main/include/log4cxx/asyncappender.h \
    $(top_srcdir)/src/main/include/log4cxx/basicconfigurator.h \
    $(top_srcdir)/src/main/include/log4cxx/consoleappender.h \
    $(top_srcdir)/src/main/include/log4cxx/dailyrollingfileappender.h \
    $(top_srcdir)/src/main/include/log4cxx/defaultconfigurator.h \
    $(top_srcdir)/src/main/include/log4cxx/defaultloggerfactory.h \
    $(top_srcdir)/src/main/include/log4cxx/fileappender.h \
    $(top_srcdir)/src/main/include/log4cxx/file.h \
    $(top_srcdir)/src/main/include/log4cxx/hierarchy.h \
    $(top_srcdir)/src/main/include/log4cxx/htmllayout.h \
    $(top_srcdir)/src/main/include/log4cxx/jsonlayout.h \
    $(top_srcdir)/src/main/include/log4cxx/layout.h \
    $(top_srcdir)/src/main/include/log4cxx/level.h \
    $(top_srcdir)/src/main/include/log4cxx/logger.h \
    $(top_srcdir)/src/main/include/log4cxx/logmanager.h \
    $(top_srcdir)/src/main/include/log4cxx/logstring.h \
    $(top_srcdir)/src/main/include/log4cxx/mdc.h \
    $(top_srcdir)/src/main/include/log4cxx/ndc.h \
    $(top_srcdir)/src/main/include/log4cxx/patternlayout.h \
    $(top_srcdir)/src/main/include/log4cxx/portability.h \
    $(top_srcdir)/src/main/include/log4cxx/propertyconfigurator.h \
    $(top_srcdir)/src/main/include/log4cxx/provisionnode.h \
    $(top_srcdir)/src/main/include/log4cxx/rollingfileappender.h \
    $(top_srcdir)/src/main/include/log4cxx/simplelayout.h \
    $(top_srcdir)/src/main/include/log4cxx/stream.h \
    $(top_srcdir)/src/main/include/log4cxx/ttcclayout.h \
    $(top_srcdir)/src/main/include/log4cxx/writerappender.h

dist-hook:
	-rm -f $(distdir)/log4cxx.h
