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
noinst_HEADERS = \
    $(top_srcdir)/src/test/cpp/abts.h \
    $(top_srcdir)/src/test/cpp/abts_tests.h \
    $(top_srcdir)/src/test/cpp/appenderskeletontestcase.h \
    $(top_srcdir)/src/test/cpp/customlogger/xlogger.h \
    $(top_srcdir)/src/test/cpp/fileappendertestcase.h \
    $(top_srcdir)/src/test/cpp/helpers/localechanger.h \
    $(top_srcdir)/src/test/cpp/insertwide.h \
    $(top_srcdir)/src/test/cpp/logunit.h \
    $(top_srcdir)/src/test/cpp/net/socketservertestcase.h \
    $(top_srcdir)/src/test/cpp/pattern/num343patternconverter.h \
    $(top_srcdir)/src/test/cpp/testchar.h \
    $(top_srcdir)/src/test/cpp/testutil.h \
    $(top_srcdir)/src/test/cpp/util/absolutedateandtimefilter.h \
    $(top_srcdir)/src/test/cpp/util/absolutetimefilter.h \
    $(top_srcdir)/src/test/cpp/util/binarycompare.h \
    $(top_srcdir)/src/test/cpp/util/compare.h \
    $(top_srcdir)/src/test/cpp/util/controlfilter.h \
    $(top_srcdir)/src/test/cpp/util/filenamefilter.h \
    $(top_srcdir)/src/test/cpp/util/filter.h \
    $(top_srcdir)/src/test/cpp/util/iso8601filter.h \
    $(top_srcdir)/src/test/cpp/util/linenumberfilter.h \
    $(top_srcdir)/src/test/cpp/util/relativetimefilter.h \
    $(top_srcdir)/src/test/cpp/util/serializationtesthelper.h \
    $(top_srcdir)/src/test/cpp/util/threadfilter.h \
    $(top_srcdir)/src/test/cpp/util/transformer.h \
    $(top_srcdir)/src/test/cpp/util/xmlfilenamefilter.h \
    $(top_srcdir)/src/test/cpp/util/xmllineattributefilter.h \
    $(top_srcdir)/src/test/cpp/util/xmlthreadfilter.h \
    $(top_srcdir)/src/test/cpp/util/xmltimestampfilter.h \
    $(top_srcdir)/src/test/cpp/vectorappender.h \
    $(top_srcdir)/src/test/cpp/writerappendertestcase.h \
    $(top_srcdir)/src/test/cpp/xml/xlevel.h

AM_CPPFLAGS = -I$(top_srcdir)/src/main/include -I$(top_builddir)/src/main/include

check_PROGRAMS = testsuite

customlogger_tests = \
    customlogger/xlogger.cpp \
    customlogger/xloggertestcase.cpp

defaultinit_tests = \
    defaultinit/testcase1.cpp \
    defaultinit/testcase2.cpp \
    defaultinit/testcase3.cpp \
    defaultinit/testcase4.cpp

filter_tests = \
    filter/andfiltertest.cpp \
    filter/denyallfiltertest.cpp \
    filter/levelmatchfiltertest.cpp \
    filter/levelrangefiltertest.cpp \
    filter/loggermatchfiltertest.cpp \
    filter/mapfiltertest.cpp \
    filter/stringmatchfiltertest.cpp

helpers = \
    helpers/absolutetimedateformattestcase.cpp \
    helpers/cacheddateformattestcase.cpp \
    helpers/charsetdecodertestcase.cpp \
    helpers/charsetencodertestcase.cpp \
    helpers/cyclicbuffertestcase.cpp \
    helpers/datetimedateformattestcase.cpp \
    helpers/inetaddresstestcase.cpp \
    helpers/iso8601dateformattestcase.cpp \
    helpers/localechanger.cpp \
    helpers/messagebuffertest.cpp \
    helpers/optionconvertertestcase.cpp       \
    helpers/propertiestestcase.cpp \
    helpers/relativetimedateformattestcase.cpp \
    helpers/stringtokenizertestcase.cpp \
    helpers/stringhelpertestcase.cpp \
    helpers/syslogwritertest.cpp \
    helpers/threadtestcase.cpp \
    helpers/timezonetestcase.cpp \
    helpers/transcodertestcase.cpp

net_tests = \
    net/smtpappendertestcase.cpp \
    net/socketappendertestcase.cpp \
    net/sockethubappendertestcase.cpp \
    net/socketservertestcase.cpp \
    net/syslogappendertestcase.cpp \
    net/telnetappendertestcase.cpp \
    net/xmlsocketappendertestcase.cpp

pattern_tests = \
    pattern/num343patternconverter.cpp \
    pattern/patternparsertestcase.cpp

rolling_tests = \
    rolling/filenamepatterntestcase.cpp \
    rolling/filterbasedrollingtest.cpp \
    rolling/manualrollingtest.cpp \
    rolling/obsoletedailyrollingfileappendertest.cpp \
    rolling/obsoleterollingfileappendertest.cpp \
    rolling/sizebasedrollingtest.cpp \
    rolling/timebasedrollingtest.cpp

util = \
    util/absolutetimefilter.cpp \
    util/absolutedateandtimefilter.cpp \
    util/binarycompare.cpp \
    util/compare.cpp \
    util/controlfilter.cpp \
    util/filenamefilter.cpp \
    util/utilfilter.cpp \
    util/iso8601filter.cpp \
    util/linenumberfilter.cpp \
    util/relativetimefilter.cpp \
    util/serializationtesthelper.cpp \
    util/threadfilter.cpp \
    util/transformer.cpp \
    util/xmlfilenamefilter.cpp \
    util/xmllineattributefilter.cpp \
    util/xmltimestampfilter.cpp \
    util/xmlthreadfilter.cpp

varia_tests = \
    varia/errorhandlertestcase.cpp \
    varia/levelmatchfiltertestcase.cpp \
    varia/levelrangefiltertestcase.cpp

db_tests = \
    db/odbcappendertestcase.cpp

xml_tests = \
    xml/customleveltestcase.cpp \
    xml/domtestcase.cpp \
    xml/xlevel.cpp \
    xml/xmllayouttestcase.cpp \
    xml/xmllayouttest.cpp

nt_tests = \
    nt/nteventlogappendertestcase.cpp

testsuite_SOURCES = \
    $(customlogger_tests) \
    $(defaultinit_tests) \
    $(filter_tests) \
    $(helpers) \
    $(net_tests) \
    $(pattern_tests) \
    $(rolling_tests) \
    $(util) \
    $(varia_tests) \
    $(db_tests) \
    $(xml_tests) \
    $(nt_tests) \
    abts.cpp \
    asyncappendertestcase.cpp \
    encodingtest.cpp \
    filetestcase.cpp \
    hierarchytest.cpp \
    hierarchythresholdtestcase.cpp \
    jsonlayouttest.cpp \
    l7dtestcase.cpp \
    leveltestcase.cpp \
    logunit.cpp \
    loggertestcase.cpp \
    minimumtestcase.cpp \
    patternlayouttest.cpp \
    vectorappender.cpp \
    appenderskeletontestcase.cpp \
    consoleappendertestcase.cpp \
    fileappendertestcase.cpp \
    rollingfileappendertestcase.cpp \
    streamtestcase.cpp \
    writerappendertestcase.cpp \
    ndctestcase.cpp \
    propertyconfiguratortest.cpp \
    mdctestcase.cpp

testsuite_LDADD = \
    $(top_builddir)/src/main/cpp/liblog4cxx.la

testsuite_DEPENDENCIES = \
    $(top_builddir)/src/main/cpp/liblog4cxx.la

check: testsuite
