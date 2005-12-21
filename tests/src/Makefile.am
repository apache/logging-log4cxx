noinst_HEADERS = \
	$(top_srcdir)/tests/src/customlogger/*.h \
	$(top_srcdir)/tests/src/helpers/*.h \
	$(top_srcdir)/tests/src/net/*.h \
	$(top_srcdir)/tests/src/pattern/*.h \
	$(top_srcdir)/tests/src/util/*.h \
	$(top_srcdir)/tests/src/xml/*.h \
	$(top_srcdir)/tests/src/*.h

if TESTS

INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)/include

noinst_PROGRAMS = testsuite shortsocketserver

customlogger_tests = \
	customlogger/xlogger.cpp\
	customlogger/xloggertestcase.cpp

defaultinit_tests = \
	defaultinit/testcase1.cpp\
	defaultinit/testcase2.cpp\
	defaultinit/testcase3.cpp\
	defaultinit/testcase4.cpp

helpers = \
        helpers/absolutetimedateformattestcase.cpp \
        helpers/cacheddateformattestcase.cpp \
        helpers/charsetdecodertestcase.cpp \
        helpers/charsetencodertestcase.cpp \
        helpers/cyclicbuffertestcase.cpp\
        helpers/datetimedateformattestcase.cpp \
        helpers/iso8601dateformattestcase.cpp \
        helpers/localechanger.cpp\
        helpers/optionconvertertestcase.cpp       \
        helpers/propertiestestcase.cpp \
        helpers/relativetimedateformattestcase.cpp \
        helpers/stringtokenizertestcase.cpp \
        helpers/stringhelpertestcase.cpp \
        helpers/timezonetestcase.cpp \
        helpers/transcodertestcase.cpp \
        helpers/unicodehelpertestcase.cpp 

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
	util/absolutetimefilter.cpp\
	util/absolutedateandtimefilter.cpp\
	util/binarycompare.cpp\
	util/compare.cpp\
	util/controlfilter.cpp\
	util/filenamefilter.cpp \
	util/filter.cpp\
	util/iso8601filter.cpp\
	util/linenumberfilter.cpp\
	util/relativetimefilter.cpp\
	util/threadfilter.cpp\
	util/transformer.cpp\
	util/xmlfilenamefilter.cpp \
	util/xmllineattributefilter.cpp\
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
	xml/xmllayouttestcase.cpp

nt_tests = \
	nt/nteventlogappendertestcase.cpp

testsuite_SOURCES = \
        $(customlogger_tests) \
        $(defaultinit_tests) \
        $(helpers) \
        $(net_tests) \
        $(pattern_tests) \
        $(rolling_tests) \
        $(util) \
        $(varia_tests) \
        $(db_tests) \
        $(xml_tests) \
        $(nt_tests) \
        asyncappendertestcase.cpp\
        encodingtest.cpp\
        filetestcase.cpp \
        hierarchythresholdtestcase.cpp\
        l7dtestcase.cpp\
        leveltestcase.cpp \
        loggertestcase.cpp\
        main.cpp\
        minimumtestcase.cpp\
        patternlayouttest.cpp\
        vectorappender.cpp\
        appenderskeletontestcase.cpp\
        consoleappendertestcase.cpp\
        fileappendertestcase.cpp\
        rollingfileappendertestcase.cpp\
        streamtestcase.cpp\
        writerappendertestcase.cpp \
        ndctestcase.cpp

testsuite_LDADD = \
        $(top_builddir)/src/liblog4cxx.la

testsuite_LDFLAGS = \
        @LIBS_CPPUNIT@

AM_CPPFLAGS = \
        @CPPFLAGS_CPPUNIT@

testsuite_DEPENDENCIES = \
        $(top_builddir)/src/liblog4cxx.la

shortsocketserver_SOURCES = \
        $(util) \
        $(xml_tests) \
        shortsocketserver.cpp

shortsocketserver_LDADD = \
        $(top_builddir)/src/liblog4cxx.la

shortsocketserver_LDFLAGS = \
        @LIBS_CPPUNIT@

shortsocketserver_DEPENDENCIES = \
        $(top_builddir)/src/liblog4cxx.la

check: testsuite shortsocketserver

endif
