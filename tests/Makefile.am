noinst_PROGRAMS = \
		hierarchy_test\
		level_test\
		ndc_test\
		mdc_test\
		filter_test\
        consoleappender_test\
        fileappender_test\
        htmllayout_test\
        xmllayout_test\
        ttcclayout_test\
        patternlayout_test\
		propertyconfigurator_test\
		domconfigurator_test

EXTRA_DIST = \
  consoleappender_test.sh\
  consoleappender_test.witness\
  propertyconfigurator_test.properties\
  domconfigurator_test.xml

INCLUDES = -I$(top_srcdir)/include

hierarchy_test_SOURCES = hierarchy_test.cpp
hierarchy_test_LDADD = $(top_builddir)/src/liblog4cxx.la

level_test_SOURCES = level_test.cpp
level_test_LDADD = $(top_builddir)/src/liblog4cxx.la

ndc_test_SOURCES = ndc_test.cpp
ndc_test_LDADD = $(top_builddir)/src/liblog4cxx.la

mdc_test_SOURCES = mdc_test.cpp
mdc_test_LDADD = $(top_builddir)/src/liblog4cxx.la

filter_test_SOURCES = filter_test.cpp
filter_test_LDADD = $(top_builddir)/src/liblog4cxx.la

consoleappender_test_SOURCES = consoleappender_test.cpp
consoleappender_test_LDADD = $(top_builddir)/src/liblog4cxx.la

fileappender_test_SOURCES = fileappender_test.cpp
fileappender_test_LDADD = $(top_builddir)/src/liblog4cxx.la

htmllayout_test_SOURCES = htmllayout_test.cpp
htmllayout_test_LDADD = $(top_builddir)/src/liblog4cxx.la

xmllayout_test_SOURCES = xmllayout_test.cpp
xmllayout_test_LDADD = $(top_builddir)/src/liblog4cxx.la

ttcclayout_test_SOURCES = ttcclayout_test.cpp
ttcclayout_test_LDADD = $(top_builddir)/src/liblog4cxx.la

patternlayout_test_SOURCES = patternlayout_test.cpp
patternlayout_test_LDADD = $(top_builddir)/src/liblog4cxx.la

propertyconfigurator_test_SOURCES = propertyconfigurator_test.cpp
propertyconfigurator_test_LDADD = $(top_builddir)/src/liblog4cxx.la

domconfigurator_test_SOURCES = domconfigurator_test.cpp
domconfigurator_test_LDADD = $(top_builddir)/src/liblog4cxx.la

TESTS = \
		hierarchy_test\
		level_test\
		ndc_test\
		mdc_test\
 		filter_test\
		consoleappender_test.sh\
        fileappender_test\
        htmllayout_test\
        xmllayout_test\
        ttcclayout_test\
        patternlayout_test\
		propertyconfigurator_test\
		domconfigurator_test
