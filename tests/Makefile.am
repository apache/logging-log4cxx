SUBDIRS = console_test
noinst_PROGRAMS = \
		hierarchy_test\
		level_test\
		ndc_test\
		filter_test\
        consoleappender_test\
        fileappender_test\
        htmllayout_test\
        xmllayout_test\
        ttcclayout_test\
        patternlayout_test

EXTRA_DIST = \
  hierarchy_test.witness\
  hierarchy_test.sh\
  level_test.witness\
  level_test.sh\
  ndc_test.witness\
  ndc_test.sh\
  filter_test.witness\
  filter_test.sh\
  consoleappender_test.sh\
  consoleappender_test.witness\
  fileappender_test.sh\
  fileappender_test.witness\
  htmllayout_test.sh\
  htmllayout_test.witness\
  xmllayout_test.sh\
  xmllayout_test.witness\
  ttcclayout_test.sh\
  patternlayout_test.witness\
  patternlayout_test.sh

INCLUDES = -I$(top_srcdir)/include

hierarchy_test_SOURCES = hierarchy_test.cpp
hierarchy_test_LDADD = $(top_builddir)/src/liblog4cxx.la

level_test_SOURCES = level_test.cpp
level_test_LDADD = $(top_builddir)/src/liblog4cxx.la

ndc_test_SOURCES = ndc_test.cpp
ndc_test_LDADD = $(top_builddir)/src/liblog4cxx.la

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

TESTS = \
		hierarchy_test.sh\
		level_test.sh\
		ndc_test.sh\
 		filter_test.sh\
		consoleappender_test.sh\
        fileappender_test.sh\
        htmllayout_test.sh\
        xmllayout_test.sh\
        ttcclayout_test.sh\
        patternlayout_test.sh
