SUBDIRS = console_test

noinst_PROGRAMS = \
        consoleappender_test\
        fileappender_test\
        htmllayout_test\
        xmllayout_test

EXTRA_DIST = \
	consoleappender_test.sh\
	consoleappender_test.witness\
	fileappender_test.sh\
	fileappender_test.witness
	htmllayout_test.sh\
	htmllayout_test.witness
	xmllayout_test.sh\
	xmllayout_test.witness

INCLUDES = -I$(top_srcdir)/include

consoleappender_test_SOURCES = consoleappender_test.cpp
consoleappender_test_LDADD = $(top_builddir)/src/liblog4cxx.la

fileappender_test_SOURCES = fileappender_test.cpp
fileappender_test_LDADD = $(top_builddir)/src/liblog4cxx.la

htmllayout_test_SOURCES = htmllayout_test.cpp
htmllayout_test_LDADD = $(top_builddir)/src/liblog4cxx.la

xmllayout_test_SOURCES = xmllayout_test.cpp
xmllayout_test_LDADD = $(top_builddir)/src/liblog4cxx.la

TESTS = \
        consoleappender_test.sh\
        fileappender_test.sh\
        htmllayout_test.sh\
        xmllayout_test.sh
