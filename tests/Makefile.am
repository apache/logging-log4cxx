SUBDIRS = console_test

noinst_PROGRAMS = consoleappender_test fileappender_test

EXTRA_DIST = \
	consoleappender_test.sh\
	consoleappender_test.witness\
	fileappender_test.sh\
	fileappender_test.witness

INCLUDES = -I$(top_srcdir)/include

consoleappender_test_SOURCES = consoleappender_test.cpp
consoleappender_test_LDADD = $(top_builddir)/src/liblog4cxx.la

fileappender_test_SOURCES = fileappender_test.cpp
fileappender_test_LDADD = $(top_builddir)/src/liblog4cxx.la

TESTS = consoleappender_test.sh fileappender_test.sh

