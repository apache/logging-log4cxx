EXTRA_DIST = *.cpp

if TESTS

INCLUDES = -I$(top_srcdir)/include
check_PROGRAMS = testsuite
testsuite_SOURCES = \
	main.cpp \
	loggertestcase.cpp
testsuite_LDADD = $(top_builddir)/src/liblog4cxx.la
testsuite_LDFLAGS = -lcppunit -ldl

TESTS = testsuite

endif
