EXTRA_DIST = *.cpp

if TESTS

noinst_LIBRARIES = libhelpers.a

INCLUDES = -I$(top_srcdir)/include

libhelpers_a_SOURCES = \
	boundedfifotestcase.cpp
	
check: libhelpers.a

endif
