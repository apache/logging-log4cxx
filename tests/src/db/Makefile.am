EXTRA_DIST = $(top_srcdir)/tests/src/db/*.cpp

if TESTS

noinst_LIBRARIES = libdb.a
INCLUDES = -I$(top_srcdir)/include

libdb_a_SOURCES = \
	odbcappendertestcase.cpp

check: libdb.a

endif


