EXTRA_DIST = $(top_srcdir)/tests/src/db/*.cpp
noinst_HEADERS= $(top_srcdir)/tests/src/db/*.h

if TESTS

noinst_LIBRARIES = libdb.a
INCLUDES = -I$(top_srcdir)/include

libnet_a_SOURCES = \
	socketservertestcase.cpp

check: libdb.a

endif


