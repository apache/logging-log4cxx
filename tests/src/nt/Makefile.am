EXTRA_DIST = $(top_srcdir)/tests/src/nt/*.cpp
noinst_HEADERS= $(top_srcdir)/tests/src/nt/*.h

if TESTS

noinst_LIBRARIES = libnt.a
INCLUDES = -I$(top_srcdir)/include

libnet_a_SOURCES = \
	socketservertestcase.cpp

check: libnt.a

endif


