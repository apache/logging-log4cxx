EXTRA_DIST = *.cpp
noinst_HEADERS= *.h

if TESTS

noinst_LIBRARIES = libnet.a
INCLUDES = -I$(top_srcdir)/include

libnet_a_SOURCES = \
	socketservertestcase.cpp

check: libnet.a 

endif


