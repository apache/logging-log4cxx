EXTRA_DIST = *.cpp
noinst_HEADERS= *.h

if TESTS

noinst_LIBRARIES = libxml.a

INCLUDES = -I$(top_srcdir)/include

libxml_a_SOURCES = \
	xlevel.cpp
	
check: libxml.a

endif
