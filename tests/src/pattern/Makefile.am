EXTRA_DIST = *.cpp
noinst_HEADERS= *.h

if TESTS

noinst_LIBRARIES = libpattern.a

INCLUDES = -I$(top_srcdir)/include

libpattern_a_SOURCES = \
	num343patternconverter.cpp \
	patternparsertestcase.cpp
	
check: libpattern.a

endif


