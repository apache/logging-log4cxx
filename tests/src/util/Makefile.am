EXTRA_DIST = *.cpp
noinst_HEADERS= *.h

if TESTS

noinst_LIBRARIES = libutil.a

INCLUDES = -I$(top_srcdir)/include

libutil_a_SOURCES = \
	absolutetimefilter.cpp\
	absolutedateandtimefilter.cpp\
	compare.cpp\
	controlfilter.cpp\
	filter.cpp\
	iso8601filter.cpp\
	linenumberfilter.cpp\
	relativetimefilter.cpp\
	threadfilter.cpp\
	transformer.cpp
	
check: libutil.a

endif


