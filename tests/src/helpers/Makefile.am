EXTRA_DIST = *.cpp

if TESTS

noinst_LIBRARIES = libhelpers.a

INCLUDES = -I$(top_srcdir)/include

libhelpers_a_SOURCES = \
        absolutetimedateformattestcase.cpp \
        cacheddateformattestcase.cpp \
	cyclicbuffertestcase.cpp\
        datetimedateformattestcase.cpp \
        iso8601dateformattestcase.cpp \
	optionconvertertestcase.cpp       \
        relativetimedateformattestcase.cpp \
        stringtokenizertestcase.cpp \
        timezonetestcase.cpp

check: libhelpers.a

endif
