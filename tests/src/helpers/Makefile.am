EXTRA_DIST = *.cpp *.h

if TESTS

noinst_LIBRARIES = libhelpers.a

INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)/include

libhelpers_a_SOURCES = \
        absolutetimedateformattestcase.cpp \
        cacheddateformattestcase.cpp \
        charsetdecodertestcase.cpp \
        charsetencodertestcase.cpp \
        cyclicbuffertestcase.cpp\
        datetimedateformattestcase.cpp \
        iso8601dateformattestcase.cpp \
        localechanger.cpp\
        optionconvertertestcase.cpp       \
        propertiestestcase.cpp \
        relativetimedateformattestcase.cpp \
        stringtokenizertestcase.cpp \
        stringhelpertestcase.cpp \
        timezonetestcase.cpp \
        transcodertestcase.cpp \
        unicodehelpertestcase.cpp 

check: libhelpers.a

endif
