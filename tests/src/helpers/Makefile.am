EXTRA_DIST = *.cpp *.h

if TESTS

noinst_LIBRARIES = libhelpers.a

INCLUDES = -I$(top_srcdir)/include

libhelpers_a_SOURCES = \
        absolutetimedateformattestcase.cpp \
        cacheddateformattestcase.cpp \
        cyclicbuffertestcase.cpp\
        datetimedateformattestcase.cpp \
        iso8601dateformattestcase.cpp \
        localechanger.cpp\
        optionconvertertestcase.cpp       \
        propertiestestcase.cpp \
        relativetimedateformattestcase.cpp \
        stringtokenizertestcase.cpp \
        timezonetestcase.cpp \
        transcodertestcase.cpp

check: libhelpers.a

endif
