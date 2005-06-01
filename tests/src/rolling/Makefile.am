EXTRA_DIST = *.cpp

if TESTS

noinst_LIBRARIES = librolling.a

INCLUDES = -I$(top_srcdir)/include

librolling_a_SOURCES = \
        filenamepatterntestcase.cpp \
        filterbasedrollingtest.cpp \
        manualrollingtest.cpp \
        obsoletedailyrollingfileappendertest.cpp \
        obsoleterollingfileappendertest.cpp \
        sizebasedrollingtest.cpp \
        timebasedrollingtest.cpp

check: librolling.a

endif


