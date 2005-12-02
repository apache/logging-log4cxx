EXTRA_DIST = $(top_srcdir)/tests/src/nt/*.cpp

if TESTS

noinst_LIBRARIES = libnt.a
INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)/include

libnt_a_SOURCES = \
	nteventlogappendertestcase.cpp

check: libnt.a

endif


