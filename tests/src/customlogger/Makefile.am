EXTRA_DIST = *.cpp
noinst_HEADERS= *.h

if TESTS

noinst_LIBRARIES = libcustomlogger.a

INCLUDES = -I$(top_srcdir)/include

libcustomlogger_a_SOURCES = \
	xlogger.cpp\
	xloggertestcase.cpp
	
check: libcustomlogger.a

endif
