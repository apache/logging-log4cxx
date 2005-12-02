EXTRA_DIST = $(top_srcdir)/tests/src/net/*.cpp
noinst_HEADERS= $(top_srcdir)/tests/src/net/*.h

if TESTS

noinst_LIBRARIES = libnet.a
INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)/include

libnet_a_SOURCES = \
	smtpappendertestcase.cpp \
	socketappendertestcase.cpp \
	sockethubappendertestcase.cpp \
	socketservertestcase.cpp \
	syslogappendertestcase.cpp \
	telnetappendertestcase.cpp \
	xmlsocketappendertestcase.cpp

check: libnet.a 

endif


