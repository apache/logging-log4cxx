SUBDIRS = xml
noinst_PROGRAMS = logging

performanceincdir = $(includedir)/log4cxx
performanceinc_HEADERS= *.h

INCLUDES = -I$(top_srcdir)/include

logging_SOURCES = main.cpp nullappender.cpp
logging_LDADD = $(top_builddir)/src/liblog4cxx.la

EXTRA_DIST = logging.sh

