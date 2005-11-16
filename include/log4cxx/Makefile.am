SUBDIRS = helpers net nt rolling spi varia xml config db private pattern filter
log4cxxincdir = $(includedir)/log4cxx
log4cxxinc_HEADERS= $(top_srcdir)/include/log4cxx/*.h log4cxx.h
DISTCLEANFILES = log4cxx.h
EXTRA_DIST = log4cxx.hw

dist-hook:
	-rm -f $(distdir)/log4cxx.h

