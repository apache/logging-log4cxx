lib_LTLIBRARIES = liblog4cxx.la

INCLUDES = -I$(top_srcdir)/include

liblog4cxx_la_SOURCES = \
	appenderattachableimpl.cpp \
	appenderskeleton.cpp \
	asyncappender.cpp \
	boundedfifo.cpp \
	consoleappender.cpp \
	criticalsection.cpp \
	datelayout.cpp \
	dateformat.cpp \
	defaultcategoryfactory.cpp \
	domconfigurator.cpp \
	fileappender.cpp \
	formattinginfo.cpp \
	gnomexmlreader.cpp \
	hierarchy.cpp \
	htmllayout.cpp \
	inetaddress.cpp \
	level.cpp \
	levelmatchfilter.cpp \
	levelrangefilter.cpp \
	logger.cpp \
	loggingevent.cpp \
	loglog.cpp \
	logmanager.cpp \
	msxmlreader.cpp \
	ndc.cpp \
	nteventlogappender.cpp \
	objectimpl.cpp\
	onlyonceerrorhandler.cpp \
	optionconverter.cpp \
	patternconverter.cpp \
	patternlayout.cpp \
	patternparser.cpp \
	rollingfileappender.cpp \
	rootcategory.cpp \
	serversocket.cpp \
	semaphore.cpp \
	simplelayout.cpp \
	socket.cpp \
	socketappender.cpp \
	sockethubappender.cpp \
	socketimpl.cpp \
	socketinputstream.cpp \
	socketnode.cpp \
	socketoutputstream.cpp \
	stringmatchfilter.cpp \
	telnetappender.cpp \
	transform.cpp \
	thread.cpp \
	threadspecificdata.cpp \
	ttcclayout.cpp \
	writerappender.cpp \
	xmllayout.cpp

liblog4cxx_la_LDFLAGS = -version-info @LT_VERSION@

bin_PROGRAMS = simplesocketserver
simplesocketserver_SOURCES = simplesocketserver.cpp
simplesocketserver_LDADD = $(top_builddir)/src/liblog4cxx.la


