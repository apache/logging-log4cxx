SUBDIRS = customlogger defaultinit helpers util xml

EXTRA_DIST = *.cpp
noinst_HEADERS= *.h

if TESTS

INCLUDES = -I$(top_srcdir)/include
noinst_PROGRAMS = testsuite
testsuite_SOURCES = \
	asyncappendertestcase.cpp\
	hierarchythresholdtestcase.cpp\
	loggertestcase.cpp\
	main.cpp\
	minimumtestcase.cpp\
	patternlayouttest.cpp\
	vectorappender.cpp
	

testsuite_LDADD = \
	$(top_builddir)/src/liblog4cxx.la
	
testsuite_LDFLAGS = \
	-Wl,--whole-archive,customlogger/libcustomlogger.a,--no-whole-archive\
	-Wl,--whole-archive,defaultinit/libdefaultinit.a,--no-whole-archive\
	-Wl,--whole-archive,helpers/libhelpers.a,--no-whole-archive\
	-Wl,--whole-archive,util/libutil.a,--no-whole-archive\
	-Wl,--whole-archive,xml/libxml.a,--no-whole-archive\
	-lcppunit -ldl -lboost_regex
	
testsuite_DEPENDENCIES = \
	customlogger/libcustomlogger.a\
	defaultinit/libdefaultinit.a\
	helpers/libhelpers.a\
	util/libutil.a\
	xml/libxml.a\
	$(top_builddir)/src/liblog4cxx.la

check: testsuite
endif
