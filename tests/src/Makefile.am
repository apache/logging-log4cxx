SUBDIRS = customlogger defaultinit helpers net pattern rolling util varia db xml nt

EXTRA_DIST = $(top_srcdir)/tests/src/*.cpp
noinst_HEADERS= $(top_srcdir)/tests/src/*.h

if TESTS

INCLUDES = -I$(top_srcdir)/include
noinst_PROGRAMS = testsuite shortsocketserver

testsuite_SOURCES = \
        asyncappendertestcase.cpp\
        filetestcase.cpp \
        hierarchythresholdtestcase.cpp\
        l7dtestcase.cpp\
        leveltestcase.cpp \
        loggertestcase.cpp\
        main.cpp\
        minimumtestcase.cpp\
        patternlayouttest.cpp\
        vectorappender.cpp\
        appenderskeletontestcase.cpp\
        consoleappendertestcase.cpp\
        fileappendertestcase.cpp\
        rollingfileappendertestcase.cpp\
        writerappendertestcase.cpp


testsuite_LDADD = \
        $(top_builddir)/src/liblog4cxx.la

testsuite_LDFLAGS = \
        -Wl,--whole-archive,customlogger/libcustomlogger.a,--no-whole-archive\
        -Wl,--whole-archive,defaultinit/libdefaultinit.a,--no-whole-archive\
        -Wl,--whole-archive,helpers/libhelpers.a,--no-whole-archive\
        -Wl,--whole-archive,net/libnet.a,--no-whole-archive\
        -Wl,--whole-archive,pattern/libpattern.a,--no-whole-archive\
        -Wl,--whole-archive,util/libutil.a,--no-whole-archive\
        -Wl,--whole-archive,varia/libvaria.a,--no-whole-archive\
        -Wl,--whole-archive,xml/libxml.a,--no-whole-archive\
        -Wl,--whole-archive,db/libdb.a,--no-whole-archive\
        -Wl,--whole-archive,nt/libnt.a,--no-whole-archive\
        @LIBS_CPPUNIT@ -lboost_regex

AM_CPPFLAGS = @CPPFLAGS_CPPUNIT@

testsuite_DEPENDENCIES = \
        customlogger/libcustomlogger.a\
        defaultinit/libdefaultinit.a\
        helpers/libhelpers.a\
        net/libnet.a\
        pattern/libpattern.a\
        util/libutil.a\
        varia/libvaria.a\
        xml/libxml.a\
        db/libdb.a\
        nt/libnt.a\
        $(top_builddir)/src/liblog4cxx.la

shortsocketserver_SOURCES = \
        shortsocketserver.cpp

shortsocketserver_LDADD = \
        $(top_builddir)/src/liblog4cxx.la

shortsocketserver_LDFLAGS = \
        -Wl,--whole-archive,util/libutil.a,--no-whole-archive\
        -Wl,--whole-archive,xml/libxml.a,--no-whole-archive\
        @LIBS_CPPUNIT@ -lboost_regex

shortsocketserver_DEPENDENCIES = \
        util/libutil.a\
        xml/libxml.a\
        $(top_builddir)/src/liblog4cxx.la

check: testsuite shortsocketserver
endif
