lib_LTLIBRARIES = liblog4cxx.la

INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)/include

liblog4cxx_la_SOURCES = \
        appenderattachableimpl.cpp \
        appenderskeleton.cpp \
        aprinitializer.cpp \
        asyncappender.cpp \
        basicconfigurator.cpp \
        cacheddateformat.cpp \
        class.cpp \
        condition.cpp \
        configurator.cpp \
        consoleappender.cpp \
        cyclicbuffer.cpp \
        datagrampacket.cpp \
        datagramsocket.cpp \
        datelayout.cpp \
        dateformat.cpp \
        defaultcategoryfactory.cpp \
        domconfigurator.cpp \
        exception.cpp \
        fallbackerrorhandler.cpp \
        file.cpp \
        fileappender.cpp \
        filewatchdog.cpp \
        formattinginfo.cpp \
        gnomexml.cpp \
        hierarchy.cpp \
        htmllayout.cpp \
        inetaddress.cpp \
        layout.cpp\
        level.cpp \
        levelmatchfilter.cpp \
        levelrangefilter.cpp \
        loader.cpp\
        locale.cpp\
        locationinfo.cpp\
        logger.cpp \
        loggingevent.cpp \
        loglog.cpp \
        logmanager.cpp \
        mdc.cpp \
        msxml.cpp \
        mutex.cpp \
        ndc.cpp \
        nteventlogappender.cpp \
        objectimpl.cpp \
        objectptr.cpp \
        odbcappender.cpp \
        onlyonceerrorhandler.cpp \
        optionconverter.cpp \
        patternconverter.cpp \
        patternlayout.cpp \
        patternparser.cpp \
        pool.cpp \
        properties.cpp \
        propertyconfigurator.cpp \
        propertyresourcebundle.cpp \
        propertysetter.cpp \
        relativetimedateformat.cpp \
        resourcebundle.cpp \
        rollingfileappender.cpp \
        rootcategory.cpp \
        serversocket.cpp \
        simpledateformat.cpp \
        simplelayout.cpp \
        smtpappender.cpp \
        socket.cpp \
        socketappender.cpp \
        socketappenderskeleton.cpp \
        sockethubappender.cpp \
        socketimpl.cpp \
        socketinputstream.cpp \
        socketnode.cpp \
        socketoutputstream.cpp \
        strftimedateformat.cpp \
        stringhelper.cpp \
        stringmatchfilter.cpp \
        stringtokenizer.cpp \
        synchronized.cpp \
        syslogappender.cpp \
        syslogwriter.cpp \
        system.cpp \
        telnetappender.cpp \
        timezone.cpp \
        transform.cpp \
        thread.cpp \
        threadspecificdata.cpp \
        transcoder.cpp \
        ttcclayout.cpp \
        writerappender.cpp \
        xmllayout.cpp\
        xmlsocketappender.cpp

AM_CPPFLAGS = @CPPFLAGS_XML@ @CPPFLAGS_ODBC@
liblog4cxx_la_LDFLAGS = -version-info @LT_VERSION@ @LIBS_XML@ @LIBS_ODBC@ -@APR_LIBS@

