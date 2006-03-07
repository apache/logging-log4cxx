lib_LTLIBRARIES = liblog4cxx.la

INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)/include


liblog4cxx_la_SOURCES = \
        action.cpp \
        appenderattachableimpl.cpp \
        appenderskeleton.cpp \
        aprinitializer.cpp \
        asyncappender.cpp \
        basicconfigurator.cpp \
        bufferedwriter.cpp \
        bytebuffer.cpp \
        cacheddateformat.cpp \
        charsetdecoder.cpp \
        charsetencoder.cpp \
        class.cpp \
        classnamepatternconverter.cpp \
        classregistration.cpp \
        condition.cpp \
        configurator.cpp \
        consoleappender.cpp \
        cyclicbuffer.cpp \
        dailyrollingfileappender.cpp \
        datagrampacket.cpp \
        datagramsocket.cpp \
        date.cpp \
        dateformat.cpp \
        datelayout.cpp \
        datepatternconverter.cpp \
        defaultcategoryfactory.cpp \
        defaultconfigurator.cpp \
        domconfigurator.cpp \
        exception.cpp \
        fallbackerrorhandler.cpp \
        file.cpp \
        fileappender.cpp \
        filedatepatternconverter.cpp \
        filelocationpatternconverter.cpp \
        fileoutputstream.cpp \
        filerenameaction.cpp \
        filewatchdog.cpp \
        filterbasedtriggeringpolicy.cpp \
        fixedwindowrollingpolicy.cpp \
        formattinginfo.cpp \
        fulllocationpatternconverter.cpp \
        hierarchy.cpp \
        htmllayout.cpp \
        inetaddress.cpp \
        integer.cpp \
        integerpatternconverter.cpp \
        layout.cpp\
        level.cpp \
        levelmatchfilter.cpp \
        levelrangefilter.cpp \
        levelpatternconverter.cpp \
        linelocationpatternconverter.cpp \
        lineseparatorpatternconverter.cpp \
        literalpatternconverter.cpp \
        loggerpatternconverter.cpp \
        loggingeventpatternconverter.cpp \
        loader.cpp\
        locale.cpp\
        locationinfo.cpp\
        logger.cpp \
        loggingevent.cpp \
        loglog.cpp \
        logmanager.cpp \
        logstream.cpp \
        manualtriggeringpolicy.cpp \
        messagepatternconverter.cpp \
        methodlocationpatternconverter.cpp \
        mdc.cpp \
        mutex.cpp \
        nameabbreviator.cpp \
        namepatternconverter.cpp \
        ndcpatternconverter.cpp \
        ndc.cpp \
        nteventlogappender.cpp \
        objectimpl.cpp \
        objectptr.cpp \
        obsoleterollingfileappender.cpp \
        odbcappender.cpp \
        onlyonceerrorhandler.cpp \
        optionconverter.cpp \
        outputdebugstringappender.cpp \
        outputstream.cpp \
        outputstreamwriter.cpp \
        patternconverter.cpp \
        patternlayout.cpp \
        patternparser.cpp \
        pool.cpp \
        properties.cpp \
        propertiespatternconverter.cpp \
        propertyconfigurator.cpp \
        propertyresourcebundle.cpp \
        propertysetter.cpp \
        relativetimedateformat.cpp \
        relativetimepatternconverter.cpp \
        resourcebundle.cpp \
        rollingfileappender.cpp \
        rollingpolicy.cpp \
        rollingpolicybase.cpp \
        rolloverdescription.cpp \
        rootcategory.cpp \
        serversocket.cpp \
        simpledateformat.cpp \
        simplelayout.cpp \
        sizebasedtriggeringpolicy.cpp \
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
        systemerrwriter.cpp \
        systemoutwriter.cpp \
        telnetappender.cpp \
        thread.cpp \
        threadspecificdata.cpp \
        threadpatternconverter.cpp \
        throwableinformationpatternconverter.cpp \
        timezone.cpp \
        timebasedrollingpolicy.cpp \
        transform.cpp \
        triggeringpolicy.cpp \
        transcoder.cpp \
        ttcclayout.cpp \
        unicodehelper.cpp \
        writer.cpp \
        writerappender.cpp \
        xmllayout.cpp\
        xmlsocketappender.cpp

AM_CPPFLAGS = @CPPFLAGS_XML@ @CPPFLAGS_ODBC@
liblog4cxx_la_LDFLAGS = -version-info @LT_VERSION@ @LIBS_XML@ @LIBS_ODBC@ -@APR_LIBS@

