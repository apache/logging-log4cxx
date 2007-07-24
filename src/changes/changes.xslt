<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

-->
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xsl:version="1.0">

   <xsl:output method="xml" indent="yes"/>

   <xsl:apply-templates select="/"/>

   <xsl:template match="/">
  <xsl:comment>

 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

  </xsl:comment>
  <document>
  <properties>
    <title>Apache log4cxx</title>
  </properties>
  <body>
  
    <release version="0.10.0" date="2007-07-30" description="First Apache release">
       <xsl:apply-templates select='/rss/channel/item'>
           <xsl:sort select="substring-after(key, '-')" data-type="number"/>
       </xsl:apply-templates>
     </release>

<release version="0.9.7" date="2004-05-10">
<issue type="fix">Fixed examples source code in the "Short introduction to log4cxx".</issue>
<issue type="fix">Fixed, in the renaming algorithm of RollingFileAppender and
  DailyRollingFileAppender, a problem specific to Unicode.</issue>
<issue type="fix">Fixed conflict with Windows macros "min" and "max", by renaming
  StrictMath::min and StrictMath::max to StrictMath::minimum and
  StrictMath::maximum.</issue>
<issue type="add">Port to HPUX 11.0.</issue>
<issue type="fix">Fixed segmentation fault in PropertyConfigurator.</issue>
<issue type="add">Port to Solaris.</issue>
<issue type="fix">Fixed MutexException thrown while destroying RollingFileAppender.</issue>
<issue type="fix">Logging macros can be used without explicity declaring the use of log4cxx namespace.</issue>
<issue type="fix">Fixed static library unresolved externals for msvc 6 and 7.1</issue>
</release>
<release version="0.9.6" date="2004-04-11">
<issue>Timezone management has been optimized through the class TimeZone</issue>
<issue>Inter-thread synchronization and reference counting has been optimized</issue>
<issue>Reference counting now uses gcc atomic functions (bug 929078)</issue>
<issue>Use of StringBuffer has been optimized.</issue>
<issue>Support of localisation throug resourceBundles</issue>
<issue>SyslogAppender now uses the system function 'syslog' to log on the local host.
 (only for POSIX systems)</issue>
<issue>Added TimeZone configuration to PatternLayout (bug 912563)</issue>
<issue>Support of the DailyRollingFileAppender (feature request 842765)</issue>
</release>
<release version="0.9.5" date="2004-02-04">
<issue>Port of log4j Jnuit tests with Cppunit and Boost Regex.</issue>
<issue>Added explicit exports for MSDEV 6 and MSDEV 7 (no further need of .def files)</issue>
<issue>Custom levels can be configured through the DOMConfigurator and
  PropertyConfigurator classes (Level inherites from Object)</issue>
<issue>Added a reference counter to LoggingEvent to avoid useless copies
  (LoggingEvent inherites from Object)</issue>
<issue>The file log4j.xml as well as the file log4j.properties are now search
  for, in log4cxx initialization.</issue>
<issue>The root logger can be assigned the "OFF" level.</issue>
<issue>Added MSVC6 project missing files mutext.cpp and condition.cpp (bug 847397)</issue>
<issue>condition.cpp now compiles with MSVC6 (bug 847417)</issue>
<issue>fixed pure virtual function call in PropertyConfigurator::configureAndWatch
  (bug 848521)</issue>
<issue>XMLAppender now displays correct timestamp with MSVC 6 (bug 852836)</issue>
<issue>SRLPORT 4.6 support.</issue>
<issue>Fixed an infinite loop in class Properties.</issue>
<issue>Fixed compilations problems with unicode.</issue>
<issue>Fixed SocketAppender bug concerning MDC and NDC.</issue>
</release>
<release version="0.9.4" date="2003-10-25">
<issue>StringBuffer has been optimized.</issue>
<issue>Fixed miscellaneous threading problems.</issue>
<issue>Added TimeZone support in PatternLayout (bug 796894)</issue>
<issue>Fixed threading configuration problems (bug 809125)</issue>
<issue>Fixed miscellaneous MSVC and cygwin compilation problems.</issue>
</release>
<release version="0.9.3" date="2003-09-19">
<issue>Changed tstring to log4cxx::String and tostringstream to
  log4cxx::StringBuffer.
</issue>
<issue>Fixed MSVC 2003 compilation erros and warnings.
</issue>
<issue>Added helpers for NDC and MDC.
</issue>
<issue>Added TimeZone support in TTCCLayout.
</issue>
<issue>Fixed compilation problems with logger macros (LOG4CXX_...)
</issue>
<issue>Fixed milliseconds formatting problem with MSVC 6.0 and 2003
</issue>
<issue>Fixed AsyncAppender crash
</issue>
<issue>Added new tests
</issue>
<issue>Added benchmarks
</issue>
</release>
<release version="0.9.2" date="2003-08-10">
<issue>Fixed FreeBSD compilation problem with pthread mutex (class CriticalSection).
</issue>
<issue>Fixed milliseconds formatting problem (class DateFormat).
</issue>
<issue>Long events (&gt; 1024 chars) are now supported in the class XMLSocketAppender.
</issue>
<issue>Carriage returns have been normalized in the class XMLLayout.
</issue>
</release>
<release version="0.9.1" date="2003-08-06">
<issue>Fixed deadlock problems in classes Logger and AsyncAppender.
</issue>
<issue>Fixed MSVC 6.0 compilation problems.
</issue>
<issue>Added MSVC 6.0 static libraty project.
</issue>
<issue>Default configuration for the SMTP options is "no".
</issue>
</release>
<release version="0.9.0" date="2003-08-06">
<issue>Added ODBCAppender (matching log4j JDBCAppender)
</issue>
<issue>Added SyslogAppender
</issue>
<issue>Added SMTPAppender (only for Linux/FreeBSD)
</issue>
<issue>Added BasicConfigurator
</issue>
<issue>Added a FileWatchDog in PropertyConfigurator and DOMConfigurator
</issue>
<issue>Possibility to load a custom LoggerFactory through the DOMConfigurator
</issue>
<issue>Changed time precision from seconds to milliseconds
</issue>
<issue>Added MSVC 6.0 'Unicode Debug' and 'Unicode Release' targets
</issue>
<issue>Added Java like System class.
</issue>
</release>
<release version="0.1.1" date="2003-07-09">
<issue>Fixed MSVC 6.0 compilation problems concerning the 'Release' target
</issue>
<issue>Added MSVC 6.0 tests projects
</issue>
</release>
<release version="0.1.0" date="2003-07-08">
<issue>FreeBSD Autotools/Compilation support
</issue>
<issue>Fixed TelnetAppender crash when a socket bind exception occured.
</issue>
<issue>Added log4j DTD support to XMLLayout and DOMConfigurator
</issue>
<issue>Can now send events in XML format over TCP (class XMLSocketAppender) for the
  log4j Chainsaw UI
</issue>
<issue>Now compiles with 'configure --enable-unicode' (UTF16 Unicode support)
</issue>
<issue>Added Java like Properties class. It's a helper for the PropertyConfigurator
</issue>
<issue>Added Java like objects with dynamic cast and instanciation. Custom objects
  can be configured through the DOMConfigurator and PropertyConfigurator classes
</issue>
<issue>Port of the PropertyConfigurator class
</issue>
<issue>Port of the "Map Diagnostic Context" (MDC) class
</issue>
<issue>Added 13 tests (try make check)
</issue>
</release>
<release version="0.0.1" date="2003-05-31">
<issue type="add">Loggers, Hierarchy, Filters, Appenders, Layouts, NDC
</issue>
<issue type="add">Appenders:
  AsyncAppender, ConsoleAppender, FileAppender, NTEventLogAppender,
  RollingFileAppender, SocketAppender, SocketHubAappender,
  TelnetAppender
</issue>
<issue type="add">Layouts:
  HTMLLayout, PatternLayout, SimpleLayout, TTCCLayout, XMLLayout
</issue>
<issue type="add">Filters:
  DenyAllFilter, LevelMatchFilter, LevelRangeFilter, StringMatchFilter

</issue>
<issue type="add">Configurators:
  DOMConfigurator
</issue>
</release>
  </body>
</document>
</xsl:template>

<xsl:template match="item">
      <action issue="{key}"><xsl:value-of select="summary"/></action>
</xsl:template>

</xsl:transform>
