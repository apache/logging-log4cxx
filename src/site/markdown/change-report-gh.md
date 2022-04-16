Changelog {#changelog}
===
<!--
 Note: License header cannot be first, as doxygen does not generate
 cleanly if it before the '==='
-->
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

# Release History

| Version                                                                                | Date       | Description          |
| -------------------------------------------------------------------------------------- | ---------- | -------------------- |
| [0.13.0](#0.13.0) | 2022-04-15 | Maintenance release  |
| [0.12.1](#0.12.1) | 2021-09-21 | Bugfix for 0.12.0 |
| [0.12.0](#0.12.0) | 2021-05-01 | First release to require C++11. Updates for smart pointers.  Standardization on CMake for building. |
| [0.11.0](#0.11.0) | 2020-08-09 | Maintenance release. |
| [0.10.0](#0.10.0) | 2008-04-03 | First Apache release |
| [0.9.7](#0.9.7)   | 2004-05-10 |                      |
| [0.9.6](#0.9.6)   | 2004-04-11 |                      |
| [0.9.5](#0.9.5)   | 2004-02-04 |                      |
| [0.9.4](#0.9.4)   | 2003-10-25 |                      |
| [0.9.3](#0.9.3)   | 2003-09-19 |                      |
| [0.9.2](#0.9.2)   | 2003-08-10 |                      |
| [0.9.1](#0.9.1)   | 2003-08-06 |                      |
| [0.9.0](#0.9.0)   | 2003-08-06 |                      |
| [0.1.1](#0.1.1)   | 2003-07-09 |                      |
| [0.1.0](#0.1.0)   | 2003-07-08 |                      |
| [0.0.1](#0.0.1)   | 2003-05-31 |                      |

<a name="0.13.0"/>
## Release 0.13.1 - 2022-04-15

This release fixes a number of issues.  Notable new features include the
ability to block signals from threads that the library creates, automatic
creation of log directories, new color patterns, and the ability to determine
the library version at compile and run-time.

Bug
---

-   \[[LOGCXX-102](https://issues.apache.org/jira/browse/LOGCXX-102)\] -
    PropertyConfigurator does not process the RollingFileAppender
    options
-   \[[LOGCXX-387](https://issues.apache.org/jira/browse/LOGCXX-387)\] -
    SocketAppenderSkeleton re-connects only once
-   \[[LOGCXX-431](https://issues.apache.org/jira/browse/LOGCXX-431)\] -
    When log4cxx creates a thread, it doesn\'t block signals it\'s not
    using, leading to unreliable signal delivery for the calling
    process.
-   \[[LOGCXX-519](https://issues.apache.org/jira/browse/LOGCXX-519)\] -
    Version11 - \"INSTALL.TXT\" and \"vstudio.apt\" miss explenation for
    generating the log4cxx.dll
-   \[[LOGCXX-525](https://issues.apache.org/jira/browse/LOGCXX-525)\] -
    Compressing log files does not create directories
-   \[[LOGCXX-536](https://issues.apache.org/jira/browse/LOGCXX-536)\] -
    CMakeLists.txt install pgkconfig and cmake modue to wrong place
-   \[[LOGCXX-537](https://issues.apache.org/jira/browse/LOGCXX-537)\] -
    double mutex lock
-   \[[LOGCXX-540](https://issues.apache.org/jira/browse/LOGCXX-540)\] -
    propertiestestcase.properties contains CRLF, does not well play with
    git
-   \[[LOGCXX-543](https://issues.apache.org/jira/browse/LOGCXX-543)\] -
    Some tests can fail when there is a \"Q\" in the pathname
-   \[[LOGCXX-546](https://issues.apache.org/jira/browse/LOGCXX-546)\] -
    Multi threaded applications run at single threaded speed

New Feature
-----------

-   \[[LOGCXX-529](https://issues.apache.org/jira/browse/LOGCXX-529)\] -
    Support color and highlight conversion patterns

Improvement
-----------

-   \[[LOGCXX-337](https://issues.apache.org/jira/browse/LOGCXX-337)\] -
    Suggested fix for socketappender not reconnecting multiple times
-   \[[LOGCXX-538](https://issues.apache.org/jira/browse/LOGCXX-538)\] -
    Tests cannot be run in parallel
-   \[[LOGCXX-539](https://issues.apache.org/jira/browse/LOGCXX-539)\] -
    Allow distribustion log4j to be used for socketservertest
-   \[[LOGCXX-547](https://issues.apache.org/jira/browse/LOGCXX-547)\] -
    Allow for hiding of location data
-   \[[LOGCXX-548](https://issues.apache.org/jira/browse/LOGCXX-548)\] -
    Doxygen documentation is not reproducible
-   \[[LOGCXX-550](https://issues.apache.org/jira/browse/LOGCXX-550)\] -
    Add ability to get thread name not just ID

Wish
----

-   \[[LOGCXX-544](https://issues.apache.org/jira/browse/LOGCXX-544)\] -
    Please embedd library version in a header
-   \[[LOGCXX-551](https://issues.apache.org/jira/browse/LOGCXX-551)\] -
    CMake documented build option for Boost vs C++17 Implementation for
    shared\_mutex


<a name="0.12.0"/>
## Release 0.12.1 - 2021-09-21

This is a minor bugfix release to fix issues found with 0.12.0.  Notably, this version fixes a bug
where a multithreaded application would crash when using a rolling file.

Bug
---

-   \[[LOGCXX-534](https://issues.apache.org/jira/browse/LOGCXX-534)\] -
    Crashed in log->forcedLog function when running with multi-thread
-   \[[LOGCXX-528](https://issues.apache.org/jira/browse/LOGCXX-528)\] -
    log4cxx fails to build on Centos 7.6 / g++ 4.8.5 / Boost 1.53


<a name="0.12.0"/>
## Release 0.12.0 - 2021-05-01

This is the first release to require a minimum version of C++11.  This means that all objects in log4cxx
are now created using `std::shared_ptr` as the smart pointer implementation.

Alternative build systems have been removed, and we now support CMake only for building the library.

With the introduction of smart pointers, the old behavior of implicit casting no longer works.  In
order to cast between classes, use the new [log4cxx::cast](@ref log4cxx.cast) method.  This method returns an invalid
`shared_ptr` on failure, or a `shared_ptr` pointing at the same object on success.  This should be
transparent to user code, unless you are interacting with log4cxx internals directly.

Before:

```{.cpp}
ObjectPtr instance = Loader::loadClass(className).newInstance();
AppenderPtr appender = instance;
```

After:

```{.cpp}
ObjectPtr instance = ObjectPtr(Loader::loadClass(className).newInstance());
AppenderPtr appender = log4cxx::cast<Appender>(instance);
// At this point(assuming the cast was good), instance and appender
// both point at the same object.
```

Bug
---

-   \[[LOGCXX-322](https://issues.apache.org/jira/browse/LOGCXX-322)\] -
    Crashes on exit from multithreaded program using log4cxx
-   \[[LOGCXX-485](https://issues.apache.org/jira/browse/LOGCXX-485)\] -
    Levels leak memory
-   \[[LOGCXX-486](https://issues.apache.org/jira/browse/LOGCXX-486)\] -
    Replace ObjectPtr with more standard shared\_ptr.
-   \[[LOGCXX-507](https://issues.apache.org/jira/browse/LOGCXX-507)\] -
    Data race on LevelPtr when using the async appender
-   \[[LOGCXX-508](https://issues.apache.org/jira/browse/LOGCXX-508)\] -
    sync
-   \[[LOGCXX-510](https://issues.apache.org/jira/browse/LOGCXX-510)\] -
    Build problems using CMAKE and Visual Studio 2019 Community
-   \[[LOGCXX-517](https://issues.apache.org/jira/browse/LOGCXX-517)\] -
    Circular reference in ErrorHandlerTestCase
-   \[[LOGCXX-521](https://issues.apache.org/jira/browse/LOGCXX-521)\] -
    Can\'t link cleanly with ODBC
-   \[[LOGCXX-526](https://issues.apache.org/jira/browse/LOGCXX-526)\] -
    GCC-11.1.0 Support

New Feature
-----------

-   \[[LOGCXX-515](https://issues.apache.org/jira/browse/LOGCXX-515)\] -
    Add macros to utilize libfmt formatting for messages

Improvement
-----------

-   \[[LOGCXX-523](https://issues.apache.org/jira/browse/LOGCXX-523)\] -
    Add in error handling for rollover errors

<a name="0.11.0"/>
### Release 0.11.0 - 2020-08-09

|                                                                     |                                                                                                                                                                                                                                                 |    |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -- |
| Type                                                                | Changes                                                                                                                                                                                                                                         | By |
| ![](images/fix.gif "fix")    | cmake and autotools generate different versioned binaries Fixes [LOGCXX-512](https://issues.apache.org/jira/browse/LOGCXX-512).                                                                                                                 |    |
| ![](images/fix.gif "fix")    | CachedDateFormat reuses timestamps without updating milliseconds after formatting timestamp with ms == 654 Fixes [LOGCXX-506](https://issues.apache.org/jira/browse/LOGCXX-506).                                                                |    |
| ![](images/update.gif "update") | Checksums/Signatures don't match for log4cxx binaries Fixes [LOGCXX-503](https://issues.apache.org/jira/browse/LOGCXX-503).                                                                                                                     |    |
| ![](images/update.gif "update") | appenderattachable.h function doc formatted "incorrectly" Fixes [LOGCXX-502](https://issues.apache.org/jira/browse/LOGCXX-502).                                                                                                                 |    |
| ![](images/update.gif "update") | Logging in Timing-Critical Applications Fixes [LOGCXX-500](https://issues.apache.org/jira/browse/LOGCXX-500).                                                                                                                                   |    |
| ![](images/fix.gif "fix")    | Provide a windows build environment for the project by replacing the ant build with a CMake build Fixes [LOGCXX-494](https://issues.apache.org/jira/browse/LOGCXX-494).                                                                         |    |
| ![](images/fix.gif "fix")    | Wrong usage of milli- vs. micro- and non- vs. milliseconds in some docs. Fixes [LOGCXX-493](https://issues.apache.org/jira/browse/LOGCXX-493).                                                                                                  |    |
| ![](images/fix.gif "fix")    | conditional expression is constant Fixes [LOGCXX-490](https://issues.apache.org/jira/browse/LOGCXX-490).                                                                                                                                        |    |
| ![](images/fix.gif "fix")    | Space after log level hides messages Fixes [LOGCXX-488](https://issues.apache.org/jira/browse/LOGCXX-488).                                                                                                                                      |    |
| ![](images/fix.gif "fix")    | Spelling error s/excute/execute Fixes [LOGCXX-484](https://issues.apache.org/jira/browse/LOGCXX-484).                                                                                                                                           |    |
| ![](images/update.gif "update") | Not able to see hebrew values when logging in log4cxx Fixes [LOGCXX-483](https://issues.apache.org/jira/browse/LOGCXX-483).                                                                                                                     |    |
| ![](images/fix.gif "fix")    | Build failure with GCC-6 Fixes [LOGCXX-482](https://issues.apache.org/jira/browse/LOGCXX-482).                                                                                                                                                  |    |
| ![](images/fix.gif "fix")    | TimeBasedRollingPolicy should append as configured on rollover Fixes [LOGCXX-464](https://issues.apache.org/jira/browse/LOGCXX-464).                                                                                                            |    |
| ![](images/fix.gif "fix")    | LogLog::setQuietMode(true) does not suppress exception reporting Fixes [LOGCXX-455](https://issues.apache.org/jira/browse/LOGCXX-455).                                                                                                          |    |
| ![](images/fix.gif "fix")    | make install fails, trying to overwrite header files Fixes [LOGCXX-446](https://issues.apache.org/jira/browse/LOGCXX-446).                                                                                                                      |    |
| ![](images/fix.gif "fix")    | Return by const reference in Logger::getName() Fixes [LOGCXX-443](https://issues.apache.org/jira/browse/LOGCXX-443).                                                                                                                            |    |
| ![](images/fix.gif "fix")    | Autoconf 2.69 needs 'ACLOCAL\_AMFLAGS= -I .' Fixes [LOGCXX-433](https://issues.apache.org/jira/browse/LOGCXX-433).                                                                                                                              |    |
| ![](images/fix.gif "fix")    | Wildcards in Makefile.am break either VPATH or non-VPATH installs Fixes [LOGCXX-428](https://issues.apache.org/jira/browse/LOGCXX-428).                                                                                                         |    |
| ![](images/fix.gif "fix")    | exceptions in CachedDateFormatTestCase after LOGCXX-420 Fixes [LOGCXX-425](https://issues.apache.org/jira/browse/LOGCXX-425).                                                                                                                   |    |
| ![](images/fix.gif "fix")    | liblog4cxx.pc.in should reflect dependency on apr-1, apr-1-util Fixes [LOGCXX-424](https://issues.apache.org/jira/browse/LOGCXX-424).                                                                                                           |    |
| ![](images/fix.gif "fix")    | Repair autogen script warnings Fixes [LOGCXX-423](https://issues.apache.org/jira/browse/LOGCXX-423).                                                                                                                                            |    |
| ![](images/fix.gif "fix")    | Regression of LOGCXX-420 Fixes [LOGCXX-422](https://issues.apache.org/jira/browse/LOGCXX-422).                                                                                                                                                  |    |
| ![](images/fix.gif "fix")    | Possible out\_of\_range exception for millisecond formats in CachedDateFormat Fixes [LOGCXX-420](https://issues.apache.org/jira/browse/LOGCXX-420).                                                                                             |    |
| ![](images/fix.gif "fix")    | atoi undefined on Mac OS 10.9 compiling stringhelper.cpp Fixes [LOGCXX-417](https://issues.apache.org/jira/browse/LOGCXX-417).                                                                                                                  |    |
| ![](images/fix.gif "fix")    | Configure and watch could crash on app exit with static linking Fixes [LOGCXX-416](https://issues.apache.org/jira/browse/LOGCXX-416).                                                                                                           |    |
| ![](images/fix.gif "fix")    | Empty XML configuration file causes crash Fixes [LOGCXX-415](https://issues.apache.org/jira/browse/LOGCXX-415).                                                                                                                                 |    |
| ![](images/fix.gif "fix")    | possibly wrong use of autotools docdir (due to Alex Zbarcea) Fixes [LOGCXX-414](https://issues.apache.org/jira/browse/LOGCXX-414).                                                                                                              |    |
| ![](images/fix.gif "fix")    | log4cxx doesn't compile on openembedded (due to Alex Zbarcea) Fixes [LOGCXX-413](https://issues.apache.org/jira/browse/LOGCXX-413).                                                                                                             |    |
| ![](images/fix.gif "fix")    | Log4cxx doesn't roll normally when working under multiple processes environment Fixes [LOGCXX-412](https://issues.apache.org/jira/browse/LOGCXX-412).                                                                                           |    |
| ![](images/fix.gif "fix")    | Crash when logging on multiple threads. Fixes [LOGCXX-411](https://issues.apache.org/jira/browse/LOGCXX-411).                                                                                                                                   |    |
| ![](images/fix.gif "fix")    | C++11 does not allow char literals with highest bit set unless cast Fixes [LOGCXX-400](https://issues.apache.org/jira/browse/LOGCXX-400).                                                                                                       |    |
| ![](images/fix.gif "fix")    | Non-ascii character output wrong. Fixes [LOGCXX-399](https://issues.apache.org/jira/browse/LOGCXX-399).                                                                                                                                         |    |
| ![](images/fix.gif "fix")    | Infinite loop in Transcoder::encode(const LogString& src, std::wstring& dst) Fixes [LOGCXX-398](https://issues.apache.org/jira/browse/LOGCXX-398).                                                                                              |    |
| ![](images/fix.gif "fix")    | Levels are not thread safe Fixes [LOGCXX-394](https://issues.apache.org/jira/browse/LOGCXX-394).                                                                                                                                                |    |
| ![](images/fix.gif "fix")    | Hierarchy::updateParents loops forever on illegal logger-name like '.logger1' Fixes [LOGCXX-388](https://issues.apache.org/jira/browse/LOGCXX-388).                                                                                             |    |
| ![](images/fix.gif "fix")    | Mingw build type conversion error Fixes [LOGCXX-382](https://issues.apache.org/jira/browse/LOGCXX-382).                                                                                                                                         |    |
| ![](images/fix.gif "fix")    | Pkgconfig can't find dependencies properly if log4cxx built statically Fixes [LOGCXX-381](https://issues.apache.org/jira/browse/LOGCXX-381).                                                                                                    |    |
| ![](images/fix.gif "fix")    | Load Properties File Fails When There Are multibyte Characters in the Path Fixes [LOGCXX-369](https://issues.apache.org/jira/browse/LOGCXX-369).                                                                                                |    |
| ![](images/fix.gif "fix")    | method and class name functions not properly implemented Fixes [LOGCXX-368](https://issues.apache.org/jira/browse/LOGCXX-368).                                                                                                                  |    |
| ![](images/fix.gif "fix")    | Build fails on Linux with g++ 4.4 Fixes [LOGCXX-367](https://issues.apache.org/jira/browse/LOGCXX-367).                                                                                                                                         |    |
| ![](images/fix.gif "fix")    | Errors when compile log4cxx 0.10.0 under Win7 x64 with Visual Studio 2010 (due to Christian Boos and Feng Nan) Fixes [LOGCXX-366](https://issues.apache.org/jira/browse/LOGCXX-366).                                                            |    |
| ![](images/fix.gif "fix")    | Unit tests fail on system dates later than 2009-12-31. Fixes [LOGCXX-365](https://issues.apache.org/jira/browse/LOGCXX-365).                                                                                                                    |    |
| ![](images/fix.gif "fix")    | SMTPAppender generating Emails with an empty body Fixes [LOGCXX-358](https://issues.apache.org/jira/browse/LOGCXX-358).                                                                                                                         |    |
| ![](images/fix.gif "fix")    | apache-log4cxx-0.10.0\\src\\main\\include\\log4cxx\\spi\\configurator.h(57) : warning C4231: nonstandard extension used : 'extern' before template explicit instantiation Fixes [LOGCXX-356](https://issues.apache.org/jira/browse/LOGCXX-356). |    |
| ![](images/fix.gif "fix")    | When a client disconnects the SocketHubAppender crashes on the next log message Fixes [LOGCXX-353](https://issues.apache.org/jira/browse/LOGCXX-353).                                                                                           |    |
| ![](images/fix.gif "fix")    | Download page does not have link to KEYS file Fixes [LOGCXX-351](https://issues.apache.org/jira/browse/LOGCXX-351).                                                                                                                             |    |
| ![](images/fix.gif "fix")    | Transcoder::encodeCharsetName bungles encoding Fixes [LOGCXX-340](https://issues.apache.org/jira/browse/LOGCXX-340).                                                                                                                            |    |
| ![](images/update.gif "update") | Child thread does not inherit a copy of the mapped diagnostic context of its parent Fixes [LOGCXX-339](https://issues.apache.org/jira/browse/LOGCXX-339).                                                                                       |    |
| ![](images/fix.gif "fix")    | Suggested fix for socketappender not reconnecting multiple times Fixes [LOGCXX-337](https://issues.apache.org/jira/browse/LOGCXX-337).                                                                                                          |    |
| ![](images/fix.gif "fix")    | Test compilation fails: Overloading ambiguity Fixes [LOGCXX-336](https://issues.apache.org/jira/browse/LOGCXX-336).                                                                                                                             |    |
| ![](images/fix.gif "fix")    | DailyRollingFileAppender should roll if program doesn't run at rolling time Fixes [LOGCXX-331](https://issues.apache.org/jira/browse/LOGCXX-331).                                                                                               |    |
| ![](images/fix.gif "fix")    | TLS memory of APR is not freed in destructor of APRInitializer Fixes [LOGCXX-320](https://issues.apache.org/jira/browse/LOGCXX-320).                                                                                                            |    |
| ![](images/fix.gif "fix")    | Please make sure that the LOG4CXX\_\* macro's can be used as ordinary statements. Fixes [LOGCXX-319](https://issues.apache.org/jira/browse/LOGCXX-319).                                                                                         |    |
| ![](images/fix.gif "fix")    | Log4cxx triggers locking inversion which can result in a deadlock. Fixes [LOGCXX-317](https://issues.apache.org/jira/browse/LOGCXX-317).                                                                                                        |    |
| ![](images/fix.gif "fix")    | Build process fails in case of absence of iconv support in apr-util Fixes [LOGCXX-313](https://issues.apache.org/jira/browse/LOGCXX-313).                                                                                                       |    |
| ![](images/fix.gif "fix")    | Property/DOMConfigurator::configureAndWatch can continue to run after APR termination Fixes [LOGCXX-305](https://issues.apache.org/jira/browse/LOGCXX-305).                                                                                     |    |
| ![](images/fix.gif "fix")    | BasicConfigurator::configure results in writer not set warning. Fixes [LOGCXX-304](https://issues.apache.org/jira/browse/LOGCXX-304).                                                                                                           |    |
| ![](images/fix.gif "fix")    | DOMConfigurator does not set ErrorHandler. Fixes [LOGCXX-303](https://issues.apache.org/jira/browse/LOGCXX-303).                                                                                                                                |    |
| ![](images/fix.gif "fix")    | ODBCAppender connection settings broken (or just have changed). Fixes [LOGCXX-300](https://issues.apache.org/jira/browse/LOGCXX-300).                                                                                                           |    |
| ![](images/fix.gif "fix")    | odbcappender.cpp does not compile with unixODBC on linux. Fixes [LOGCXX-299](https://issues.apache.org/jira/browse/LOGCXX-299).                                                                                                                 |    |
| ![](images/fix.gif "fix")    | SMTPAppender does not build properly with autotools. Fixes [LOGCXX-298](https://issues.apache.org/jira/browse/LOGCXX-298).                                                                                                                      |    |
| ![](images/fix.gif "fix")    | Escape sequences not recognized in property files. Fixes [LOGCXX-293](https://issues.apache.org/jira/browse/LOGCXX-293).                                                                                                                        |    |
| ![](images/fix.gif "fix")    | Value continuation does not properly handle CRLF in property files. Fixes [LOGCXX-292](https://issues.apache.org/jira/browse/LOGCXX-292).                                                                                                       |    |
| ![](images/fix.gif "fix")    | Tab characters are not recognized in property files. Fixes [LOGCXX-291](https://issues.apache.org/jira/browse/LOGCXX-291).                                                                                                                      |    |
| ![](images/fix.gif "fix")    | Unnecessary trailing semi-colons after LOG4CXX\_INFO et al in docs, examples and tests. Fixes [LOGCXX-288](https://issues.apache.org/jira/browse/LOGCXX-288).                                                                                   |    |
| ![](images/fix.gif "fix")    | gcc 4.3 requires \#include \<cstring\> when using memcpy and related. Fixes [LOGCXX-286](https://issues.apache.org/jira/browse/LOGCXX-286).                                                                                                     |    |
| ![](images/fix.gif "fix")    | LevelRangeFilter has default value for acceptOnMatch that is different from log4j Fixes [LOGCXX-285](https://issues.apache.org/jira/browse/LOGCXX-285).                                                                                         |    |
| ![](images/fix.gif "fix")    | Unit tests fail to compile with xlc\_r on AIX Fixes [LOGCXX-284](https://issues.apache.org/jira/browse/LOGCXX-284).                                                                                                                             |    |
| ![](images/fix.gif "fix")    | Suspicious, but harmless, reuse of LOCAL1 in SyslogAppender Fixes [LOGCXX-283](https://issues.apache.org/jira/browse/LOGCXX-283).                                                                                                               |    |
| ![](images/fix.gif "fix")    | Thread::sleep not affected by Thread::interrupt. Fixes [LOGCXX-282](https://issues.apache.org/jira/browse/LOGCXX-282).                                                                                                                          |    |
| ![](images/fix.gif "fix")    | Sun Studio 11 reports function hides base virtual function warning Fixes [LOGCXX-281](https://issues.apache.org/jira/browse/LOGCXX-281).                                                                                                        |    |
| ![](images/fix.gif "fix")    | tests and sample code unnecessarily compiled during default make target Fixes [LOGCXX-280](https://issues.apache.org/jira/browse/LOGCXX-280).                                                                                                   |    |
| ![](images/fix.gif "fix")    | Threads for reconnecting sockets do not end cleanly when program exits Fixes [LOGCXX-278](https://issues.apache.org/jira/browse/LOGCXX-278).                                                                                                    |    |
| ![](images/fix.gif "fix")    | Reconnection not working for sockets Fixes [LOGCXX-277](https://issues.apache.org/jira/browse/LOGCXX-277).                                                                                                                                      |    |
| ![](images/fix.gif "fix")    | AndFilter and others defined but not implemented Fixes [LOGCXX-276](https://issues.apache.org/jira/browse/LOGCXX-276).                                                                                                                          |    |
| ![](images/fix.gif "fix")    | Headers cannot be included with very strict warning settings Fixes [LOGCXX-275](https://issues.apache.org/jira/browse/LOGCXX-275).                                                                                                              |    |
| ![](images/fix.gif "fix")    | Prevent filenamepatterntestcase from failing in some timezones Fixes [LOGCXX-273](https://issues.apache.org/jira/browse/LOGCXX-273).                                                                                                            |    |
| ![](images/update.gif "update") | Apache log4cxx 0.11.0 release Fixes [LOGCXX-272](https://issues.apache.org/jira/browse/LOGCXX-272).                                                                                                                                             |    |
| ![](images/fix.gif "fix")    | MDC::put will not overwrite existing key value pair Fixes [LOGCXX-271](https://issues.apache.org/jira/browse/LOGCXX-271).                                                                                                                       |    |
| ![](images/fix.gif "fix")    | Add ability to compile out logging by logging level. Fixes [LOGCXX-270](https://issues.apache.org/jira/browse/LOGCXX-270).                                                                                                                      |    |
| ![](images/fix.gif "fix")    | Local variables hide member variables Fixes [LOGCXX-267](https://issues.apache.org/jira/browse/LOGCXX-267).                                                                                                                                     |    |
| ![](images/fix.gif "fix")    | Eliminate Extra ";" ignored warnings Fixes [LOGCXX-266](https://issues.apache.org/jira/browse/LOGCXX-266).                                                                                                                                      |    |
| ![](images/fix.gif "fix")    | Eliminate anachronism warnings Fixes [LOGCXX-265](https://issues.apache.org/jira/browse/LOGCXX-265).                                                                                                                                            |    |
| ![](images/fix.gif "fix")    | Bad link to log4cxx-dev archive Fixes [LOGCXX-263](https://issues.apache.org/jira/browse/LOGCXX-263).                                                                                                                                           |    |
| ![](images/fix.gif "fix")    | socketappendertestcase and xmlsocketappendertestcase not run Fixes [LOGCXX-262](https://issues.apache.org/jira/browse/LOGCXX-262).                                                                                                              |    |
| ![](images/fix.gif "fix")    | Console appender crashes if layout is not set Fixes [LOGCXX-249](https://issues.apache.org/jira/browse/LOGCXX-249).                                                                                                                             |    |
| ![](images/add.gif "add")    | Set SONAME in cmake like autotools based buildsystem would do. Fixes [32](https://github.com/apache/logging-log4cxx/pull/32).                                                                                                                   |    |
| ![](images/add.gif "add")    | Implementation of map-based filter. Fixes [24](https://github.com/apache/logging-log4cxx/pull/24).                                                                                                                                              |    |
| ![](images/add.gif "add")    | Added support for building log4cxx as a statically linked library on Windows. Fixes [21](https://github.com/apache/logging-log4cxx/pull/21).                                                                                                    |    |
| ![](images/add.gif "add")    | Replaced ant build with cmake. Fixes [14](https://github.com/apache/logging-log4cxx/pull/14).                                                                                                                                                   |    |
| ![](images/add.gif "add")    | JSONLayout Fixes [13](https://github.com/apache/logging-log4cxx/pull/13).                                                                                                                                                                       |    |
| ![](images/update.gif "update") | Behavior of StringHelper::startsWith and endsWith synced.                                                                                                                                                                                       |    |
| ![](images/update.gif "update") | Documented C (class) and M (method) log format keywords.                                                                                                                                                                                        |    |
| ![](images/add.gif "add")    | LocationInfo for Borland C++ Builder and successors improved.                                                                                                                                                                                   |    |

<a name="0.10.0"/>
### Release 0.10.0 - 2008-04-03

|                                                                     |                                                                                                                                                                                                |    |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -- |
| Type                                                                | Changes                                                                                                                                                                                        | By |
| ![](images/fix.gif "fix")    | Several appenders fail to compile in Visual Studio 2008 Fixes [LOGCXX-259](https://issues.apache.org/jira/browse/LOGCXX-259).                                                                  |    |
| ![](images/fix.gif "fix")    | unable to build from make dist package due to missing doxygen file Fixes [LOGCXX-258](https://issues.apache.org/jira/browse/LOGCXX-258).                                                       |    |
| ![](images/fix.gif "fix")    | ServerSocket::accept hangs on Unix Fixes [LOGCXX-257](https://issues.apache.org/jira/browse/LOGCXX-257).                                                                                       |    |
| ![](images/fix.gif "fix")    | SocketHubAppender fails after accepting connection Fixes [LOGCXX-256](https://issues.apache.org/jira/browse/LOGCXX-256).                                                                       |    |
| ![](images/add.gif "add")    | Add build option for static C RTL Fixes [LOGCXX-254](https://issues.apache.org/jira/browse/LOGCXX-254).                                                                                        |    |
| ![](images/fix.gif "fix")    | Transcoder compilation error with utf-8 charset Fixes [LOGCXX-253](https://issues.apache.org/jira/browse/LOGCXX-253).                                                                          |    |
| ![](images/add.gif "add")    | Add documentation for use of operator\<\< in logging requests Fixes [LOGCXX-252](https://issues.apache.org/jira/browse/LOGCXX-252).                                                            |    |
| ![](images/fix.gif "fix")    | NDC::cloneStack and NDC::inherit missing in 0.10.0 RC2 Fixes [LOGCXX-251](https://issues.apache.org/jira/browse/LOGCXX-251).                                                                   |    |
| ![](images/fix.gif "fix")    | ODBCAppender has unicode issues Fixes [LOGCXX-248](https://issues.apache.org/jira/browse/LOGCXX-248).                                                                                          |    |
| ![](images/fix.gif "fix")    | MSVC project has wrong additional include directories Fixes [LOGCXX-247](https://issues.apache.org/jira/browse/LOGCXX-247).                                                                    |    |
| ![](images/fix.gif "fix")    | Config refresh hangs a client application that uses TelnetAppender Fixes [LOGCXX-246](https://issues.apache.org/jira/browse/LOGCXX-246).                                                       |    |
| ![](images/fix.gif "fix")    | Problem Compile in Doxy Fixes [LOGCXX-243](https://issues.apache.org/jira/browse/LOGCXX-243).                                                                                                  |    |
| ![](images/update.gif "update") | Eliminate log4cxx proxies for APR types Fixes [LOGCXX-242](https://issues.apache.org/jira/browse/LOGCXX-242).                                                                                  |    |
| ![](images/fix.gif "fix")    | Non-ascii named files have names mangled Fixes [LOGCXX-241](https://issues.apache.org/jira/browse/LOGCXX-241).                                                                                 |    |
| ![](images/update.gif "update") | Inconsistent const qualification on logging methods. Fixes [LOGCXX-239](https://issues.apache.org/jira/browse/LOGCXX-239).                                                                     |    |
| ![](images/fix.gif "fix")    | Include missing headers Fixes [LOGCXX-237](https://issues.apache.org/jira/browse/LOGCXX-237).                                                                                                  |    |
| ![](images/fix.gif "fix")    | Re-order constructor initialiser lists to match declaration order Fixes [LOGCXX-236](https://issues.apache.org/jira/browse/LOGCXX-236).                                                        |    |
| ![](images/add.gif "add")    | Add ObjectPtrT::exchange Fixes [LOGCXX-235](https://issues.apache.org/jira/browse/LOGCXX-235).                                                                                                 |    |
| ![](images/fix.gif "fix")    | Assignment operator removes const qualifier Fixes [LOGCXX-234](https://issues.apache.org/jira/browse/LOGCXX-234).                                                                              |    |
| ![](images/update.gif "update") | Unnecessary casts in ObjectPtrT Fixes [LOGCXX-233](https://issues.apache.org/jira/browse/LOGCXX-233).                                                                                          |    |
| ![](images/update.gif "update") | Drop src/performance Fixes [LOGCXX-232](https://issues.apache.org/jira/browse/LOGCXX-232).                                                                                                     |    |
| ![](images/fix.gif "fix")    | Deadlock in AsyncAppender Fixes [LOGCXX-231](https://issues.apache.org/jira/browse/LOGCXX-231).                                                                                                |    |
| ![](images/update.gif "update") | Align ant build options with automake Fixes [LOGCXX-230](https://issues.apache.org/jira/browse/LOGCXX-230).                                                                                    |    |
| ![](images/update.gif "update") | Remove @author tags Fixes [LOGCXX-228](https://issues.apache.org/jira/browse/LOGCXX-228).                                                                                                      |    |
| ![](images/update.gif "update") | Remove @since tags Fixes [LOGCXX-227](https://issues.apache.org/jira/browse/LOGCXX-227).                                                                                                       |    |
| ![](images/update.gif "update") | Default configurator uses \*.properties in preference to \*.xml Fixes [LOGCXX-226](https://issues.apache.org/jira/browse/LOGCXX-226).                                                          |    |
| ![](images/update.gif "update") | Migrate unit tests from LGPL'd CPPUNIT to an ASL'd testing framework Fixes [LOGCXX-225](https://issues.apache.org/jira/browse/LOGCXX-225).                                                     |    |
| ![](images/fix.gif "fix")    | trunk compile error. Fixes [LOGCXX-222](https://issues.apache.org/jira/browse/LOGCXX-222).                                                                                                     |    |
| ![](images/fix.gif "fix")    | ThreadID layout does not match debugger Fixes [LOGCXX-221](https://issues.apache.org/jira/browse/LOGCXX-221).                                                                                  |    |
| ![](images/fix.gif "fix")    | Memory leaks when using MFC Fixes [LOGCXX-220](https://issues.apache.org/jira/browse/LOGCXX-220).                                                                                              |    |
| ![](images/fix.gif "fix")    | suspicious warnings Fixes [LOGCXX-219](https://issues.apache.org/jira/browse/LOGCXX-219).                                                                                                      |    |
| ![](images/add.gif "add")    | Visual Studio 8 build Fixes [LOGCXX-218](https://issues.apache.org/jira/browse/LOGCXX-218).                                                                                                    |    |
| ![](images/fix.gif "fix")    | Not initialized LoggerPtr segfault program. Fixes [LOGCXX-217](https://issues.apache.org/jira/browse/LOGCXX-217).                                                                              |    |
| ![](images/fix.gif "fix")    | crash on program exit Fixes [LOGCXX-216](https://issues.apache.org/jira/browse/LOGCXX-216).                                                                                                    |    |
| ![](images/update.gif "update") | Eliminate sqlext.h from odbcappender.h Fixes [LOGCXX-215](https://issues.apache.org/jira/browse/LOGCXX-215).                                                                                   |    |
| ![](images/fix.gif "fix")    | Possible memory leak due to fault in build process (via make) Fixes [LOGCXX-214](https://issues.apache.org/jira/browse/LOGCXX-214).                                                            |    |
| ![](images/fix.gif "fix")    | trace method implementation is missing Fixes [LOGCXX-213](https://issues.apache.org/jira/browse/LOGCXX-213).                                                                                   |    |
| ![](images/fix.gif "fix")    | unittest failed Fixes [LOGCXX-212](https://issues.apache.org/jira/browse/LOGCXX-212).                                                                                                          |    |
| ![](images/fix.gif "fix")    | Crash(Segmentation Fault) in DailyRollingFileAppender when file change Fixes [LOGCXX-211](https://issues.apache.org/jira/browse/LOGCXX-211).                                                   |    |
| ![](images/fix.gif "fix")    | HTMLLayout NDC null check Fixes [LOGCXX-210](https://issues.apache.org/jira/browse/LOGCXX-210).                                                                                                |    |
| ![](images/fix.gif "fix")    | A message of type wchar\_t\* is not beeing written correctly to the internal message buffer (Revision: 592627) Fixes [LOGCXX-209](https://issues.apache.org/jira/browse/LOGCXX-209).           |    |
| ![](images/fix.gif "fix")    | isTraceEnabled implemenation missing in logger.cpp (Revision: 592627) Fixes [LOGCXX-208](https://issues.apache.org/jira/browse/LOGCXX-208).                                                    |    |
| ![](images/fix.gif "fix")    | PatternParserTestCase and FileNamePatternTestCase fail only with VC6 Fixes [LOGCXX-204](https://issues.apache.org/jira/browse/LOGCXX-204).                                                     |    |
| ![](images/fix.gif "fix")    | ObjectPtrT has inconsistent const-ness on accessors Fixes [LOGCXX-202](https://issues.apache.org/jira/browse/LOGCXX-202).                                                                      |    |
| ![](images/add.gif "add")    | Visual Studio 6 build Fixes [LOGCXX-201](https://issues.apache.org/jira/browse/LOGCXX-201).                                                                                                    |    |
| ![](images/add.gif "add")    | Implement compression for RollingFileAppender Fixes [LOGCXX-200](https://issues.apache.org/jira/browse/LOGCXX-200).                                                                            |    |
| ![](images/fix.gif "fix")    | ant can't generate vc6 project Fixes [LOGCXX-197](https://issues.apache.org/jira/browse/LOGCXX-197).                                                                                           |    |
| ![](images/fix.gif "fix")    | Syslog appender destructor can cause core Fixes [LOGCXX-196](https://issues.apache.org/jira/browse/LOGCXX-196).                                                                                |    |
| ![](images/fix.gif "fix")    | Syslog appender adds characters to output. Fixes [LOGCXX-195](https://issues.apache.org/jira/browse/LOGCXX-195).                                                                               |    |
| ![](images/fix.gif "fix")    | Garbage in log files when appenders are defined in multiple levels of the logger hierarchy Fixes [LOGCXX-194](https://issues.apache.org/jira/browse/LOGCXX-194).                               |    |
| ![](images/update.gif "update") | Please rename or remove new local variable "buf" in Logger.h macros Fixes [LOGCXX-193](https://issues.apache.org/jira/browse/LOGCXX-193).                                                      |    |
| ![](images/update.gif "update") | Suggested improvements to log4cxx webpages Fixes [LOGCXX-192](https://issues.apache.org/jira/browse/LOGCXX-192).                                                                               |    |
| ![](images/fix.gif "fix")    | Application cores when syslog appender is given an unreachable host/ip. Fixes [LOGCXX-191](https://issues.apache.org/jira/browse/LOGCXX-191).                                                  |    |
| ![](images/fix.gif "fix")    | The 'logger.h' header includes itself. Fixes [LOGCXX-190](https://issues.apache.org/jira/browse/LOGCXX-190).                                                                                   |    |
| ![](images/update.gif "update") | Migrate to Maven 2.0 for documentation and packaging Fixes [LOGCXX-189](https://issues.apache.org/jira/browse/LOGCXX-189).                                                                     |    |
| ![](images/update.gif "update") | Upgrade to apr 1.2.9 and apr-util 1.2.8 Fixes [LOGCXX-188](https://issues.apache.org/jira/browse/LOGCXX-188).                                                                                  |    |
| ![](images/fix.gif "fix")    | LogLog::emit() could potentially interleave messages Fixes [LOGCXX-187](https://issues.apache.org/jira/browse/LOGCXX-187).                                                                     |    |
| ![](images/fix.gif "fix")    | Garbage characters in log files when log requests from multiple threads with hyperthreading enabled Fixes [LOGCXX-186](https://issues.apache.org/jira/browse/LOGCXX-186).                      |    |
| ![](images/fix.gif "fix")    | Crash when log level set to 'inherited' Fixes [LOGCXX-184](https://issues.apache.org/jira/browse/LOGCXX-184).                                                                                  |    |
| ![](images/fix.gif "fix")    | Compiler warning: dereferencing type-punned pointer will break strict-aliasing rules Fixes [LOGCXX-183](https://issues.apache.org/jira/browse/LOGCXX-183).                                     |    |
| ![](images/fix.gif "fix")    | missing man page for simplesocketserver Fixes [LOGCXX-182](https://issues.apache.org/jira/browse/LOGCXX-182).                                                                                  |    |
| ![](images/fix.gif "fix")    | Level::DEBUG and other non-local statics cause crash on app shutdown on AIX Fixes [LOGCXX-181](https://issues.apache.org/jira/browse/LOGCXX-181).                                              |    |
| ![](images/fix.gif "fix")    | Build fails at domconfigurator.h Fixes [LOGCXX-180](https://issues.apache.org/jira/browse/LOGCXX-180).                                                                                         |    |
| ![](images/add.gif "add")    | example applications do SIGABRT on aix 5.2 Fixes [LOGCXX-179](https://issues.apache.org/jira/browse/LOGCXX-179).                                                                               |    |
| ![](images/fix.gif "fix")    | Link failure if wchar\_t cannot be determined as UTF-16 or UTF-32 Fixes [LOGCXX-178](https://issues.apache.org/jira/browse/LOGCXX-178).                                                        |    |
| ![](images/fix.gif "fix")    | SocketImpl::accept uses private APR function: apr\_wait\_for\_io\_or\_timeout Fixes [LOGCXX-177](https://issues.apache.org/jira/browse/LOGCXX-177).                                            |    |
| ![](images/fix.gif "fix")    | APRCharsetEncoder is not thread safe Fixes [LOGCXX-175](https://issues.apache.org/jira/browse/LOGCXX-175).                                                                                     |    |
| ![](images/fix.gif "fix")    | configure fail with ".infig.status: error: cannot find input file:" Fixes [LOGCXX-172](https://issues.apache.org/jira/browse/LOGCXX-172).                                                      |    |
| ![](images/add.gif "add")    | Add project description file for projects.apache.org Fixes [LOGCXX-171](https://issues.apache.org/jira/browse/LOGCXX-171).                                                                     |    |
| ![](images/fix.gif "fix")    | XMLLayoutTestCase fails on compilers that do not provide location info Fixes [LOGCXX-169](https://issues.apache.org/jira/browse/LOGCXX-169).                                                   |    |
| ![](images/fix.gif "fix")    | log4j.dtd does not contain rollingPolicy and other o.a.l.r.RFA elements Fixes [LOGCXX-168](https://issues.apache.org/jira/browse/LOGCXX-168).                                                  |    |
| ![](images/fix.gif "fix")    | system locale charmap is not determined properly on Fedora Core 6 Fixes [LOGCXX-167](https://issues.apache.org/jira/browse/LOGCXX-167).                                                        |    |
| ![](images/fix.gif "fix")    | XMLSocketAppender may generate erroneous output due to mismatched encoding Fixes [LOGCXX-165](https://issues.apache.org/jira/browse/LOGCXX-165).                                               |    |
| ![](images/fix.gif "fix")    | XMLSocketAppender is disabled Fixes [LOGCXX-164](https://issues.apache.org/jira/browse/LOGCXX-164).                                                                                            |    |
| ![](images/fix.gif "fix")    | liblog4cxx (svn 480882) does not link on Mac OS X 10.4 Fixes [LOGCXX-163](https://issues.apache.org/jira/browse/LOGCXX-163).                                                                   |    |
| ![](images/fix.gif "fix")    | Problem printing string with embedded NULL character Fixes [LOGCXX-162](https://issues.apache.org/jira/browse/LOGCXX-162).                                                                     |    |
| ![](images/fix.gif "fix")    | Using RollingFileAppender increases the working set with each rollover Fixes [LOGCXX-161](https://issues.apache.org/jira/browse/LOGCXX-161).                                                   |    |
| ![](images/fix.gif "fix")    | helpers/object.h: DECLARE\_LOG4CXX\_OBJECT macro definition is missing virtual destructor declaration Fixes [LOGCXX-160](https://issues.apache.org/jira/browse/LOGCXX-160).                    |    |
| ![](images/fix.gif "fix")    | Initialization of local static objects out of order on Linux Fixes [LOGCXX-159](https://issues.apache.org/jira/browse/LOGCXX-159).                                                             |    |
| ![](images/fix.gif "fix")    | tolower not defined in stringhelper.cpp Fixes [LOGCXX-158](https://issues.apache.org/jira/browse/LOGCXX-158).                                                                                  |    |
| ![](images/fix.gif "fix")    | make install fails since @manual\_dest@ replacement is missing in Makefiles Fixes [LOGCXX-157](https://issues.apache.org/jira/browse/LOGCXX-157).                                              |    |
| ![](images/update.gif "update") | immediate flush in console appender Fixes [LOGCXX-156](https://issues.apache.org/jira/browse/LOGCXX-156).                                                                                      |    |
| ![](images/update.gif "update") | Update source headers per new ASF header policy Fixes [LOGCXX-155](https://issues.apache.org/jira/browse/LOGCXX-155).                                                                          |    |
| ![](images/add.gif "add")    | Automate log4cxx site and doxygen generation and deployment Fixes [LOGCXX-153](https://issues.apache.org/jira/browse/LOGCXX-153).                                                              |    |
| ![](images/fix.gif "fix")    | gcc warning about cast from \`const void\*' to \`log4cxx::helpers::Object\*' discards qualifiers from pointer target typ Fixes [LOGCXX-152](https://issues.apache.org/jira/browse/LOGCXX-152). |    |
| ![](images/fix.gif "fix")    | Umlauts as literal in patternlayout won't be logged correct Fixes [LOGCXX-151](https://issues.apache.org/jira/browse/LOGCXX-151).                                                              |    |
| ![](images/fix.gif "fix")    | logstream's operator\<\< declared in the wrong namespace Fixes [LOGCXX-150](https://issues.apache.org/jira/browse/LOGCXX-150).                                                                 |    |
| ![](images/fix.gif "fix")    | make dist does not work Fixes [LOGCXX-149](https://issues.apache.org/jira/browse/LOGCXX-149).                                                                                                  |    |
| ![](images/fix.gif "fix")    | DailyRollingFileAppender::~DailyRollingFileAppender must call finalize Fixes [LOGCXX-146](https://issues.apache.org/jira/browse/LOGCXX-146).                                                  |    |
| ![](images/fix.gif "fix")    | \-xarch=v8plus should be removed from Makefile.in Fixes [LOGCXX-143](https://issues.apache.org/jira/browse/LOGCXX-143).                                                                        |    |
| ![](images/fix.gif "fix")    | socketservertestcase.cpp does not compile with Sun Studio 11 on Solaris Fixes [LOGCXX-142](https://issues.apache.org/jira/browse/LOGCXX-142).                                                  |    |
| ![](images/update.gif "update") | Upgrade to APR 1.2.7 or later Fixes [LOGCXX-141](https://issues.apache.org/jira/browse/LOGCXX-141).                                                                                            |    |
| ![](images/fix.gif "fix")    | Handle leak with LoggingEvent::getCurrentThreadName Fixes [LOGCXX-140](https://issues.apache.org/jira/browse/LOGCXX-140).                                                                      |    |
| ![](images/fix.gif "fix")    | XMLLayoutTestCase uses inadequate filters for 64 bit platforms Fixes [LOGCXX-139](https://issues.apache.org/jira/browse/LOGCXX-139).                                                           |    |
| ![](images/fix.gif "fix")    | XMLLayoutTestCase output and filtered output gets overwritten Fixes [LOGCXX-138](https://issues.apache.org/jira/browse/LOGCXX-138).                                                            |    |
| ![](images/fix.gif "fix")    | DailyRollingFileAppender not using Property options Fixes [LOGCXX-136](https://issues.apache.org/jira/browse/LOGCXX-136).                                                                      |    |
| ![](images/update.gif "update") | Use std::string with logstream Fixes [LOGCXX-135](https://issues.apache.org/jira/browse/LOGCXX-135).                                                                                           |    |
| ![](images/fix.gif "fix")    | FileAppender could create missing directories Fixes [LOGCXX-134](https://issues.apache.org/jira/browse/LOGCXX-134).                                                                            |    |
| ![](images/fix.gif "fix")    | Missing parenthesis in LOG4CXX\_ASSERT Fixes [LOGCXX-133](https://issues.apache.org/jira/browse/LOGCXX-133).                                                                                   |    |
| ![](images/fix.gif "fix")    | various segmentation faults in multithreaded application Fixes [LOGCXX-132](https://issues.apache.org/jira/browse/LOGCXX-132).                                                                 |    |
| ![](images/fix.gif "fix")    | TimeBasedRollingPolicy is declared "abstract" Fixes [LOGCXX-131](https://issues.apache.org/jira/browse/LOGCXX-131).                                                                            |    |
| ![](images/fix.gif "fix")    | Compile fails on gcc4.1 Fixes [LOGCXX-130](https://issues.apache.org/jira/browse/LOGCXX-130).                                                                                                  |    |
| ![](images/fix.gif "fix")    | Asyncappender is full of race conditions (improper use of condition variables) Fixes [LOGCXX-129](https://issues.apache.org/jira/browse/LOGCXX-129).                                           |    |
| ![](images/fix.gif "fix")    | Main build.xml not referencing "env" properly. Fixes [LOGCXX-127](https://issues.apache.org/jira/browse/LOGCXX-127).                                                                           |    |
| ![](images/fix.gif "fix")    | std::cout stops working if log4cxx is first to output Fixes [LOGCXX-126](https://issues.apache.org/jira/browse/LOGCXX-126).                                                                    |    |
| ![](images/update.gif "update") | L7dTestCase is stubbed out Fixes [LOGCXX-125](https://issues.apache.org/jira/browse/LOGCXX-125).                                                                                               |    |
| ![](images/fix.gif "fix")    | wchar\_t constructor missing in class NDC Fixes [LOGCXX-124](https://issues.apache.org/jira/browse/LOGCXX-124).                                                                                |    |
| ![](images/fix.gif "fix")    | UTF-8 build fails on Linux Fixes [LOGCXX-123](https://issues.apache.org/jira/browse/LOGCXX-123).                                                                                               |    |
| ![](images/fix.gif "fix")    | Wrong parameter description in Patternlayout Fixes [LOGCXX-120](https://issues.apache.org/jira/browse/LOGCXX-120).                                                                             |    |
| ![](images/fix.gif "fix")    | ndctestcase not working Fixes [LOGCXX-119](https://issues.apache.org/jira/browse/LOGCXX-119).                                                                                                  |    |
| ![](images/fix.gif "fix")    | Hierarchy corrupts with PropertyConfigurator Fixes [LOGCXX-118](https://issues.apache.org/jira/browse/LOGCXX-118).                                                                             |    |
| ![](images/fix.gif "fix")    | Memory leak with ThreadSpecificData on Win32 Fixes [LOGCXX-117](https://issues.apache.org/jira/browse/LOGCXX-117).                                                                             |    |
| ![](images/fix.gif "fix")    | SVN head does not compiler with MinGW compiler Fixes [LOGCXX-116](https://issues.apache.org/jira/browse/LOGCXX-116).                                                                           |    |
| ![](images/fix.gif "fix")    | SVN head does not compile with Borland C++ compiler Fixes [LOGCXX-115](https://issues.apache.org/jira/browse/LOGCXX-115).                                                                      |    |
| ![](images/update.gif "update") | Upgrade APR to 1.2.2 from 1.1.0 Fixes [LOGCXX-114](https://issues.apache.org/jira/browse/LOGCXX-114).                                                                                          |    |
| ![](images/update.gif "update") | separate apr detection m4 codes from aclocal.m4 Fixes [LOGCXX-113](https://issues.apache.org/jira/browse/LOGCXX-113).                                                                          |    |
| ![](images/update.gif "update") | change "static" to "auto" for Transcoder::decode() decoder and CharsetDecoder::getDefaultDecoder() decoder Fixes [LOGCXX-112](https://issues.apache.org/jira/browse/LOGCXX-112).               |    |
| ![](images/update.gif "update") | make Logger cache a LoggerRepositoryPtr instead of a "blind" pointer Fixes [LOGCXX-111](https://issues.apache.org/jira/browse/LOGCXX-111).                                                     |    |
| ![](images/fix.gif "fix")    | try fix 64bit log4cxx\_intptr\_t Fixes [LOGCXX-110](https://issues.apache.org/jira/browse/LOGCXX-110).                                                                                         |    |
| ![](images/fix.gif "fix")    | Can't compile log4cxx in ascii on Windows Fixes [LOGCXX-107](https://issues.apache.org/jira/browse/LOGCXX-107).                                                                                |    |
| ![](images/fix.gif "fix")    | maxFileSize has bad type in SizeBasedTriggeringPolicy file Fixes [LOGCXX-106](https://issues.apache.org/jira/browse/LOGCXX-106).                                                               |    |
| ![](images/fix.gif "fix")    | Infinite loop in string replacing Fixes [LOGCXX-105](https://issues.apache.org/jira/browse/LOGCXX-105).                                                                                        |    |
| ![](images/fix.gif "fix")    | ODBCAppender::close does not check if appender is already closed Fixes [LOGCXX-104](https://issues.apache.org/jira/browse/LOGCXX-104).                                                         |    |
| ![](images/update.gif "update") | Much of CVS HEAD seems \#if 0 out, especially ResourceBundle stuff Fixes [LOGCXX-103](https://issues.apache.org/jira/browse/LOGCXX-103).                                                       |    |
| ![](images/fix.gif "fix")    | Fixes for ODBCAppender Fixes [LOGCXX-100](https://issues.apache.org/jira/browse/LOGCXX-100).                                                                                                   |    |
| ![](images/fix.gif "fix")    | Gump build fails for log4cxx-ant-no-wchar-t target Fixes [LOGCXX-98](https://issues.apache.org/jira/browse/LOGCXX-98).                                                                         |    |
| ![](images/update.gif "update") | simplesocketserver.cpp should use LOG4CXX\_STR("...") not L"..." Fixes [LOGCXX-94](https://issues.apache.org/jira/browse/LOGCXX-94).                                                           |    |
| ![](images/update.gif "update") | Explore use of security-enhanced CRT methods Fixes [LOGCXX-88](https://issues.apache.org/jira/browse/LOGCXX-88).                                                                               |    |
| ![](images/update.gif "update") | Remove remaining uses of Category and Priority Fixes [LOGCXX-87](https://issues.apache.org/jira/browse/LOGCXX-87).                                                                             |    |
| ![](images/add.gif "add")    | Add TRACE level Fixes [LOGCXX-86](https://issues.apache.org/jira/browse/LOGCXX-86).                                                                                                            |    |
| ![](images/update.gif "update") | Mac OS/X fixes and enhancements Fixes [LOGCXX-85](https://issues.apache.org/jira/browse/LOGCXX-85).                                                                                            |    |
| ![](images/fix.gif "fix")    | Problems with stream logging in UTF8, no WCHAR\_T build Fixes [LOGCXX-84](https://issues.apache.org/jira/browse/LOGCXX-84).                                                                    |    |
| ![](images/fix.gif "fix")    | log4cxx::Level::ERROR fails to compile when GDI enabled Fixes [LOGCXX-83](https://issues.apache.org/jira/browse/LOGCXX-83).                                                                    |    |
| ![](images/fix.gif "fix")    | Compiling with stream.h in multiple object files errors Fixes [LOGCXX-82](https://issues.apache.org/jira/browse/LOGCXX-82).                                                                    |    |
| ![](images/fix.gif "fix")    | SimpleDateFormat does not compile on Solaris 2.95.2 gcc Fixes [LOGCXX-81](https://issues.apache.org/jira/browse/LOGCXX-81).                                                                    |    |
| ![](images/update.gif "update") | Migrated network appenders to APR network IO Fixes [LOGCXX-80](https://issues.apache.org/jira/browse/LOGCXX-80).                                                                               |    |
| ![](images/update.gif "update") | configure check for apr-util Fixes [LOGCXX-79](https://issues.apache.org/jira/browse/LOGCXX-79).                                                                                               |    |
| ![](images/fix.gif "fix")    | Static builds broken Fixes [LOGCXX-77](https://issues.apache.org/jira/browse/LOGCXX-77).                                                                                                       |    |
| ![](images/add.gif "add")    | user.home, user.dir, java.io.tmpdir available within configuration files Fixes [LOGCXX-76](https://issues.apache.org/jira/browse/LOGCXX-76).                                                   |    |
| ![](images/add.gif "add")    | Cygwin build Fixes [LOGCXX-75](https://issues.apache.org/jira/browse/LOGCXX-75).                                                                                                               |    |
| ![](images/add.gif "add")    | MinGW build Fixes [LOGCXX-74](https://issues.apache.org/jira/browse/LOGCXX-74).                                                                                                                |    |
| ![](images/fix.gif "fix")    | Not loading configuration from log4cxx.properties or log4cxx.xml Fixes [LOGCXX-73](https://issues.apache.org/jira/browse/LOGCXX-73).                                                           |    |
| ![](images/update.gif "update") | INSTALL out of date Fixes [LOGCXX-72](https://issues.apache.org/jira/browse/LOGCXX-72).                                                                                                        |    |
| ![](images/update.gif "update") | Update performance page on web site Fixes [LOGCXX-71](https://issues.apache.org/jira/browse/LOGCXX-71).                                                                                        |    |
| ![](images/fix.gif "fix")    | Logic flaws in StringHelper::startsWith and StringHelper::endsWith Fixes [LOGCXX-70](https://issues.apache.org/jira/browse/LOGCXX-70).                                                         |    |
| ![](images/fix.gif "fix")    | NTEventLogAppender always uses RPC method for logging and has inadequate error handling. Fixes [LOGCXX-67](https://issues.apache.org/jira/browse/LOGCXX-67).                                   |    |
| ![](images/fix.gif "fix")    | SyslogAppender append method currently stubbed out Fixes [LOGCXX-66](https://issues.apache.org/jira/browse/LOGCXX-66).                                                                         |    |
| ![](images/update.gif "update") | Migrate to APR network IO Fixes [LOGCXX-64](https://issues.apache.org/jira/browse/LOGCXX-64).                                                                                                  |    |
| ![](images/update.gif "update") | Platform appropriate line-feed convention Fixes [LOGCXX-63](https://issues.apache.org/jira/browse/LOGCXX-63).                                                                                  |    |
| ![](images/update.gif "update") | log4cxx 0.10.0 release Fixes [LOGCXX-62](https://issues.apache.org/jira/browse/LOGCXX-62).                                                                                                     |    |
| ![](images/fix.gif "fix")    | XML layout can be mismatched with document encoding Fixes [LOGCXX-60](https://issues.apache.org/jira/browse/LOGCXX-60).                                                                        |    |
| ![](images/update.gif "update") | Implement encoding support for Writer appender Fixes [LOGCXX-59](https://issues.apache.org/jira/browse/LOGCXX-59).                                                                             |    |
| ![](images/fix.gif "fix")    | ImmediateFlush'd FileAppenders extremely slow on Windows Fixes [LOGCXX-58](https://issues.apache.org/jira/browse/LOGCXX-58).                                                                   |    |
| ![](images/add.gif "add")    | Port log4j performance test Fixes [LOGCXX-57](https://issues.apache.org/jira/browse/LOGCXX-57).                                                                                                |    |
| ![](images/fix.gif "fix")    | BasicConfiguration is unreliable Fixes [LOGCXX-56](https://issues.apache.org/jira/browse/LOGCXX-56).                                                                                           |    |
| ![](images/add.gif "add")    | DailyRolling File Appender Fixes [LOGCXX-55](https://issues.apache.org/jira/browse/LOGCXX-55).                                                                                                 |    |
| ![](images/fix.gif "fix")    | Eliminate use of boost-regex in unit tests Fixes [LOGCXX-54](https://issues.apache.org/jira/browse/LOGCXX-54).                                                                                 |    |
| ![](images/fix.gif "fix")    | Problems compiling with MsDev 6.0 (space in paths) Fixes [LOGCXX-53](https://issues.apache.org/jira/browse/LOGCXX-53).                                                                         |    |
| ![](images/add.gif "add")    | Migrate log4j 1.3 RollingFileAppender Fixes [LOGCXX-52](https://issues.apache.org/jira/browse/LOGCXX-52).                                                                                      |    |
| ![](images/fix.gif "fix")    | variable name clash in macro Fixes [LOGCXX-50](https://issues.apache.org/jira/browse/LOGCXX-50).                                                                                               |    |
| ![](images/add.gif "add")    | Move timezone specification into pattern, remove locale specification Fixes [LOGCXX-49](https://issues.apache.org/jira/browse/LOGCXX-49).                                                      |    |
| ![](images/add.gif "add")    | Use hex representation for thread identifier Fixes [LOGCXX-48](https://issues.apache.org/jira/browse/LOGCXX-48).                                                                               |    |
| ![](images/fix.gif "fix")    | Check headers for missing declarations and Effective C++ violations Fixes [LOGCXX-47](https://issues.apache.org/jira/browse/LOGCXX-47).                                                        |    |
| ![](images/fix.gif "fix")    | Extra semicolon after namespace closing paren Fixes [LOGCXX-46](https://issues.apache.org/jira/browse/LOGCXX-46).                                                                              |    |
| ![](images/fix.gif "fix")    | \_T causes error : 1048576 cannot be used as a function Fixes [LOGCXX-45](https://issues.apache.org/jira/browse/LOGCXX-45).                                                                    |    |
| ![](images/add.gif "add")    | GUMP integation Fixes [LOGCXX-44](https://issues.apache.org/jira/browse/LOGCXX-44).                                                                                                            |    |
| ![](images/add.gif "add")    | configure/make help needed Fixes [LOGCXX-43](https://issues.apache.org/jira/browse/LOGCXX-43).                                                                                                 |    |
| ![](images/fix.gif "fix")    | Layout timestamp doesn't seem to adjust for daylight saving Fixes [LOGCXX-41](https://issues.apache.org/jira/browse/LOGCXX-41).                                                                |    |
| ![](images/fix.gif "fix")    | PatternLayout does not support Java date format specifiers Fixes [LOGCXX-40](https://issues.apache.org/jira/browse/LOGCXX-40).                                                                 |    |
| ![](Pictures/100002000000001400000014836C96AED584EDBB.gif "remove") | Remove DailyRollingFileAppender Fixes [LOGCXX-39](https://issues.apache.org/jira/browse/LOGCXX-39).                                                                                            |    |
| ![](images/fix.gif "fix")    | Unable to build log4cxx under Borland C++ Fixes [LOGCXX-37](https://issues.apache.org/jira/browse/LOGCXX-37).                                                                                  |    |
| ![](images/add.gif "add")    | Migrate to Apache Portable Runtime threads Fixes [LOGCXX-36](https://issues.apache.org/jira/browse/LOGCXX-36).                                                                                 |    |
| ![](Pictures/100002000000001400000014836C96AED584EDBB.gif "remove") | Avoid use of MSXML Fixes [LOGCXX-35](https://issues.apache.org/jira/browse/LOGCXX-35).                                                                                                         |    |
| ![](images/fix.gif "fix")    | Visual Studio 6 CVS build broken Fixes [LOGCXX-34](https://issues.apache.org/jira/browse/LOGCXX-34).                                                                                           |    |
| ![](images/fix.gif "fix")    | log4cxx::Exception is not derived from std::exception Fixes [LOGCXX-33](https://issues.apache.org/jira/browse/LOGCXX-33).                                                                      |    |
| ![](images/fix.gif "fix")    | Missing copy constructors and assignment operators Fixes [LOGCXX-32](https://issues.apache.org/jira/browse/LOGCXX-32).                                                                         |    |
| ![](images/fix.gif "fix")    | Missing const qualifiers, Exception::getMessage() in particular. Fixes [LOGCXX-31](https://issues.apache.org/jira/browse/LOGCXX-31).                                                           |    |
| ![](images/fix.gif "fix")    | StringTokenizer uses evil strtok and wcstok functions Fixes [LOGCXX-30](https://issues.apache.org/jira/browse/LOGCXX-30).                                                                      |    |
| ![](images/fix.gif "fix")    | Appender attributes are not passed passed to setOption correctly. Fixes [LOGCXX-29](https://issues.apache.org/jira/browse/LOGCXX-29).                                                          |    |
| ![](images/fix.gif "fix")    | Appender threshold cannot be set in configuration files Fixes [LOGCXX-28](https://issues.apache.org/jira/browse/LOGCXX-28).                                                                    |    |
| ![](images/fix.gif "fix")    | Appender threshold cannot be set in configuration files Fixes [LOGCXX-27](https://issues.apache.org/jira/browse/LOGCXX-27).                                                                    |    |
| ![](images/fix.gif "fix")    | Default initialization is broken Fixes [LOGCXX-26](https://issues.apache.org/jira/browse/LOGCXX-26).                                                                                           |    |
| ![](images/add.gif "add")    | Add Ant+cpptasks build file Fixes [LOGCXX-25](https://issues.apache.org/jira/browse/LOGCXX-25).                                                                                                |    |
| ![](images/fix.gif "fix")    | Class and module name not available in LogEvent Fixes [LOGCXX-24](https://issues.apache.org/jira/browse/LOGCXX-24).                                                                            |    |
| ![](images/fix.gif "fix")    | Unit tests have become stale Fixes [LOGCXX-23](https://issues.apache.org/jira/browse/LOGCXX-23).                                                                                               |    |
| ![](images/fix.gif "fix")    | Backslashes in filenames in XML config of FileAppender broken Fixes [LOGCXX-22](https://issues.apache.org/jira/browse/LOGCXX-22).                                                              |    |
| ![](images/add.gif "add")    | Add check that libxml2 not libxml has been included Fixes [LOGCXX-21](https://issues.apache.org/jira/browse/LOGCXX-21).                                                                        |    |
| ![](images/add.gif "add")    | Add .cvsignore's to ignore generated files Fixes [LOGCXX-19](https://issues.apache.org/jira/browse/LOGCXX-19).                                                                                 |    |
| ![](images/add.gif "add")    | LoggerStream Feature Fixes [LOGCXX-18](https://issues.apache.org/jira/browse/LOGCXX-18).                                                                                                       |    |
| ![](images/update.gif "update") | Use of non reentrant time functions Fixes [LOGCXX-17](https://issues.apache.org/jira/browse/LOGCXX-17).                                                                                        |    |
| ![](images/fix.gif "fix")    | Misleading statements in Introduction to log4cxx Fixes [LOGCXX-16](https://issues.apache.org/jira/browse/LOGCXX-16).                                                                           |    |
| ![](images/fix.gif "fix")    | PatternLayout don't use locale time zone,it's use GMT tome zone Fixes [LOGCXX-15](https://issues.apache.org/jira/browse/LOGCXX-15).                                                            |    |
| ![](images/add.gif "add")    | add -Wall to compile log4cxx will get many warning Fixes [LOGCXX-14](https://issues.apache.org/jira/browse/LOGCXX-14).                                                                         |    |
| ![](images/add.gif "add")    | Add branch optimization hint to LOG4CXX\_DEBUG macro Fixes [LOGCXX-13](https://issues.apache.org/jira/browse/LOGCXX-13).                                                                       |    |
| ![](images/fix.gif "fix")    | the threshold of ApenderSkeleton can not be set by calling setOption. Fixes [LOGCXX-12](https://issues.apache.org/jira/browse/LOGCXX-12).                                                      |    |
| ![](images/fix.gif "fix")    | Timezone may have side-effects Fixes [LOGCXX-11](https://issues.apache.org/jira/browse/LOGCXX-11).                                                                                             |    |
| ![](images/fix.gif "fix")    | Conflicting definitions of tchar.h/simulatenous Unicode+MBCS Fixes [LOGCXX-10](https://issues.apache.org/jira/browse/LOGCXX-10).                                                               |    |
| ![](images/fix.gif "fix")    | Compilation problems using VC5 or VC6 with later Platform SDKs Fixes [LOGCXX-8](https://issues.apache.org/jira/browse/LOGCXX-8).                                                               |    |
| ![](images/fix.gif "fix")    | SocketAppender binary format not compatible with Chainsaw Fixes [LOGCXX-7](https://issues.apache.org/jira/browse/LOGCXX-7).                                                                    |    |
| ![](images/add.gif "add")    | Win32 OutputDebugString Fixes [LOGCXX-6](https://issues.apache.org/jira/browse/LOGCXX-6).                                                                                                      |    |
| ![](images/fix.gif "fix")    | Preprocessor macro WIN32 used instead of \_WIN32 Fixes [LOGCXX-5](https://issues.apache.org/jira/browse/LOGCXX-5).                                                                             |    |
| ![](images/fix.gif "fix")    | initialization not working on many OS's Fixes [LOGCXX-4](https://issues.apache.org/jira/browse/LOGCXX-4).                                                                                      |    |
| ![](images/fix.gif "fix")    | Missing \#else Fixes [LOGCXX-3](https://issues.apache.org/jira/browse/LOGCXX-3).                                                                                                               |    |
| ![](images/fix.gif "fix")    | logger.h includes config.h Fixes [LOGCXX-2](https://issues.apache.org/jira/browse/LOGCXX-2).                                                                                                   |    |

<a name="0.9.7"/>
### Release 0.9.7 - 2004-05-10

|                                                                  |                                                                                                                                                     |    |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | -- |
| Type                                                             | Changes                                                                                                                                             | By |
| ![](images/fix.gif "fix") | Fixed examples source code in the "Short introduction to log4cxx".                                                                                  |    |
| ![](images/fix.gif "fix") | Fixed, in the renaming algorithm of RollingFileAppender and DailyRollingFileAppender, a problem specific to Unicode.                                |    |
| ![](images/fix.gif "fix") | Fixed conflict with Windows macros "min" and "max", by renaming StrictMath::min and StrictMath::max to StrictMath::minimum and StrictMath::maximum. |    |
| ![](images/add.gif "add") | Port to HPUX 11.0.                                                                                                                                  |    |
| ![](images/fix.gif "fix") | Fixed segmentation fault in PropertyConfigurator.                                                                                                   |    |
| ![](images/add.gif "add") | Port to Solaris.                                                                                                                                    |    |
| ![](images/fix.gif "fix") | Fixed MutexException thrown while destroying RollingFileAppender.                                                                                   |    |
| ![](images/fix.gif "fix") | Logging macros can be used without explicity declaring the use of log4cxx namespace.                                                                |    |
| ![](images/fix.gif "fix") | Fixed static library unresolved externals for msvc 6 and 7.1                                                                                        |    |

<a name="0.9.6"/>
### Release 0.9.6 - 2004-04-11

|                                                                     |                                                                                                         |    |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | -- |
| Type                                                                | Changes                                                                                                 | By |
| ![](images/update.gif "update") | Timezone management has been optimized through the class TimeZone                                       |    |
| ![](images/update.gif "update") | Inter-thread synchronization and reference counting has been optimized                                  |    |
| ![](images/update.gif "update") | Reference counting now uses gcc atomic functions (bug 929078)                                           |    |
| ![](images/update.gif "update") | Use of StringBuffer has been optimized.                                                                 |    |
| ![](images/add.gif "add")    | Support of localisation throug resourceBundles                                                          |    |
| ![](images/update.gif "update") | SyslogAppender now uses the system function 'syslog' to log on the local host. (only for POSIX systems) |    |
| ![](images/add.gif "add")    | Added TimeZone configuration to PatternLayout (bug 912563)                                              |    |
| ![](images/add.gif "add")    | Support of the DailyRollingFileAppender (feature request 842765)                                        |    |

<a name="0.9.5"/>
### Release 0.9.5 - 2004-02-04

|                                                                  |                                                                                                                            |    |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | -- |
| Type                                                             | Changes                                                                                                                    | By |
| ![](images/add.gif "add") | Port of log4j Jnuit tests with Cppunit and Boost Regex.                                                                    |    |
| ![](images/add.gif "add") | Added explicit exports for MSDEV 6 and MSDEV 7 (no further need of .def files)                                             |    |
| ![](images/add.gif "add") | Custom levels can be configured through the DOMConfigurator and PropertyConfigurator classes (Level inherites from Object) |    |
| ![](images/add.gif "add") | Added a reference counter to LoggingEvent to avoid useless copies (LoggingEvent inherites from Object)                     |    |
| ![](images/add.gif "add") | The file log4j.xml as well as the file log4j.properties are now search for, in log4cxx initialization.                     |    |
| ![](images/add.gif "add") | The root logger can be assigned the "OFF" level.                                                                           |    |
| ![](images/add.gif "add") | Added MSVC6 project missing files mutext.cpp and condition.cpp (bug 847397)                                                |    |
| ![](images/fix.gif "fix") | condition.cpp now compiles with MSVC6 (bug 847417)                                                                         |    |
| ![](images/fix.gif "fix") | fixed pure virtual function call in PropertyConfigurator::configureAndWatch (bug 848521)                                   |    |
| ![](images/fix.gif "fix") | XMLAppender now displays correct timestamp with MSVC 6 (bug 852836)                                                        |    |
| ![](images/add.gif "add") | SRLPORT 4.6 support.                                                                                                       |    |
| ![](images/fix.gif "fix") | Fixed an infinite loop in class Properties.                                                                                |    |
| ![](images/fix.gif "fix") | Fixed compilations problems with unicode.                                                                                  |    |
| ![](images/fix.gif "fix") | Fixed SocketAppender bug concerning MDC and NDC.                                                                           |    |

<a name="0.9.4"/>
### Release 0.9.4 - 2003-10-25

|                                                                     |                                                           |    |
| ------------------------------------------------------------------- | --------------------------------------------------------- | -- |
| Type                                                                | Changes                                                   | By |
| ![](images/update.gif "update") | StringBuffer has been optimized.                          |    |
| ![](images/fix.gif "fix")    | Fixed miscellaneous threading problems.                   |    |
| ![](images/add.gif "add")    | Added TimeZone support in PatternLayout (bug 796894)      |    |
| ![](images/fix.gif "fix")    | Fixed threading configuration problems (bug 809125)       |    |
| ![](images/fix.gif "fix")    | Fixed miscellaneous MSVC and cygwin compilation problems. |    |

<a name="0.9.3"/>
### Release 0.9.3 - 2003-09-19

|                                                                     |                                                                                 |    |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------- | -- |
| Type                                                                | Changes                                                                         | By |
| ![](images/update.gif "update") | Changed tstring to log4cxx::String and tostringstream to log4cxx::StringBuffer. |    |
| ![](images/fix.gif "fix")    | Fixed MSVC 2003 compilation erros and warnings.                                 |    |
| ![](images/add.gif "add")    | Added helpers for NDC and MDC.                                                  |    |
| ![](images/add.gif "add")    | Added TimeZone support in TTCCLayout.                                           |    |
| ![](images/fix.gif "fix")    | Fixed compilation problems with logger macros (LOG4CXX\_...)                    |    |
| ![](images/fix.gif "fix")    | Fixed milliseconds formatting problem with MSVC 6.0 and 2003                    |    |
| ![](images/fix.gif "fix")    | Fixed AsyncAppender crash                                                       |    |
| ![](images/add.gif "add")    | Added new tests                                                                 |    |
| ![](images/add.gif "add")    | Added benchmarks                                                                |    |

<a name="0.9.2"/>
### Release 0.9.2 - 2003-08-10

|                                                                     |                                                                               |    |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------- | -- |
| Type                                                                | Changes                                                                       | By |
| ![](images/fix.gif "fix")    | Fixed FreeBSD compilation problem with pthread mutex (class CriticalSection). |    |
| ![](images/fix.gif "fix")    | Fixed milliseconds formatting problem (class DateFormat).                     |    |
| ![](images/add.gif "add")    | Long events (\> 1024 chars) are now supported in the class XMLSocketAppender. |    |
| ![](images/update.gif "update") | Carriage returns have been normalized in the class XMLLayout.                 |    |

<a name="0.9.1"/>
### Release 0.9.1 - 2003-08-06

|                                                                     |                                                              |    |
| ------------------------------------------------------------------- | ------------------------------------------------------------ | -- |
| Type                                                                | Changes                                                      | By |
| ![](images/fix.gif "fix")    | Fixed deadlock problems in classes Logger and AsyncAppender. |    |
| ![](images/fix.gif "fix")    | Fixed MSVC 6.0 compilation problems.                         |    |
| ![](images/add.gif "add")    | Added MSVC 6.0 static libraty project.                       |    |
| ![](images/update.gif "update") | Default configuration for the SMTP options is "no".          |    |

<a name="0.9.0"/>
### Release 0.9.0 - 2003-08-06

|                                                                  |                                                                        |    |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------- | -- |
| Type                                                             | Changes                                                                | By |
| ![](images/add.gif "add") | Added ODBCAppender (matching log4j JDBCAppender)                       |    |
| ![](images/add.gif "add") | Added SyslogAppender                                                   |    |
| ![](images/add.gif "add") | Added SMTPAppender (only for Linux/FreeBSD)                            |    |
| ![](images/add.gif "add") | Added BasicConfigurator                                                |    |
| ![](images/add.gif "add") | Added a FileWatchDog in PropertyConfigurator and DOMConfigurator       |    |
| ![](images/add.gif "add") | Possibility to load a custom LoggerFactory through the DOMConfigurator |    |
| ![](images/add.gif "add") | Changed time precision from seconds to milliseconds                    |    |
| ![](images/add.gif "add") | Added MSVC 6.0 'Unicode Debug' and 'Unicode Release' targets           |    |
| ![](images/add.gif "add") | Added Java like System class.                                          |    |

<a name="0.1.1"/>
### Release 0.1.1 - 2003-07-09

|                                                                  |                                                                     |    |
| ---------------------------------------------------------------- | ------------------------------------------------------------------- | -- |
| Type                                                             | Changes                                                             | By |
| ![](images/fix.gif "fix") | Fixed MSVC 6.0 compilation problems concerning the 'Release' target |    |
| ![](images/add.gif "add") | Added MSVC 6.0 tests projects                                       |    |

<a name="0.1.0"/>
### Release 0.1.0 - 2003-07-08

|                                                                  |                                                                                                                                                            |    |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -- |
| Type                                                             | Changes                                                                                                                                                    | By |
| ![](images/add.gif "add") | FreeBSD Autotools/Compilation support                                                                                                                      |    |
| ![](images/fix.gif "fix") | Fixed TelnetAppender crash when a socket bind exception occured.                                                                                           |    |
| ![](images/add.gif "add") | Added log4j DTD support to XMLLayout and DOMConfigurator                                                                                                   |    |
| ![](images/add.gif "add") | Can now send events in XML format over TCP (class XMLSocketAppender) for the log4j Chainsaw UI                                                             |    |
| ![](images/add.gif "add") | Now compiles with 'configure --enable-unicode' (UTF16 Unicode support)                                                                                     |    |
| ![](images/add.gif "add") | Added Java like Properties class. It's a helper for the PropertyConfigurator                                                                               |    |
| ![](images/add.gif "add") | Added Java like objects with dynamic cast and instanciation. Custom objects can be configured through the DOMConfigurator and PropertyConfigurator classes |    |
| ![](images/add.gif "add") | Port of the PropertyConfigurator class                                                                                                                     |    |
| ![](images/add.gif "add") | Port of the "Map Diagnostic Context" (MDC) class                                                                                                           |    |
| ![](images/add.gif "add") | Added 13 tests (try make check)                                                                                                                            |    |

<a name="0.0.1"/>
### Release 0.0.1 - 2003-05-31

|                                                                  |                                                                                                                                                      |    |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | -- |
| Type                                                             | Changes                                                                                                                                              | By |
| ![](images/add.gif "add") | Loggers, Hierarchy, Filters, Appenders, Layouts, NDC                                                                                                 |    |
| ![](images/add.gif "add") | Appenders: AsyncAppender, ConsoleAppender, FileAppender, NTEventLogAppender, RollingFileAppender, SocketAppender, SocketHubAappender, TelnetAppender |    |
| ![](images/add.gif "add") | Layouts: HTMLLayout, PatternLayout, SimpleLayout, TTCCLayout, XMLLayout                                                                              |    |
| ![](images/add.gif "add") | Filters: DenyAllFilter, LevelMatchFilter, LevelRangeFilter, StringMatchFilter                                                                        |    |
| ![](images/add.gif "add") | Configurators: DOMConfigurator                                                                                                                       |    |
