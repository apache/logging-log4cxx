Frequently Asked Technical Questions {#faq}
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
[TOC]

## How do I add a custom level to Apache Log4cxx?{#custom_levels}

This is a common topic for all the Apache logging frameworks and typically motivated to try to
categorize events by functionality or audience.  An common request is to add an AUDIT level so that
the user can configure AUDIT level messages to go to a specific appender. However, the logger name
was designed explicitly to support routing of messages by topic or audience. The common pattern of
using classnames for logger names obscures the more general capability of logger name to represent
the topic or audience of the logging request. The easiest approach to solve the underlying issue is
to use a logger names like "AUDIT.com.example.MyPackage.MyClass" that allow all AUDIT messages to be
routed to a particular appender. If you attempted to use a level for that then you would lose the
ability to distinguish between different significances within the audit messages.

## My application on Windows crashes on shutdown?{#msvc_crash}

Apache Log4cxx API calls use C++ Standard Template Library string parameters. If the caller is using
a different instance or type of the C Runtime Library that Log4cxx, then it is very likely that some
memory that was originally allocated by Log4cxx would be freed by the caller. If log4cxx and the
caller are using different C RTL's, the program will likely crash at the point. Use "Multithread
DLL" with release builds of Log4cxx and "Multithread DLL Debug" with debug builds.

## Does Apache Log4cxx support Unicode?{#unicode_supported}

Yes. Apache Log4cxx exposes API methods in multiple string flavors supporting differently encoded
textual content, like `char*`, `std::string`, `wchar_t*`, `std::wstring`, `CFStringRef` et al. All
provided texts will be converted to the `LogString` type before further processing, which is one of
several supported internal representations and is selected by the `LOG4CXX_CHAR` cmake option. If methods are
used that take `LogString` as arguments, the macro `LOG4CXX_STR()` can be used to convert literals
to the current `LogString` type. 

The default external representation is controlled by the `LOG4CXX_CHARSET` cmake option.
This default is used to encode a multi-byte characters
unless an `Encoding` property is explicitly configured
for the log4cxx::FileAppender specialization you use.
Note you should use `UTF-8` or `UTF-16` encoding when writing XML or JSON layouts.
Log4cxx also implements character set encodings for `US-ASCII` (`ISO646-US` or `ANSI_X3.4-1968`)
and `ISO-8859-1` (`ISO-LATIN-1` or `CP1252`).
You are highly encouraged to stick to `UTF-8` for the best support from tools and operating systems.

The `locale` character set encoding provides support beyond the above internally implemented options.
It allows you to use any multi-byte encoding provided by the standard library.
If using the `locale` character set encoding or
you use `fwide` to make `stdout` or `stderr` wide-oriented (log4cxx::ConsoleAppender then uses `fputws`)
you will need to explicitly configure the system locale at startup,
for example by using:

```
std::setlocale( LC_ALL, "" ); /* Set user-preferred locale for C functions */
std::locale::global(std::locale("")); /* Set user-preferred locale for C++ functions */
```

This is necessary because, according to the [libc documentation](https://www.gnu.org/software/libc/manual/html_node/Setting-the-Locale.html),
all programs start in the `C` locale by default, which is the [same as ANSI_X3.4-1968](https://stackoverflow.com/questions/48743106/whats-ansi-x3-4-1968-encoding)
and what's commonly known as the encoding `US-ASCII`. That encoding supports a very limited set of
characters only, so inputting Unicode with that encoding in effect to output characters can't work
properly. For example, here is some Hebrew text which says "People with disabilities":

	נשים עם מוגבלות

If you are to log this information, output on some console might be like the following, simply
because the app uses `US-ASCII` by default and that can't map those characters:

```
loggername - ?????????? ???? ??????????????
```

The important thing to understand is that this is some always applied, backwards compatible default
behaviour and even the case when the current environment sets a locale like `en_US.UTF-8`.

## Does Log4cxx support logging at process termination?{#atexit_events}

Log4cxx must be built with -DLOG4CXX_EVENTS_AT_EXIT=ON to use logging during the application
termination (i.e. in static destuctors and other atexit() functions) . When this option is used,
the dynamic memory deallocation, buffer flushing and file handle closing normally done in destructors
is not performed. Setting the "BufferedIO" option of any log4cxx::FileAppender to true is possible when using
this option due to the forced buffers flushing during the static deinitialization phase.
