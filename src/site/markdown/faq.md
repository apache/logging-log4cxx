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

# Frequently Asked Technical Questions
## <a name="table_of_contents"></a>Table of contents

<ol>
	<li><a href="#custom_levels">How do I add a custom level to Apache log4cxx?</a></li>
	<li><a href="#msvc_crash">My application on Windows crashes on shutdown?</a></li>
	<li><a href="#unicode_supported">Does Apache log4cxx support Unicode?</a></li>
</ol>

## <a name="custom_levels"></a>How do I add a custom level to Apache log4cxx?

This is a common topic for all the Apache logging frameworks and typically motivated to try to
categorize events by functionality or audience.  An common request is to add an AUDIT level so that
the user can configure AUDIT level messages to go to a specific appender. However, the logger name
was designed explicitly to support routing of messages by topic or audience. The common pattern of
using classnames for logger names obscures the more general capability of logger name to represent
the topic or audience of the logging request. The easiest approach to solve the underlying issue is
to use a logger names like "AUDIT.com.example.MyPackage.MyClass" that allow all AUDIT messages to be
routed to a particular appender. If you attempted to use a level for that then you would lose the
ability to distinguish between different significances within the audit messages.

## <a name="msvc_crash"></a>My application on Windows crashes on shutdown?

Apache log4cxx API calls use C++ Standard Template Library string parameters. If the caller is using
a different instance or type of the C Runtime Library that log4cxx, then it is very likely that some
memory that was originally allocated by log4cxx would be freed by the caller. If log4cxx and the
caller are using different C RTL's, the program will likely crash at the point. Use "Multithread
DLL" with release builds of log4cxx and "Multithread DLL Debug" with debug builds.

## <a name="unicode_supported"></a>Does Apache log4cxx support Unicode?

Yes. Apache log4cxx exposes API methods in multiple string flavors supporting differently encoded
textual content, like `char*`, `std::string`, `wchar_t*`, `std::wstring`, `CFStringRef` et al. All
provided texts will be converted to the `LogString` type before further processing, which is one of
several supported Unicode representations selected by the `--with-logchar` option. If methods are
used that take `LogString` as arguments, the macro `LOG4CXX_STR()` can be used to convert literals
to the current `LogString` type. FileAppenders support an encoding property as well, which should be
explicitly specified to `UTF-8` or `UTF-16` for e.g. XML files. The important point is to get the
chain of input, internal processing and output correct and that might need some additional setup in
the app using log4cxx:

According to the [libc documentation](https://www.gnu.org/software/libc/manual/html_node/Setting-the-Locale.html),
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
behaviour and even the case when the current environment sets a locale like `en_US.UTF-8`. One might
need to explicitly tell the app at startup to use the locale of the environment and make things
compatible with Unicode this way. See also [some SO post](https://stackoverflow.com/questions/571359/how-do-i-set-the-proper-initial-locale-for-a-c-program-on-windows)
on setting the default locale in C++.

```
std::setlocale( LC_ALL, "" ); /* Set locale for C functions */
std::locale::global(std::locale("")); /* set locale for C++ functions */
```

See [LOGCXX-483](https://issues.apache.org/jira/browse/LOGCXX-483) or [GHPR #31](https://github.com/apache/logging-log4cxx/pull/31#issuecomment-668870727)
for additional details.
