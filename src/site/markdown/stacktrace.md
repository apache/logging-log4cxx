Stacktrace Support {#stacktrace-support}
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
When debugging a code base and an assertion is hit, it is often useful to
have a stacktrace as part of an assertion in order for you to tell where
you are in the code to know why it is buggy.  Generating a stacktrace can
be done with [Boost Stacktrace](https://www.boost.org/doc/libs/1_81_0/doc/html/stacktrace.html),
or using the [stacktrace](https://en.cppreference.com/w/cpp/header/stacktrace) header if you are using a C++23 compatible compiler.

In order to enable stacktraces when using the `LOG4CXX_ASSERT` family of macros,
simply define `LOG4CXX_ENABLE_STACKTRACE` in your buildsystem.  If you are using a
compiler that does not support C++17 and the `__has_include` macro, Boost Stacktrace
must be installed and available on your system.  If your compiler supports the
`__has_include` macro, then it will search for Boost Stacktrace, followed by searching
for `<stacktrace>`.  Both implementations will insert an
entry into the MDC named `stacktrace` that may then be inserted into log
statements.  When using the [PatternLayout](@ref log4cxx.PatternLayout), this
may be accomplished by using the `%%X{stacktrace}` conversion pattern.

## Putting the stacktrace into the MDC

If you want a stacktrace in any part of your code(not just on assertions),
the following snippet of code may be used to insert a stacktrace into the
current MDC:

~~~{.cpp}
::log4cxx::MDC mdc_("stacktrace", LOG4CXX_EOL + boost::stacktrace::to_string(boost::stacktrace::stacktrace()));
~~~

This may be inserted at any point in your application, giving you access
to the current stacktrace in any log statement, not just in assert statements.
