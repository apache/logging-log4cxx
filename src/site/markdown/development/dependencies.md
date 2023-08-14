Log4cxx Dependencies {#dependencies}
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

As of version 0.12.0, Log4cxx requires a minimum C++ version of C++11.

Log4cxx requires the following software to build and/or run correctly:

|Dependency Name|Version|Dependency Type|Homepage|
|---------------|-------|---------------|--------|
|Apache Portable Runtime(APR)|>=1.5.4|Compile/Runtime|https://apr.apache.org
|APR-Util       |>=1.5.4|Compile/Runtime|https://apr.apache.org
|gzip           |any    |Test/Runtime(optional)|https://gzip.org
|sed            |any    |Test|N/A
|zip            |any    |Test/Runtime(optional)|N/A

## APR+APR-Util

The Apache Portable Runtime(APR) provides the cross-platform backend for log4cxx.
Both APR and APR-util need to be installed and available on your system.

## sed+gzip+zip

These applications are needed during test of log4cxx.  `gzip`and `sed` are generally installed
by default on Linux.  `zip` may not be installed by default; check your distribution's
documentation for information on how to install these applications.

For Windows, you will have to install those tools through a system such as
MinGW, cygwin, or MSYS2.

`gzip` and `zip` only needed during runtime if you are compressing the log
files, for example by setting a rollover policy which ends in `.gz` or `.zip`.

# Optional Dependencies

The following table lists CMake options that require additional dependencies.

|CMake option   |Dependency Name|Version| Dependency Type | Homepage|
|---------------|---------------| :---: |---------------|--------|
|LOG4CXX_MULTIPROCESS_ROLLING_FILE_APPENDER |Boost | any   | Compile/runtime. Not required if your compiler supports C++17 | https://boost.org |
|ENABLE_FMT_LAYOUT | {fmt}    | 9+     | Compile/runtime | https://github.com/fmtlib/fmt |
|LOG4CXX_ENABLE_ODBC | unixodbc    | any     | Compile/runtime (not on Windows) | https://www.unixodbc.org/ |
|LOG4CXX_ENABLE_ESMTP | libesmtp    | any     | Compile/runtime (not on Windows) | https://github.com/libesmtp/libESMTP |
|LOG4CXX_QT_SUPPORT |Qt    | 5     | Compile/runtime | https://www.qt.io/download |
|LOG4CXX_CFSTRING | Mac OS/X Core Foundation | any | Compile/runtime | https://developer.apple.com/documentation/corefoundation |

## A note on C++ version and Boost

By default, Log4cxx requests C++20 features.  This is to
avoid 3rd party dependencies as much as possible.  If C++17 is not
available, a search for Boost will be taken and those libraries will be used
instead.  If you would prefer to use Boost, there are two options you have:

1. Pass `-DPREFER_BOOST=ON` to CMake when compiling.  This will ignore the
 results of the tests that check for the standard version of components that
 are required.  Note that this will switch all components, regardless of the
 C++ version in effect at compile time.
2. Revert to an earlier standard using `-DCMAKE_CXX_STANDARD=11` for example.
 This will still to check for standard versions of required components, but
 it will fall back to using Boost for newer components added in C++17.

# Licenses(direct dependencies only)

| Dependency | License |
|------------|---------|
| APR, APR-util | **Apache License, Version 2.0** |
| Boost | **Boost License, Version 1.0** |
| {fmt} | **MIT** |
| unixodbc | **LGPL** |
| libesmtp | **LGPL** |
| Qt | Refer https://www.qt.io/licensing/ |
| Mac OS/X Core Foundation | **APSL 2.0** |