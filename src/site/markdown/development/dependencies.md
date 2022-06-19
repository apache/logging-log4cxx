Dependencies {#dependencies}
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


# Log4cxx Dependencies

As of version 0.12.0, Log4cxx requires a minimum C++ version of C++11.
If C++17 is not available, then Log4cxx requires Boost Thread in order
to build, which in turn requires chrono and date\_time.

log4cxx requires the following software to build and/or run correctly:

|Dependency Name|Version|Dependency Type|Homepage|
|---------------|-------|---------------|--------|
|Apache Portable Runtime(APR)|>=1.5.4|Compile/Runtime|https://apr.apache.org
|APR-Util       |>=1.5.4|Compile/Runtime|https://apr.apache.org
|Boost          |any?   |Compile/runtime.  Not required if your compiler supports C++17|https://boost.org
|gzip           |any    |Test/Runtime(optional)|https://gzip.org
|sed            |any    |Test|N/A
|zip            |any    |Test/Runtime(optional)|N/A
|log4j          |1.2.14 |Test           |https://http://logging.apache.org/log4j/2.x/
|java           |>=6    |Test           |https://adoptopenjdk.net

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

## log4j+Java

log4j and Java are needed to run some tests to ensure that log4cxx has binary compatability with
log4j. Note that the correct binary for log4j will be downloaded and used automatically if CMAKE is
used to build the project, otherwise one needs to get that manually. Java needs to be installed on
the system already in all cases, but with CMAKE again, if it's not, the corresponding tests are
skipped entirely automatically.

# Licenses(direct dependencies only)

**Apache License, Version 2.0**: log4cxx, APR, APR-util
**Boost License, Version 1.0**: boost
