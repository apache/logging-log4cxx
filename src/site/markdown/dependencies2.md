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

# LOG4CXX Dependencies

log4cxx requires the following software to build and/or run correctly:

|Dependency Name|Version|Dependency Type|Homepage|
|---------------|-------|---------------|--------|
|Apache Portable Runtime(APR)|>=1.5.4|Compile/Runtime|https://apr.apache.org
|APR-Util       |>=1.5.4|Compile/Runtime|https://apr.apache.org
|gzip           |any    |Test/Runtime(optional)|https://gzip.org
|zip            |any    |Test/Runtime(optional)|N/A
|log4j          |1.2.14 |Test           |https://http://logging.apache.org/log4j/2.x/
|java           |>=6    |Test           |https://www.oracle.com/java/technologies/

## APR/APR-Util

The Apache Portable Runtime(APR) provides the cross-platform backend for log4cxx.
Both APR and APR-util need to be installed and available on your system.

## zip/gzip

These applications are needed during test of log4cxx.  gzip is generally installed
by default on Linux.  zip may not be installed by default; check your distribution's
documentation for information on how to install these applications.

For Windows, you will have to install gzip and zip through a system such as
MinGW, cygwin, or MSYS2.

These applications are only needed during runtime if you are compressing the log
files, for example by setting a rollover policy which ends in ".zip" or ".gz".

## log4j / Java

Log4j and Java are needed to run tests to ensure that log4cxx has binary
compatability with log4j.
Note that the correct binary for log4j will be downloaded and used automatically.
As such, you only need to have Java installed on your system.

# Licenses(direct dependencies only)

**Apache License, Version 2.0**: log4cxx, APR, APR-util
