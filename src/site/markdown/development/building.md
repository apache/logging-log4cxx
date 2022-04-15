Building {#building}
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

# Building Apache Log4cxx

As of version 0.11.0, the only supported build system for Log4cxx is CMake.
Have a look at the [build with CMake](build-cmake.html) page for more
information.  If you have trouble building, either create an issue in
[Jira](https://issues.apache.org/jira/projects/LOGCXX/issues) or send a
message to the [users mailing list].

## Covered by the team

The following list provides an overview about the environments some of the
team members have access to and therefore normally should work out of the box
or at least were used sometimes in the past. This list by no means tells
something about how good the support on each platform is, it's just a guide.

The following platforms/compilers are expected to work correctly:

* Windows 10(32 and 64-bit) - MSVC
* Windows 10(32-bit) - Embarcadero C++ Builder XE 4
* Debian 10(32 and 64-bit) - gcc 8.3.0, clang-7
* Ubuntu 20.04(32 and 64-bit) - gcc, clang
* Mac OSX - clang

Various Linux distributions already have Log4cxx as part of their package
managers - consult the documentation for your distribution to determine
if a package already exists.

[users mailing list]:@ref mailing-lists
