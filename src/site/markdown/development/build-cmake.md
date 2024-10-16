Building with CMake {#build-cmake}
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

# Supported options

| Option                 | Usage |
|------------------------|-------|
| LOG4CXX_WCHAR_T=no   | Enable wchar_t API methods, choice of yes (default), no.                                    |
| LOG4CXX_UNICHAR=yes  | Enable UniChar API methods, choice of yes, no (default).                                    |
| LOG4CXX_CFSTRING=yes | Enable CFString API methods, requires Mac OS/X CoreFoundation, choice of yes, no (default). |
| BUILD_TESTING=off    | Do not build tests.  Tests are built by default                                             |
| BUILD_FUZZERS        | Enabled by default if `BUILD_TESTING=ON` and libFuzzer is found.                            |
| BUILD_SITE=OFF       | Set to `ON` to enable the project website build. Requires Doxygen.                          |
| BUILD_SHARED_LIBS=off| Build Log4cxx as a static library. A dynamically linked Log4cxx library is built by default. Any compilation unit that includes a Log4cxx header must define LOG4CXX_STATIC.             |
| APU_STATIC=yes       | Link to the APR-Util static library. By default, the Log4cxx shared library is linked to the APR-Util shared library. If BUILD_SHARED_LIBS=off, the static APR-Util library is used.     |
| APR_STATIC=yes       | Link to the APR static library. By default, the Log4cxx shared library is linked to the APR shared library. If BUILD_SHARED_LIBS=off, the static APR library is always used.        |
| LOG4CXX_TEST_PROGRAM_PATH=path | An extra path to prepend to the PATH for test programs.  Log4cxx requires zip, sed, and grep on the PATH in order for the tests to work properly.                          |
| PREFER_BOOST=on      | Prefer the Boost version of dependent libraries over standard library |
| LOG4CXX_QT_SUPPORT=ON | Enable QString API and log4cxx::qt namespace methods, requires QtCore, choice of ON, OFF (default).                   |
| LOG4CXX_EVENTS_AT_EXIT=ON | Prevent static data cleanup to allow event logging during application exit. |
| LOG4CXX_FORMAT_NAMESPACE=std | Make the `LOG4CXX_[level]_FMT` macros use [std::format](https://en.cppreference.com/w/cpp/utility/format/format) by default.  |

# Examples

## Unix type systems

Make sure cmake (3.13+), g++, gzip, zip and make are available.
On a Debian system these may be installed by:
~~~
$ sudo apt-get install build-essential cmake gzip zip
~~~

1. Using the distro provided APR libraries
and the cmake cursors UI to configure Log4cxx options.
~~~
$ apt-get install libapr1-dev libaprutil1-dev
$ wget https://dlcdn.apache.org/logging/log4cxx/1.3.0/apache-log4cxx-1.3.0.tar.gz
$ tar xf apache-log4cxx-1.3.0.tar.gz
$ cd apache-log4cxx-1.3.0
$ mkdir build
$ cd build
$ ccmake ..
$ make
$ sudo make install
~~~

2. Install libraries locally in $HOME/libraries and
statically bind APR into the Log4cxx DSO.
~~~
$ wget https://archive.apache.org/dist/apr/apr-1.7.4.tar.bz2
$ tar xf apr-1.7.4.tar.bz2
$ cd apr-1.7.4
$ CFLAGS=-fPIC ./configure --prefix=$HOME/libraries
$ make install
$ cd $HOME
$ wget https://archive.apache.org/dist/apr/apr-util-1.6.3.bz2
$ tar xf apr-util-1.6.3.bz2
$ cd apr-util-1.6.3
$ CFLAGS=-fPIC ./configure --with-apr=$HOME/libraries --prefix=$HOME/libraries
$ make install
$ cd $HOME
$ wget https://dlcdn.apache.org/logging/log4cxx/1.3.0/apache-log4cxx-1.3.0.tar.gz
$ tar xf apache-log4cxx-1.3.0.tar.gz
$ cmake -S apache-log4cxx-1.3.0 -B build/log4cxx -DAPR_STATIC=yes -DAPU_STATIC=yes -DCMAKE_PREFIX_PATH=$HOME/libraries -DCMAKE_INSTALL_PREFIX=$HOME/Libraries -DCMAKE_BUILD_TYPE=Release
$ cmake --build build/log4cxx --target install
~~~

## Windows

1. The easiest way to get dependencies installed is to use vcpkg.
Follow the directions at https://github.com/microsoft/vcpkg#quick-start-windows and then install
the dependencies needed using `vcpkg install apr apr-util`.
Command-line utilities(zip, grep, sed) are available in the Git for Windows distribution (C:/Program Files/Git/usr/bin/)
or Msys2 can be downloaded from: https://www.msys2.org/ and by default will be installed under C:/msys2/bin.
Unless you pass BUILD_TESTING=off, the location of command-line utilities must be provided
to the Log4cxx cmake build in the LOG4CXX_TEST_PROGRAM_PATH cmake variable.

2. Building from source in %HOMEPATH%/Libraries.
Use your browser to download source for Expat from github, APR and APR-Util from https://archive.apache.org/dist/apr/
and Log4cxx from https://dlcdn.apache.org/logging/log4cxx/1.3.0.
Extract the source code into directories libexpat, apr-1.7.4, apr-util-1.6.3 and apache-log4cxx-1.3.0.
~~~
$ cd %HOMEPATH%/Libraries
$ cmake -S libexpat/expat -B buildtrees/expat -DCMAKE_INSTALL_PREFIX=%HOMEPATH%/Libraries/installed
$ cmake --build buildtrees/expat --target install --config Release
$ cmake -S apr-1.7.4 -B buildtrees/apr -DCMAKE_INSTALL_PREFIX=%HOMEPATH%/Libraries/installed
$ cmake --build buildtrees/apr --target install --config Release
$ set CMAKE_PREFIX_PATH=%HOMEPATH%/Libraries/installed
$ cmake -S apr-util-1.6.3 -B buildtrees/apr-util -DCMAKE_INSTALL_PREFIX=%HOMEPATH%/Libraries/installed
$ cmake --build buildtrees/apr-util --target install --config Release
$ cmake -S apache-log4cxx-1.3.0 -B buildtrees/log4cxx -DCMAKE_INSTALL_PREFIX=%HOMEPATH%/Libraries/installed -DLOG4CXX_TEST_PROGRAM_PATH=C:/Program Files/Git/usr/bin
$ cmake --build buildtrees/log4cxx --target install --config Release
~~~

## Mac OS/X:

APR and APR-Util are provided by the platform in Mac OS/X 10.5 and iODBC in 10.4.

cmake can be installed by typing "brew install cmake".

CMake can be built from source by typing:

~~~
$ wget https://github.com/Kitware/CMake/releases/download/v3.27.2/cmake-3.27.2.tar.gz
$ tar xf cmake-3.27.2.tar.gz
$ cd cmake-3.27.2
$ ./bootstrap
$ make
$ sudo make install
~~~

## FreeBSD:

APR, APR-Util, gzip and zip may be installed from the ports collection by:

~~~
$ cd /usr/ports/archivers/zip
$ make
$ make install
$ cd /usr/ports/archivers/gzip
$ make
$ make install
$ cd /usr/ports/devel/apr
$ make
$ make install
~~~

