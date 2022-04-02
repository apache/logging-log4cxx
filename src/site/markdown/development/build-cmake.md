Build with CMake {#build-cmake}
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

# Building Apache Log4cxx with CMake

## Quick start:

  Building and testing Log4cxx on a Unix platform with packaged APR and APR-Util.

  Make sure cmake 3.13+, g++ and make are available, install or
  build apr 1.x, apr-util 1.x, gzip and zip.

Linux example:
~~~
$ apt-get install build-essential libapr1-dev libaprutil1-dev gzip zip
$ cd apache-Log4cxx-x.x.x
$ mkdir build
$ cd build
$ ccmake ..
$ make
$ sudo make install
~~~

Windows Example:
Building and testing Log4cxx on a Microsoft Windows with APR, Expat and APR-Util built from source
extracted into apr-1.7.0, libexpat(from github) and apr-util-1.6.1 in %HOMEPATH%\Libraries.

~~~
$ cd %HOMEPATH%\Libraries
$ cmake -S libexpat\expat -B buildtrees\expat -DCMAKE_INSTALL_PREFIX=%HOMEPATH%\Libraries\installed
$ cmake --build buildtrees\expat --target install --config Release
$ cmake -S apr-1.7.0 -B buildtrees\apr -DCMAKE_INSTALL_PREFIX=%HOMEPATH%\Libraries\installed
$ cmake --build buildtrees\apr --target install --config Release
$ set CMAKE_PREFIX_PATH=%HOMEPATH%\Libraries\installed
$ cmake -S apr-util-1.6.1 -B buildtrees\apr-util -DCMAKE_INSTALL_PREFIX=%HOMEPATH%\Libraries\installed
$ cmake --build buildtrees\apr-util --target install --config Release
$ cmake -S apache-Log4cxx-x.x.x -B buildtrees\Log4cxx -DCMAKE_INSTALL_PREFIX=%HOMEPATH%\Libraries\installed
$ cmake --build buildtrees\Log4cxx --target install --config Release
~~~

## ccmake options

| Option                 | Usage |
|------------------------|-------|
| -DLOG4CXX_WCHAR_T=no   | Enable wchar_t API methods, choice of yes (default), no.                                    |
| -DLOG4CXX_UNICHAR=yes  | Enable UniChar API methods, choice of yes, no (default).                                    |
| -DLOG4CXX_CFSTRING=yes | Enable CFString API methods, requires Mac OS/X CoreFoundation, choice of yes, no (default). |
| -DBUILD_TESTING=off    | Do not build tests.  Tests are built by default                                             |
| -DBUILD_SHARED_LIBS=off| Build Log4cxx as a static library. A dynamically linked Log4cxx library is built by default. Any compilation unit that includes a Log4cxx header must define LOG4CXX_STATIC.             |
| -DAPU_STATIC=yes       | Link to the APR-Util static library. By default, the Log4cxx shared library is linked to the APR-Util shared library. If BUILD_SHARED_LIBS=off, the static APR-Util library is used.     |
| -DAPR_STATIC=yes       | Link to the APR static library. By default, the Log4cxx shared library is linked to the APR shared library. If BUILD_SHARED_LIBS=off, the static APR library is always used.        |
|-DLOG4CXX_TEST_PROGRAM_PATH=path| An extra path to prepend to the PATH for test programs.  Log4cxx requires zip, sed, and grep on the PATH in order for the tests to work properly.                          |
| -DPREFER_BOOST=on      | Prefer the Boost version of dependent libraries over standard library |

## A note on C++ version and Boost

By default, Log4cxx attempts to use at least C++17 to compile.  This is to
avoid 3rd party dependencies as much as possible.  If C++17 is not
available, a search for Boost will be taken and those libaries will be used
instead.  If you would prefer to use Boost, there are two options you have:

1. Pass `-DPREFER_BOOST=ON` to CMake when compiling.  This will ignore the
 results of the tests that check for the standard version of components that
 are required.  Note that this will switch all components, regardless of the
 C++ version in effect at compile time.
2. Revert to an earlier standard using `-DCMAKE_CXX_STANDARD=11` for example.
 This will still to check for standard versions of required components, but
 it will fall back to using Boost for newer components added in C++17.

# Platform specific notes:

## Mac OS/X:

APR and APR-Util are provided by the platform in Mac OS/X 10.5 and iODBC in 10.4.

cmake can be installed by typing "brew install cmake".

## Debian:

APR, APR-Util, openssl, gzip and zip may be installed by:

~~~
$ sudo apt-get install libssl-dev libapr1-dev libaprutil1-dev gzip zip
~~~

CMake can be built from source by typing:

~~~
$ wget https://github.com/Kitware/CMake/releases/download/v3.16.4/cmake-3.16.4.tar.gz
$ tar xf cmake-3.16.4.tar.gz
$ cd cmake-3.16.4
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

## Windows:

The easiest way to get dependencies installed is to use vcpkg(for APR/expat), and msys2 for the command-line
utilities(zip, grep, sed).

Msys2 can be downloaded from: https://www.msys2.org/
By default, this will be installed under C:\msys2, so you can add that to the build PATH by setting
LOG4CXX_TEST_PROGRAM_PATH=C:/msys64/usr/bin in your build settings.

For vcpkg, follow the directions at https://github.com/microsoft/vcpkg#quick-start-windows and then install
the dependencies needed using `vcpkg install apr apr-util`.

# Using Log4cxx in a CMake build

A log4cxxConfig.cmake and log4cxxConfigVersion.cmake is installed to allow use of find_package()
in your CMakeLists.txt.

Below are example cmake commands that compile and link "myApplication" with Log4cxx.

~~~
find_package(log4cxx 0.11)
add_executable(myApplication myMain.cpp)
target_include_directories(myApplication PRIVATE $<TARGET_PROPERTY:log4cxx,INTERFACE_INCLUDE_DIRECTORIES>)
target_link_libraries( myApplication PRIVATE log4cxx)
~~~

