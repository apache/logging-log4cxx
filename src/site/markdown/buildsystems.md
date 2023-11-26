Usage with your build system {#buildsystems}
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

The following code snippets show how to use Log4cxx with various different buildsystems.

Note that we are unable to provide support for all buildsystems that you may be using.

CMake is fully supported for building, as well as any buildsystem that can use `pkgconfig`
in order to find packages.  When using `pkgconfig`, the package name is `liblog4cxx`.

# How do I use Log4cxx with CMake? {#use_with_cmake}

Add the following to your CMakeLists.txt file:

~~~
find_package(log4cxx)

... other buildsystem information here ...

target_link_libraries( executable PRIVATE log4cxx )
~~~

# How do I use Log4cxx with CMake and pkg-config? {#use_with_cmake_pkgconfig}

Add the following to your CMakeLists.txt file:

~~~
find_package(PkgConfig)
pkg_check_modules(log4cxx REQUIRED liblog4cxx)

... other buildsystem information here ...

target_link_libraries( executable PRIVATE ${log4cxx_LIBRARIES} )
target_include_directories( executable PRIVATE ${log4cxx_INCLUDE_DIRS} )
~~~


# How do I use Log4cxx with QMake? {#use_with_qmake}

Add the following to your .pro file:

~~~
CONFIG += link_pkgconfig

PKGCONFIG += liblog4cxx
~~~

# How do I use Log4cxx with plain Make? {#use_with_make}

You probably don't want to do this - it is highly recommended to use a proper buildsystem.  However, the following minimal Makefile will build and link an application:

~~~
CXXFLAGS += $(shell pkg-config --cflags liblog4cxx)
LDFLAGS += $(shell pkg-config --libs liblog4cxx)

all: main.o
        $(CXX) -o application main.o $(LDFLAGS)
~~~
