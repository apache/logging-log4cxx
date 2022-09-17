Building with vcpkg {#build-vcpkg}
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

# Building Apache Log4cxx with vcpkg

Log4cxx is included with Microsoft vcpkg, and can thus be easily installed.
This is a quick guide to show you how to do that.

## Preparation

Windows:
~~~
> git clone https://github.com/Microsoft/vcpkg.git
> cd vcpkg
> .\bootstrap-vcpkg.bat
# Then, to hook up user-wide integration, run (note: requires admin on first use)
> .\vcpkg integrate install
~~~

Linux:
~~~
$ git clone https://github.com/Microsoft/vcpkg.git
$ cd vcpkg
$ ./bootstrap-vcpkg.sh
$ ./vcpkg integrate install
~~~

## Building log4cxx.dll

Windows:
~~~
PS> .\vcpkg install log4cxx
~~~

Linux: 
~~~
$ ./vcpkg install log4cxx
~~~

