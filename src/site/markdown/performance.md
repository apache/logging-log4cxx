Log4cxx Performance {#performance}
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

One important question with a logging library is: is it fast enough?  While
Log4cxx may not be the fastest logging implementation, it is more than fast
enough for the vast majority of cases.

In performance testing done on a developer's system(utilising an Intel
i5-8400 processor and a virtual machine), it is possible for Log4cxx to handle
over 2,000,000 messages/second in a single-threaded application.  Since
Log4cxx is designed to be multithread-safe, logging from multiple threads makes
this throughput much lower.  Delays in writing messages to disk can also
greatly decrease performance, depending on how much data is being logged.

If the logging of a particular level is disabled, performance can also be
a lot better.  While Log4cxx can generate 2,000,000 log messages/second,
skipping a disabled logging request requires only a few nano-seconds,
so application performance is not affected when
logging requests are not removed from the release build.

For the best performance, use the `LOG4CXX_[level]_FMT` series of macros,
as the [{fmt}](https://fmt.dev/latest/index.html) library
they use is significantly faster
(up to twice as fast as `operator<<`).
Note that you must include the headers from {fmt} manually.

These two pieces of logging code are logically equivalent(printing out the same
values), however the one utilizing fmt is close to 2x as fast on some systems.

```{.cpp}
   for( int x = 0; x < howmany; x++ ){
            LOG4CXX_INFO( logger, "Hello logger: msg number " << x);
   }
```

```{.cpp}
   for( int x = 0; x < howmany; x++ ){
       LOG4CXX_INFO_FMT( logger, "Hello logger: msg number {}", x);
   }
```

If you wish to benchmark Log4cxx on your own system, have a look at the tools
under the src/test/cpp/throughput and src/test/cpp/benchmark directories.
The throughput tests may be built by
specifying `BUILD_THROUGHPUT` with CMake when building Log4cxx.
The benckmark tests require Google's [Benchmark](https://github.com/google/benchmark) library
and may be built by specifying `BUILD_BENCHMARK_CHECKS` with CMake when building Log4cxx.
