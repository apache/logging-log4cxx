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

One important question with a logging library is: is it fast enough?
While Log4cxx may not be the fastest logging implementation, it is more than fast
enough for the vast majority of cases.

While Log4cxx can generate 2,000,000 log messages/second,
skipping a disabled logging request requires only a few nano-seconds,
so application performance is not affected when
logging requests are not removed from the release build.

Benchmark testing shows MessageBuffer (i.e. std::stringstream) filling
consumes the majority of CPU time when the logging request is not disabled.
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

The following table shows some timing tests using Google's benchmarking library.

    g++ (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0
	Run on (8 X 2328.61 MHz CPU s)
	CPU Caches:
	  L1 Data 32 KiB (x4)
	  L1 Instruction 32 KiB (x4)
	  L2 Unified 256 KiB (x4)
	  L3 Unified 6144 KiB (x1)
	Load Average: 0.07, 0.03, 0.01

| Benchmark    | Time         | CPU          |   Iterations |
| :----------- | -----------: | -----------: | -----------: |
| Testing disabled logging request | 0.473 ns | 0.473 ns | 1000000000 |
| Testing disabled logging request/threads:6 | 0.130 ns | 0.777 ns | 816416202 |
| Appending 5 char string using MessageBuffer, pattern: \%m\%n | 346 ns | 346 ns | 2014476 |
| Appending 5 char string using MessageBuffer, pattern: \%m\%n/threads:6 | 450 ns | 2522 ns | 287886 |
| Appending 49 char string using MessageBuffer, pattern: \%m\%n | 387 ns | 387 ns | 1805660 |
| Appending 49 char string using MessageBuffer, pattern: \%m\%n/threads:6 | 490 ns | 2691 ns | 235698 |
| Appending int value using MessageBuffer, pattern: \%m\%n | 538 ns | 538 ns | 1301436 |
| Appending int value using MessageBuffer, pattern: \%m\%n/threads:6 | 496 ns | 2775 ns | 238962 |
| Appending int+float using MessageBuffer, pattern: \%m\%n | 921 ns | 921 ns | 762785 |
| Appending int+float using MessageBuffer, pattern: \%m\%n/threads:6 | 576 ns | 3324 ns | 201900 |
| Appending int value using MessageBuffer, pattern: [\%d] \%m\%n | 566 ns | 566 ns | 1233924 |
| Appending int value using MessageBuffer, pattern: [\%d] [\%c] [\%p] \%m\%n | 624 ns | 624 ns | 1122040 |
| Appending 49 char string using FMT, pattern: \%m\%n | 360 ns | 360 ns | 1945236 |
| Appending 49 char string using FMT, pattern: \%m\%n/threads:6 | 489 ns | 2666 ns | 248046 |
| Appending int value using FMT, pattern: \%m\%n | 388 ns | 388 ns | 1804423 |
| Appending int value using FMT, pattern: \%m\%n/threads:6 | 496 ns | 2720 ns | 253938 |
| Appending int+float using FMT, pattern: \%m\%n | 519 ns | 519 ns | 1352503 |
| Appending int+float using FMT, pattern: \%m\%n/threads:6 | 515 ns | 2900 ns | 229374 |
| Async, Sending int+float using MessageBuffer | 1113 ns | 1113 ns | 633889 |
| Async, Sending int+float using MessageBuffer/threads:6 | 545 ns | 3254 ns | 211344 |
| Logging int+float using MessageBuffer, pattern: \%d \%m\%n | 1079 ns | 1078 ns | 641626 |
| Logging int+float using MessageBuffer, pattern: \%d \%m\%n/threads:6 | 1036 ns | 4715 ns | 144528 |
| Logging int+float using MessageBuffer, JSON | 1446 ns | 1446 ns | 487967 |
| Logging int+float using MessageBuffer, JSON/threads:6 | 2181 ns | 7102 ns | 85848 |
| Multiprocess logging int+float using MessageBuffer, pattern: \%d \%m\%n | 3456 ns | 3456 ns | 203235 |

-# The "Appending" benchmarks just format the message (using PatternLayout) then discard the result.
-# The "Async" benchmarks test AsyncAppender throughput, with logging events discarded in the background thread.
-# The "Logging" benchmarks write to a file using buffered output. Overhead is 2-3 times more when not using buffered output.
